// Prova degli aggiornamenti del client desktop: backend reale, nessun servizio esterno.
// Autonoma: avvia il backend da dist/ (dopo npm run build) e lo ferma alla fine.
//   node test/e2e-client-updates.mjs
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testSession } from "./helpers.mjs";
import { newKeyPair, open, seal } from "../dist/envelope.js";

const results = [];
const ok = (cond, label) => {
  results.push(Boolean(cond));
  console.log((cond ? "OK   " : "FAIL ") + label);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);

const WORK = mkdtempSync(join(tmpdir(), "startconnect-client-updates-"));
const DB = join(WORK, "data", "startconnect.sqlite");
const server = spawn(process.execPath, ["dist/index.js"], {
  env: {
    ...process.env,
    TUNNEL_KEY: "0123456789abcdef0123456789abcdef",
    JWT_SECRET: "test-secret-test-secret-test-secret",
    LDAP_URL: "ldap://127.0.0.1:1", LDAP_BASE_DN: "dc=x", LDAP_BIND_DN: "cn=x", LDAP_BIND_PASSWORD: "x",
    DATA_DIR: join(WORK, "data"), PORT: "18082", GUACD_PORT: "14898",
    STARTCONNECT_APP_IMAGE: "ghcr.io/startappsrl/startconnect-app:0.1.2",
  },
  stdio: ["ignore", "inherit", "inherit"],
});
const BASE = "http://127.0.0.1:18082/api";
const api = async (tok, method, path, body) => {
  const r = await fetch(BASE + path, {
    method,
    headers: { "content-type": "application/json", ...(tok ? { authorization: "Bearer " + tok } : {}) },
    body: body && JSON.stringify(body),
  });
  return [r.status, r.status === 204 ? null : await r.json().catch(() => null)];
};
for (let i = 0; i < 50; i++) {
  try {
    if ((await fetch(BASE + "/info")).ok) break;
  } catch {}
  await sleep(200);
}

const installer = (version, extra = "") => {
  const data = Buffer.concat([Buffer.from(`installatore ${version}${extra}`), randomBytes(1024)]);
  return { data, sha256: createHash("sha256").update(data).digest("hex") };
};
const manifest = (key, version, file, over = {}) => seal({
  t: "client-update", version, platform: "win-x64", name: `StartConnect Setup ${version}.exe`,
  sha256: file.sha256, size: file.data.length, iat: now(), ...over,
}, key.privateKey, key.publicKey);
const publish = async (tok, platform, data, env) => (await fetch(`${BASE}/client-updates/${platform}`, {
  method: "PUT",
  headers: { authorization: "Bearer " + tok, "content-type": "application/octet-stream", "x-manifest": Buffer.from(JSON.stringify(env)).toString("base64url") },
  body: data,
})).status;

try {
  const [, info] = await api(null, "GET", "/info");
  ok(info.version === "0.1.2", `versione dal tag dell'immagine (${info.version})`);

  const admin = testSession(DB, "admin", ["domain admins"], true);
  const tech = testSession(DB, "luca", ["tecnici"], false);
  const adminKey = newKeyPair(), rogueKey = newKeyPair(), otherAdminKey = newKeyPair();
  await api(admin, "POST", "/me/keys", { publicKey: adminKey.publicKey, label: "PC admin" });

  const v1 = installer("0.2.0");
  ok(await publish(admin, "win-x64", v1.data, manifest(adminKey, "0.2.0", v1)) === 400, "senza elenco fidato nessuna pubblicazione");

  const trust1 = seal({ t: "trust", version: 1, prev: "", admins: [{ name: "admin", key: adminKey.publicKey }], iat: now() }, adminKey.privateKey, adminKey.publicKey);
  ok((await api(admin, "PUT", "/trust", { env: trust1 }))[0] === 200, "elenco fidato creato");

  ok(await publish(tech, "win-x64", v1.data, manifest(adminKey, "0.2.0", v1)) === 403, "un tecnico non può pubblicare");
  ok(await publish(admin, "win-x64", v1.data, manifest(rogueKey, "0.2.0", v1)) === 400, "manifesto firmato da una chiave estranea rifiutato");
  ok(await publish(admin, "win-x64", v1.data, manifest(otherAdminKey, "0.2.0", v1)) === 400, "chiave non presente nell'elenco fidato rifiutata");
  ok(await publish(admin, "win-x64", Buffer.concat([v1.data, Buffer.from("x")]), manifest(adminKey, "0.2.0", v1)) === 400, "installatore diverso dal manifesto rifiutato");
  ok(await publish(admin, "linux-x64", v1.data, manifest(adminKey, "0.2.0", v1)) === 400, "piattaforma diversa da quella firmata rifiutata");
  ok(await publish(admin, "win-x64", v1.data, manifest(adminKey, "0.2.0", v1, { name: "../evil.exe" })) === 400, "nome di file non valido rifiutato");
  ok(await publish(admin, "win-x64", v1.data, manifest(adminKey, "latest", v1)) === 400, "versione non numerica rifiutata");
  ok(await publish(admin, "win-x64", v1.data, manifest(adminKey, "0.2.0", v1)) === 200, "aggiornamento 0.2.0 pubblicato da un amministratore fidato");

  const [st, list] = await api(tech, "GET", "/client-updates");
  const entry = list?.updates?.find((u) => u.platform === "win-x64");
  ok(st === 200 && entry?.version === "0.2.0", "i tecnici vedono l'aggiornamento");
  const signed = entry && open(entry.manifest, "client-update");
  ok(signed?.sha256 === v1.sha256 && entry.manifest.k === adminKey.publicKey, "manifesto firmato consegnato intatto, verificabile dal client");

  const dl = await fetch(`${BASE}/client-updates/win-x64/download`, { headers: { authorization: "Bearer " + tech } });
  const got = Buffer.from(await dl.arrayBuffer());
  ok(dl.ok && createHash("sha256").update(got).digest("hex") === v1.sha256, "download identico all'installatore pubblicato");
  ok((await fetch(`${BASE}/client-updates/win-x64/download`)).status === 401, "download riservato agli utenti autenticati");
  ok((await fetch(`${BASE}/client-updates/..%2Fstartconnect.sqlite/download`, { headers: { authorization: "Bearer " + tech } })).status === 404, "nessun accesso ad altri file del server");

  const old = installer("0.1.9");
  ok(await publish(admin, "win-x64", old.data, manifest(adminKey, "0.1.9", old)) === 409, "non si torna a una versione precedente");
  const v2 = installer("0.2.1");
  ok(await publish(admin, "win-x64", v2.data, manifest(adminKey, "0.2.1", v2)) === 200, "nuova versione 0.2.1 pubblicata");
  ok((await api(tech, "GET", "/client-updates"))[1].updates[0].version === "0.2.1", "si conserva solo l'ultima versione");

  ok((await api(tech, "DELETE", "/client-updates/win-x64"))[0] === 403, "un tecnico non può ritirare l'aggiornamento");
  ok((await api(admin, "DELETE", "/client-updates/win-x64"))[0] === 204 && (await api(tech, "GET", "/client-updates"))[1].updates.length === 0,
    "l'amministratore ritira l'aggiornamento");

  const [, log] = await api(admin, "GET", "/audit?limit=50");
  const actions = log.entries.map((e) => e.action);
  ok(actions.includes("client.update.publish") && actions.includes("client.update.withdraw"), "pubblicazione e ritiro nel registro");
} finally {
  server.kill();
  await sleep(300);
  rmSync(WORK, { recursive: true, force: true });
}

const failed = results.filter((r) => !r).length;
console.log(`\n${results.length - failed} OK, ${failed} FAIL`);
process.exit(failed ? 1 : 0);
