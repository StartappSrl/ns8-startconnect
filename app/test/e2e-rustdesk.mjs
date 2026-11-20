// Prova dei PC RustDesk: backend reale + rustdesk-api simulato.
// Autonoma: avvia il backend da dist/ (dopo npm run build) e lo ferma alla fine.
//   node test/e2e-rustdesk.mjs
// Verifica sincronizzazione, permessi per cartella, assegnazione, collegamento
// dall'inventario dell'agente, registro e pausa dopo un login fallito.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { testSession } from "./helpers.mjs";
import { newKeyPair } from "../dist/envelope.js";

const results = [];
const ok = (cond, label) => {
  results.push(Boolean(cond));
  console.log((cond ? "OK   " : "FAIL ") + label);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- rustdesk-api simulato (lejianwen/rustdesk-api v2.7) ----------
const now = Math.floor(Date.now() / 1000);
const PEERS = [
  { id: "123456789", hostname: "PC-CASSA", os: "Windows 11", username: "cassa", version: "1.5.1", last_online_time: now - 10, last_online_ip: "1.2.3.4" },
  { id: "987654321", hostname: "SRV-VECCHIO", os: "Windows Server 2019", username: "admin", version: "1.4.9", last_online_time: now - 86400, last_online_ip: "5.6.7.8" },
  { id: "bad id!", hostname: "INVALIDO" },
];
let password = "sync-pass";
let logins = 0;
let failedLogins = 0;
const validTokens = new Set();
const fake = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    const reply = (obj) => res.end(JSON.stringify(obj));
    if (req.method === "POST" && req.url === "/api/admin/login") {
      logins++;
      const b = JSON.parse(body);
      if (b.username === "sync" && b.password === password) {
        validTokens.add("tok-" + logins);
        return reply({ code: 0, data: { token: "tok-" + logins } });
      }
      failedLogins++;
      return reply({ code: 101, message: "Username or password error" });
    }
    if (req.method === "GET" && req.url.startsWith("/api/admin/peer/list")) {
      if (!validTokens.has(String(req.headers["api-token"] ?? ""))) return reply({ code: 403, message: "Unauthorized" });
      const page = Number(new URL(req.url, "http://x").searchParams.get("page"));
      return reply({ code: 0, data: { list: page === 1 ? PEERS : [], total: PEERS.length, page, page_size: 200 } });
    }
    res.statusCode = 404;
    res.end();
  });
});
await new Promise((r) => fake.listen(18765, "127.0.0.1", r));

// ---------- backend ----------
const WORK = mkdtempSync(join(tmpdir(), "startconnect-rustdesk-"));
const DB = join(WORK, "data", "startconnect.sqlite");
const env = {
  ...process.env,
  TUNNEL_KEY: "0123456789abcdef0123456789abcdef",
  JWT_SECRET: "test-secret-test-secret-test-secret",
  LDAP_URL: "ldap://127.0.0.1:1", LDAP_BASE_DN: "dc=x", LDAP_BIND_DN: "cn=x", LDAP_BIND_PASSWORD: "x",
  DATA_DIR: join(WORK, "data"), PORT: "18081", GUACD_PORT: "14899",
  RUSTDESK_ID_SERVER: "rds.example.org",
  RUSTDESK_API_SERVER: "http://127.0.0.1:18765",
  RUSTDESK_KEY: "6LMMFogQe6ay1bM4FCOWqYdEtm+dCGqlzLLN8XUUZO4=",
  RUSTDESK_API_USER: "sync",
  RUSTDESK_API_PASSWORD: "sync-pass",
  RUSTDESK_SYNC_SECONDS: "30",
};
const server = spawn(process.execPath, ["dist/index.js"], { env, stdio: ["ignore", "inherit", "inherit"] });
const BASE = "http://127.0.0.1:18081/api";
const api = async (tok, method, path, body) => {
  const r = await fetch(BASE + path, {
    method,
    headers: { "content-type": "application/json", ...(tok ? { authorization: "Bearer " + tok } : {}) },
    body: body && JSON.stringify(body),
  });
  return [r.status, r.status === 204 ? null : await r.json()];
};
for (let i = 0; i < 50; i++) {
  try {
    if ((await fetch(BASE + "/info")).ok) break;
  } catch {}
  await sleep(200);
}

try {
  const admin = testSession(DB, "admin", ["domain admins"], true);
  const tech = testSession(DB, "luca", ["tecnici"], false);
  const other = testSession(DB, "anna", ["altri"], false);

  // Cartelle: "Studio Bianchi" modificabile dai tecnici, "Comune" senza accesso per loro
  const [, studio] = await api(admin, "POST", "/folders", { name: "Studio Bianchi" });
  const [, comune] = await api(admin, "POST", "/folders", { name: "Comune" });
  await api(admin, "PUT", `/folders/${studio.id}/acl`, { entries: [{ group: "tecnici", level: "edit" }] });

  // Sincronizzazione all'avvio
  await sleep(1500);
  let [, cat] = await api(admin, "GET", "/catalog");
  ok(cat.rustdesk?.enabled === true, "integrazione attiva con server e chiave configurati");
  ok(cat.rustdesk.unassigned.length === 2, "sincronizzati 2 PC validi (scartato l'ID non valido)");
  const cassa = cat.rustdesk.unassigned.find((p) => p.id === "123456789");
  ok(cassa?.hostname === "PC-CASSA" && cassa.online === true, "dati e stato online dal server RustDesk");
  ok(cat.rustdesk.unassigned.find((p) => p.id === "987654321")?.online === false, "PC non visto da un giorno: non collegato");

  [, cat] = await api(tech, "GET", "/catalog");
  ok(cat.rustdesk.unassigned.length === 0 && cat.rustdesk.peers.length === 0, "un tecnico non vede i PC da assegnare");

  const [, cfg] = await api(tech, "GET", "/rustdesk/config");
  ok(cfg.idServer === "rds.example.org" && cfg.key && cfg.sync === undefined, "configurazione pubblica per i tecnici, senza stato di sincronizzazione");
  const [, cfgAdmin] = await api(admin, "GET", "/rustdesk/config");
  ok(cfgAdmin.sync?.ok === true && cfgAdmin.sync.count === 2, "stato di sincronizzazione per gli amministratori");
  ok(!JSON.stringify(cfgAdmin).includes("sync-pass"), "la password di rustdesk-api non esce dall'API");

  // Assegnazione
  let [status] = await api(tech, "PUT", "/rustdesk/peers/123456789", { folderId: studio.id, name: "Cassa 1" });
  ok(status === 404, "un tecnico non può assegnare un PC da assegnare");
  [status] = await api(admin, "PUT", "/rustdesk/peers/123456789", { folderId: studio.id, name: "Cassa 1" });
  ok(status === 200, "l'amministratore assegna il PC allo studio");
  [, cat] = await api(tech, "GET", "/catalog");
  ok(cat.rustdesk.peers.length === 1 && cat.rustdesk.peers[0].name === "Cassa 1" && cat.rustdesk.peers[0].permission === "edit",
    "il tecnico vede il PC nella sua cartella");
  [, cat] = await api(other, "GET", "/catalog");
  ok(cat.rustdesk.peers.length === 0, "chi non ha permessi sulla cartella non lo vede");

  [status] = await api(tech, "PUT", "/rustdesk/peers/123456789", { folderId: comune.id });
  ok(status === 403, "un tecnico non può spostarlo in una cartella senza permesso");

  // Apertura registrata
  let [st, opened] = await api(other, "POST", "/rustdesk/peers/123456789/open", { credential: "item" });
  ok(st === 404, "apertura negata a chi non vede la cartella");
  [st, opened] = await api(tech, "POST", "/rustdesk/peers/123456789/open", { credential: "item" });
  ok(st === 200 && opened.id === "123456789" && opened.config.idServer === "rds.example.org", "apertura consentita al tecnico");

  // La sincronizzazione successiva non sovrascrive nome e cartella
  PEERS[0].hostname = "PC-CASSA-NUOVO";
  await sleep(31_000);
  [, cat] = await api(tech, "GET", "/catalog");
  const p = cat.rustdesk.peers[0];
  ok(p?.name === "Cassa 1" && p.folderId === studio.id && p.hostname === "PC-CASSA-NUOVO", "la sincronizzazione aggiorna solo i dati del PC");

  // Aggiunta manuale e rimozione
  [status] = await api(tech, "POST", "/rustdesk/peers", { id: "555 666 777", folderId: studio.id, name: "Portatile" });
  ok(status === 201, "aggiunta manuale con ID scritto a gruppi");
  [status] = await api(tech, "POST", "/rustdesk/peers", { id: "555666777", folderId: studio.id });
  ok(status === 409, "lo stesso PC non si aggiunge due volte");
  [status] = await api(tech, "DELETE", "/rustdesk/peers/555666777");
  [, cat] = await api(admin, "GET", "/catalog");
  ok(status === 204 && cat.rustdesk.unassigned.some((x) => x.id === "555666777"), "togliere un PC dalla cartella lo rimette da assegnare");
  [status] = await api(admin, "DELETE", "/rustdesk/peers/555666777");
  [, cat] = await api(admin, "GET", "/catalog");
  ok(status === 204 && !cat.rustdesk.unassigned.some((x) => x.id === "555666777"), "l'amministratore può nascondere un PC da assegnare");

  // Collegamento dall'inventario dell'agente (dispositivo in attesa nella cartella "Comune")
  const db = new Database(DB);
  const cred = { type: "item", containerId: "c1", itemId: "i1", label: "RustDesk Comune" };
  db.prepare(`INSERT INTO devices (id, folder_id, name, public_key, status, enrolled_at, inventory, rustdesk_credential)
              VALUES ('dev1', ?, 'SRV-VECCHIO', ?, 'pending', datetime('now'), ?, ?)`)
    .run(comune.id, newKeyPair().publicKey, JSON.stringify({ rustdesk: { id: "987654321", version: "1.5.1" } }), JSON.stringify(cred));
  db.close();
  [, cat] = await api(admin, "GET", "/catalog");
  ok(cat.rustdesk.unassigned.some((x) => x.id === "987654321"), "prima dell'approvazione il PC resta da assegnare");
  const [, detail] = await api(admin, "GET", "/devices/dev1");
  [status] = await api(admin, "POST", "/devices/dev1/approve", { fingerprint: detail.fingerprint });
  [, cat] = await api(admin, "GET", "/catalog");
  const linked = cat.rustdesk.peers.find((x) => x.id === "987654321");
  ok(status === 200 && linked?.folderId === comune.id && linked.deviceId === "dev1" && linked.name === "SRV-VECCHIO",
    "approvato il dispositivo, il suo PC RustDesk va nella sua cartella");
  ok(linked?.credential?.itemId === "i1", "il PC eredita la voce StartCredentials creata con il pacchetto");

  // Codice di installazione con il riferimento alla password RustDesk (serve l'elenco fidato: qui 409 atteso)
  const [stEnroll, enrollBody] = await api(admin, "POST", "/enrollments", { folderId: comune.id, rustdeskCredential: cred });
  ok(stEnroll === 409 && enrollBody.code === "no_trust", "creazione del codice ancora vincolata all'elenco fidato");

  // Registro attività
  const [, log] = await api(admin, "GET", "/audit?limit=200");
  const actions = new Set(log.entries.map((e) => e.action));
  ok(["rustdesk.assign", "rustdesk.open", "rustdesk.add", "rustdesk.unassign", "rustdesk.ignore"].every((a) => actions.has(a)),
    "assegnazioni, aperture, aggiunte e rimozioni nel registro");
  ok(!JSON.stringify(log).includes("sync-pass"), "nessuna password nel registro");

  // Password cambiata sul server RustDesk: un solo login fallito, poi la sincronizzazione
  // si ferma (rustdesk-api bloccherebbe l'IP dopo 5 errori in 10 minuti)
  password = "cambiata";
  validTokens.clear();
  await sleep(62_000);
  const [, cfgFail] = await api(admin, "GET", "/rustdesk/config");
  ok(failedLogins === 1, `un solo login fallito in due giri di sincronizzazione (${failedLogins})`);
  ok(cfgFail.sync.ok === false && /login|sospeso/.test(cfgFail.sync.error ?? ""), "errore visibile agli amministratori");
} finally {
  server.kill();
  fake.close();
  rmSync(WORK, { recursive: true, force: true });
}

const failed = results.filter((r) => !r).length;
console.log(`\n${results.length - failed} OK, ${failed} FAIL`);
process.exit(failed ? 1 : 0);
