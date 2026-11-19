// Chiave di emergenza: limiti (niente tunnel, niente elenco con sola emergenza) e ripristino dopo la perdita del PC.
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
// rec.mjs: esbuild ../../../client/src/main/recovery.ts --bundle --platform=node --format=esm --outfile=test/rec.mjs
import { createRecovery, openRecovery } from "./rec.mjs";
import { newKeyPair, seal, payloadHash } from "../dist/envelope.js";
import { testSession } from "./helpers.mjs";
const W = process.env.WORK ?? "/tmp/rectest", BASE = "http://127.0.0.1:18080/api", AGENT = process.env.AGENT ?? "/tmp/agbin/startconnect-agent";
const ok = (c, l) => console.log((c ? "OK   " : "FAIL ") + l);
const now = () => Math.floor(Date.now() / 1000);
const tok = testSession(W + "/data/startconnect.sqlite", "admin", ["domain admins"], true);
const api = async (m, p, b) => { const r = await fetch(BASE + p, { method: m, headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: b && JSON.stringify(b) }); return [r.status, r.status === 204 ? null : await r.json()]; };

const A = newKeyPair(), B = newKeyPair();
await api("POST", "/me/keys", { publicKey: A.publicKey, label: "PC A" });
const v1 = seal({ t: "trust", version: 1, prev: "", admins: [{ name: "admin", key: A.publicKey }], iat: now() }, A.privateKey, A.publicKey);
await api("PUT", "/trust", { env: v1 });
const rec = createRecovery("una frase segreta molto lunga", "http://127.0.0.1:18080");
ok(!rec.file.includes("PRIVATE") && JSON.parse(rec.file).data.length > 40, "file della chiave di emergenza cifrato");
const v2 = seal({ t: "trust", version: 2, prev: payloadHash(v1), admins: [{ name: "admin", key: A.publicKey }, { name: "emergenza", key: rec.publicKey, role: "recovery" }], iat: now() }, A.privateKey, A.publicKey);
ok((await api("PUT", "/trust", { env: v2 }))[0] === 200, "chiave di emergenza aggiunta all'elenco");

const [, folder] = await api("POST", "/folders", { name: "Cliente", parentId: null });
const [, en] = await api("POST", "/enrollments", { folderId: folder.id, hours: 1, uses: 1 });
const env = { ...process.env, STARTCONNECT_AGENT_DIR: W + "/agent" };
execFileSync(AGENT, ["install", "--code", "SCE1-" + Buffer.from(JSON.stringify({ v: 1, u: "http://127.0.0.1:18080", sk: en.serverKey, th: payloadHash(v1), s: en.secret })).toString("base64url")], { env });
const ag = spawn(AGENT, ["run"], { env, stdio: "ignore" });
await new Promise((r) => setTimeout(r, 1500));
const [, cat] = await api("GET", "/catalog");
const dev = cat.devices[0];
await api("POST", `/devices/${dev.id}/approve`, { fingerprint: dev.fingerprint });
const [, conn] = await api("POST", "/connections", { folderId: folder.id, name: "SSH", protocol: "ssh", deviceId: dev.id, port: 22 });
const cmd = (k, user) => seal({ t: "cmd", op: "tunnel.open", device: dev.id, port: 22, user, nonce: randomBytes(18).toString("base64url"), iat: now(), exp: now() + 60 }, k.privateKey, k.publicKey);

let wrongPass = false; try { openRecovery(rec.file, "frase sbagliata ma lunga 123"); } catch { wrongPass = true; }
ok(wrongPass, "frase segreta errata rifiutata");
const R = openRecovery(rec.file, "una frase segreta molto lunga");
ok(R.publicKey === rec.publicKey, "chiave di emergenza aperta con la frase corretta");
ok((await api("POST", "/sessions", { connectionId: conn.id, command: cmd(R, "emergenza") }))[0] === 403, "la chiave di emergenza non può aprire tunnel");

// PC dell'amministratore perso: ripristino firmato con la chiave di emergenza
await api("POST", "/me/keys", { publicKey: B.publicKey, label: "PC nuovo" });
const v3 = seal({ t: "trust", version: 3, prev: payloadHash(v2), admins: [{ name: "admin", key: B.publicKey }, { name: "emergenza", key: rec.publicKey, role: "recovery" }], revokedKeys: [A.publicKey], iat: now() }, R.privateKey, R.publicKey);
ok((await api("PUT", "/trust", { env: v3 }))[0] === 200, "nuovo elenco firmato con la chiave di emergenza accettato dal server");
await new Promise((r) => setTimeout(r, 800));
const status = execFileSync(AGENT, ["status"], { env }).toString();
ok(/versione 3/.test(status), "l'agente accetta il nuovo elenco");
ok((await api("POST", "/sessions", { connectionId: conn.id, command: cmd(A, "admin") }))[0] === 403, "la chiave del PC perso non apre più tunnel");
ok((await api("POST", "/sessions", { connectionId: conn.id, command: cmd(B, "admin") }))[0] === 200, "il nuovo PC dell'amministratore apre tunnel");
const onlyRecovery = seal({ t: "trust", version: 4, prev: payloadHash(v3), admins: [{ name: "emergenza", key: rec.publicKey, role: "recovery" }], iat: now() }, R.privateKey, R.publicKey);
ok((await api("PUT", "/trust", { env: onlyRecovery }))[0] === 400, "elenco con la sola chiave di emergenza rifiutato");
ag.kill();
process.exit(0);
