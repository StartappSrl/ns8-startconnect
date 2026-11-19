// Prova completa: backend reale + agente reale + guacd simulato, inclusi tentativi di attacco.
// Uso (da server/app, dopo npm run build e go build dell'agente):
//   WORK=/tmp/startconnect-e2e DATA_DIR=$WORK/data ... node dist/index.js   (vedi README)
//   AGENT=../../agent/startconnect-agent WORK=/tmp/startconnect-e2e node test/e2e-agent.mjs
import net from "node:net";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { testSession } from "./helpers.mjs";
import WebSocket from "ws";
import { newKeyPair, seal, payloadHash, fingerprint } from "../dist/envelope.js";

const BASE = "http://127.0.0.1:18080";
const jwt = async (sub, admin, groups) => testSession(WORK + "/data/startconnect.sqlite", sub, groups, admin);
const api = async (tok, m, p, b) => {
  const r = await fetch(BASE + "/api" + p, { method: m, headers: { "content-type": "application/json", ...(tok ? { authorization: "Bearer " + tok } : {}) }, body: b && JSON.stringify(b) });
  return [r.status, r.status === 204 ? null : await r.json()];
};
const now = () => Math.floor(Date.now() / 1000);
const ok = (cond, label) => console.log((cond ? "OK   " : "FAIL ") + label);
const AGENT = process.env.AGENT ?? "../../agent/startconnect-agent";
const WORK = process.env.WORK ?? "/tmp/startconnect-e2e";
const env = { ...process.env, STARTCONNECT_AGENT_DIR: WORK + "/agentdir" };

// Servizio di destinazione sul "dispositivo": eco su 7777
net.createServer((s) => { s.on("error", () => {}); s.pipe(s); }).listen(7777, "127.0.0.1");

// guacd finto: si collega alla porta indicata da StartConnect e verifica l'eco
let guacTarget = null;
net.createServer((s) => {
  s.on("error", () => {});
  let buf = "";
  s.on("data", (d) => {
    buf += d.toString();
    if (buf.includes("6.select")) s.write("4.args,13.VERSION_1_5_0,8.hostname,4.port;");
    if (buf.includes("7.connect")) {
      const m = /7\.connect,\d+\.[^,;]*,\d+\.([^,;]*),\d+\.(\d+)/.exec(buf);
      guacTarget = m && { host: m[1], port: Number(m[2]) };
      s.write("5.ready,37.$abcdef01-0000-0000-0000-000000000000;");
    }
  });
}).listen(14822, "127.0.0.1");

const admin = await jwt("admin", true, ["domain admins"]);
const tech = await jwt("luca", false, ["tecnici"]);
const adminKey = newKeyPair(), techKey = newKeyPair(), rogueKey = newKeyPair();

await api(admin, "POST", "/me/keys", { publicKey: adminKey.publicKey, label: "PC admin" });
await api(tech, "POST", "/me/keys", { publicKey: techKey.publicKey, label: "PC luca" });
const [, noTrust] = await api(admin, "POST", "/enrollments", { folderId: "x" });

// Elenco fidato v1, firmato sul "PC" dell'amministratore
const trust1 = seal({ t: "trust", version: 1, prev: "", admins: [{ name: "admin", key: adminKey.publicKey }], iat: now() }, adminKey.privateKey, adminKey.publicKey);
ok((await api(admin, "PUT", "/trust", { env: trust1 }))[0] === 200, "elenco fidato v1 accettato");
const forged = seal({ t: "trust", version: 2, prev: payloadHash(trust1), admins: [{ name: "x", key: rogueKey.publicKey }], iat: now() }, rogueKey.privateKey, rogueKey.publicKey);
ok((await api(admin, "PUT", "/trust", { env: forged }))[0] === 400, "server rifiuta elenco v2 firmato da chiave estranea");

// Cartella, permessi e certificato del tecnico
const [, folder] = await api(admin, "POST", "/folders", { name: "Cliente Bianchi", parentId: null });
await api(admin, "PUT", `/folders/${folder.id}/acl`, { entries: [{ group: "tecnici", level: "use" }] });
const [, sec] = await api(admin, "GET", "/security");
const techRow = sec.keys.find((k) => k.username === "luca");
const cert = seal({ t: "cert", sub: "luca", key: techKey.publicKey, role: "tech", iat: now(), exp: now() + 30 * 86400 }, adminKey.privateKey, adminKey.publicKey);
ok((await api(admin, "PUT", `/keys/${techRow.id}/cert`, { env: cert }))[0] === 200, "certificato del tecnico registrato");

// Codice di installazione e installazione dell'agente
const [, en] = await api(admin, "POST", "/enrollments", { folderId: folder.id, hours: 1, uses: 1 });
const code = "SCE1-" + Buffer.from(JSON.stringify({ v: 1, u: BASE, sk: en.serverKey, th: payloadHash(trust1), s: en.secret })).toString("base64url");
const out = execFileSync(AGENT, ["install", "--code", code], { env }).toString();
const fp = /([0-9a-f]{4}(-[0-9a-f]{4}){7})/.exec(out)[1];
ok(Boolean(fp), "agente installato, impronta " + fp);
let reuse; try { execFileSync(AGENT, ["install", "--code", code], { env: { ...env, STARTCONNECT_AGENT_DIR: WORK + "/agent2" } }); reuse = false; } catch { reuse = true; }
ok(reuse, "codice di installazione monouso");
execFileSync(AGENT, ["ports", "3389,22,7777"], { env });

const agentProc = spawn(AGENT, ["run"], { env, stdio: ["ignore", "ignore", "pipe"] });
let agentLog = ""; agentProc.stderr.on("data", (d) => (agentLog += d));
await new Promise((r) => setTimeout(r, 1500));

let [, cat] = await api(admin, "GET", "/catalog");
let dev = cat.devices[0];
ok(dev.status === "pending" && dev.online, "dispositivo collegato e in attesa di approvazione");
ok(dev.fingerprint === fp, "impronta uguale su agente e server");
ok((await api(admin, "POST", `/devices/${dev.id}/approve`, { fingerprint: "0000-0000-0000-0000-0000-0000-0000-0000" }))[0] === 400, "approvazione con impronta sbagliata rifiutata");
ok((await api(admin, "POST", `/devices/${dev.id}/approve`, { fingerprint: fp }))[0] === 200, "dispositivo approvato");
const [, inv] = await api(admin, "GET", `/devices/${dev.id}`);
ok(inv.inventory?.hostname && inv.inventory?.os?.name, `inventario ricevuto: ${inv.inventory?.os?.name}, ${inv.inventory?.cpu?.cores} core`);

const [, conn] = await api(admin, "POST", "/connections", { folderId: folder.id, name: "Servizio eco", protocol: "ssh", deviceId: dev.id, port: 7777 });
const [, connBad] = await api(admin, "POST", "/connections", { folderId: folder.id, name: "Porta non consentita", protocol: "ssh", deviceId: dev.id, port: 8888 });

const command = (key, user, port, extra = {}) => seal({ t: "cmd", op: "tunnel.open", device: dev.id, port, user, nonce: randomBytes(18).toString("base64url"), iat: now(), exp: now() + 60, ...extra }, key.privateKey, key.publicKey);

// Prova positiva: il tecnico certificato apre il tunnel
const [s1, sess] = await api(tech, "POST", "/sessions", { connectionId: conn.id, credential: { username: "u", password: "p" }, command: command(techKey, "luca", 7777), cert });
ok(s1 === 200, "sessione via agente autorizzata");
await new Promise((res) => { const ws = new WebSocket(`ws://127.0.0.1:18080/tunnel?token=${encodeURIComponent(sess.token)}`, "guacamole"); ws.on("open", () => setTimeout(() => { ws.close(); res(); }, 400)); ws.on("error", res); });
ok(guacTarget?.host === "127.0.0.1", `guacd indirizzato alla porta locale ${guacTarget?.port}`);
const echo = await new Promise((res) => {
  const s = net.connect(guacTarget.port, "127.0.0.1", () => s.write("ciao dal tecnico"));
  s.on("data", (d) => { res(d.toString()); s.destroy(); });
  setTimeout(() => res("(nessuna risposta)"), 3000);
});
ok(echo === "ciao dal tecnico", "dati passati attraverso l'agente: " + JSON.stringify(echo));

// Attacchi respinti dal server
ok((await api(tech, "POST", "/sessions", { connectionId: conn.id, command: command(rogueKey, "luca", 7777), cert }))[0] === 403, "chiave non certificata rifiutata");
ok((await api(tech, "POST", "/sessions", { connectionId: conn.id, command: command(techKey, "admin", 7777), cert }))[0] === 403, "tecnico che si spaccia per un altro utente rifiutato");
ok((await api(tech, "POST", "/sessions", { connectionId: conn.id, command: command(techKey, "luca", 7777, { iat: now() - 600, exp: now() - 500 }), cert }))[0] === 403, "comando scaduto rifiutato");

// Attacco che il server lascia passare: la porta 8888 la blocca solo l'agente
const [s2] = await api(tech, "POST", "/sessions", { connectionId: connBad.id, command: command(techKey, "luca", 8888), cert });
const tok2 = (await api(tech, "POST", "/sessions", { connectionId: connBad.id, command: command(techKey, "luca", 8888), cert }))[1].token;
guacTarget = null;
await new Promise((res) => { const ws = new WebSocket(`ws://127.0.0.1:18080/tunnel?token=${encodeURIComponent(tok2)}`, "guacamole"); ws.on("open", () => setTimeout(() => { ws.close(); res(); }, 400)); ws.on("error", res); });
const blocked = await new Promise((res) => {
  const s = net.connect(guacTarget.port, "127.0.0.1", () => s.write("x"));
  s.on("data", () => res(false)); s.on("error", () => res(true)); s.on("close", () => res(true)); setTimeout(() => res(true), 2000);
});
await new Promise((r) => setTimeout(r, 300));
ok(s2 === 200 && blocked && agentLog.includes("porta 8888 non consentita"), "porta non consentita bloccata dall'agente");

// Server compromesso: inserisce nel database un elenco fidato falso
agentProc.kill(); await new Promise((r) => setTimeout(r, 300));
execFileSync("node", ["-e", `
const D=require(process.cwd()+"/node_modules/better-sqlite3");const db=new D(process.argv[2]+"/data/startconnect.sqlite");
db.prepare("INSERT INTO trust (version, envelope, hash, created_by, created_at) VALUES (2, ?, 'x', 'attacker', 'now')").run(process.argv[1]);`, JSON.stringify(forged), WORK]);
const agent2 = spawn(AGENT, ["run"], { env, stdio: ["ignore", "ignore", "pipe"] });
let log2 = ""; agent2.stderr.on("data", (d) => (log2 += d));
await new Promise((r) => setTimeout(r, 1500));
ok(log2.includes("elenco fidato rifiutato"), "agente rifiuta l'elenco fidato falsificato dal server");
// Con l'elenco falso, il server crede che "x" sia amministratore; l'agente no
const rogueCmd = command(rogueKey, "x", 7777);
const status = execFileSync(AGENT, ["status"], { env }).toString();
ok(/versione 1 \(1 amministratori\)/.test(status), "l'agente resta sulla versione fidata 1");
agent2.kill();
console.log("\n--- registro locale dell'agente ---\n" + require_log());
function require_log() { return execFileSync("tail", ["-n", "8", WORK + "/agentdir/agent.log"]).toString(); }
process.exit(0);
