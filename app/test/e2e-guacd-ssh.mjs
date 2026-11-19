// Prova con guacd reale e un server SSH locale (porta 2222, utente tester): sessione diretta e tramite agente.
// Richiede guacd in ascolto su GUACD_PORT e il backend avviato come in test/e2e-agent.mjs.
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { testSession } from "./helpers.mjs";
import WebSocket from "ws";
import { newKeyPair, seal, payloadHash } from "../dist/envelope.js";
const BASE = "http://127.0.0.1:18080/api", W = process.env.WORK ?? "/tmp/realtest", AGENT = process.env.AGENT ?? "/tmp/agbin/startconnect-agent";
const now = () => Math.floor(Date.now() / 1000);
const tok = testSession(W + "/data/startconnect.sqlite", "admin", ["domain admins"], true);
const api = async (m, p, b) => (await fetch(BASE + p, { method: m, headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: b && JSON.stringify(b) })).json();
const k = newKeyPair();
await api("POST", "/me/keys", { publicKey: k.publicKey, label: "pc" });
const trust = seal({ t: "trust", version: 1, prev: "", admins: [{ name: "admin", key: k.publicKey }], iat: now() }, k.privateKey, k.publicKey);
await api("PUT", "/trust", { env: trust });
const folder = await api("POST", "/folders", { name: "Prova", parentId: null });

// Sessione reale: legge le istruzioni Guacamole finché arriva testo del terminale
async function session(connectionId, extra = {}) {
  const s = await api("POST", "/sessions", { connectionId, credential: { username: "tester", password: "pässwörd€" }, ...extra });
  if (!s.token) return "errore: " + JSON.stringify(s);
  return new Promise((res) => {
    const ws = new WebSocket(`ws://127.0.0.1:18080/tunnel?token=${encodeURIComponent(s.token)}&width=1024&height=768&dpi=96`, "guacamole");
    const seen = new Set(); let imgBytes = 0;
    ws.on("message", (d) => {
      for (const m of d.toString().matchAll(/(\d+)\.([a-z]+)[,;]/g)) seen.add(m[2]);
      imgBytes += (d.toString().match(/\d+\.blob,/g) || []).length;
      if (d.toString().includes("4.sync")) ws.send("4.sync,1.0;"); // risponde come un client vero
    });
    setTimeout(() => { ws.close(); res(`istruzioni ricevute: ${[...seen].filter(x=>["ready","size","img","blob","sync","cursor"].includes(x)).join(", ")}; blocchi immagine: ${imgBytes}`); }, 4000);
  });
}

const direct = await api("POST", "/connections", { folderId: folder.id, name: "SSH diretto", protocol: "ssh", hostname: "127.0.0.1", port: 2222 });
console.log("SSH diretto ->", await session(direct.id));

const en = await api("POST", "/enrollments", { folderId: folder.id, hours: 1, uses: 1 });
const code = "SCE1-" + Buffer.from(JSON.stringify({ v: 1, u: "http://127.0.0.1:18080", sk: en.serverKey, th: payloadHash(trust), s: en.secret })).toString("base64url");
const env = { ...process.env, STARTCONNECT_AGENT_DIR: W + "/agent" };
execFileSync(AGENT, ["install", "--code", code], { env });
execFileSync(AGENT, ["ports", "2222"], { env });
const ag = spawn(AGENT, ["run"], { env, stdio: "ignore" });
await new Promise((r) => setTimeout(r, 1500));
const dev = (await api("GET", "/catalog")).devices[0];
await api("POST", `/devices/${dev.id}/approve`, { fingerprint: dev.fingerprint });
const via = await api("POST", "/connections", { folderId: folder.id, name: "SSH via agente", protocol: "ssh", deviceId: dev.id, port: 2222 });
const cmd = seal({ t: "cmd", op: "tunnel.open", device: dev.id, port: 2222, user: "admin", nonce: randomBytes(18).toString("base64url"), iat: now(), exp: now() + 60 }, k.privateKey, k.publicKey);
console.log("SSH via agente ->", await session(via.id, { command: cmd }));
ag.kill();
process.exit(0);
