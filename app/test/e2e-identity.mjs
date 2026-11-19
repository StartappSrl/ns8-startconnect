// Identità dei server con guacd reale: chiave SSH rilevata e verificata, chiave errata rifiutata.
// Richiede guacd su GUACD_PORT e sshd su 127.0.0.1:2222 (utente tester), come e2e-guacd-ssh.mjs.
import { readFileSync } from "node:fs";
import WebSocket from "ws";
import { testSession } from "./helpers.mjs";

const BASE = "http://127.0.0.1:18080/api";
const W = process.env.WORK ?? "/tmp/idtest";
const tok = testSession(W + "/data/startconnect.sqlite", "admin", ["domain admins"], true);
const api = async (m, p, b) => { const r = await fetch(BASE + p, { method: m, headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: b && JSON.stringify(b) }); return [r.status, await r.json()]; };
const ok = (c, l) => console.log((c ? "OK   " : "FAIL ") + l);
const accepted = () => (readFileSync("/tmp/sshd.log", "utf8").match(/Accepted password for tester/g) ?? []).length;

async function session(connectionId) {
  const [, s] = await api("POST", "/sessions", { connectionId, credential: { username: "tester", password: "pässwörd€" } });
  return new Promise((res) => {
    const ws = new WebSocket(`ws://127.0.0.1:18080/tunnel?token=${encodeURIComponent(s.token)}&width=800&height=600&dpi=96`, "guacamole");
    let images = 0;
    let error = "";
    ws.on("message", (d) => {
      const t = d.toString();
      images += (t.match(/\d+\.blob,/g) || []).length;
      const e = /5\.error,\d+\.([^,]*),/.exec(t);
      if (e) error = e[1];
      if (t.includes("4.sync")) ws.send("4.sync,1.0;");
    });
    ws.on("error", () => undefined);
    setTimeout(() => { ws.close(); res({ images, error }); }, 3500);
  });
}

const [, folder] = await api("POST", "/folders", { name: "Prova", parentId: null });
const [ps, probe] = await api("POST", "/probe", { folderId: folder.id, protocol: "ssh", hostname: "127.0.0.1", port: 2222 });
ok(ps === 200 && probe.keys.length >= 2, `chiavi SSH rilevate: ${probe.keys?.map((k) => k.type).join(", ")}`);

for (const key of probe.keys) {
  const [, c] = await api("POST", "/connections", { folderId: folder.id, name: "SSH " + key.type, protocol: "ssh", hostname: "127.0.0.1", port: 2222, options: { "host-key": key.line } });
  const before = accepted();
  const r = await session(c.id);
  console.log(`      ${key.type}: accesso ${accepted() > before ? "riuscito" : "non riuscito"}${r.error ? ` (${r.error})` : ""}`);
}

// Chiave di un altro server: guacd deve rifiutare prima di inviare la password
const other = probe.keys[0].line.replace(/[A-Za-z0-9+/]{20}(?==*$)/, "AAAAAAAAAAAAAAAAAAAA");
const [, bad] = await api("POST", "/connections", { folderId: folder.id, name: "SSH chiave errata", protocol: "ssh", hostname: "127.0.0.1", port: 2222, options: { "host-key": other } });
const before = accepted();
const r = await session(bad.id);
ok(accepted() === before, `chiave diversa da quella confermata: connessione bloccata, password non inviata${r.error ? ` (${r.error})` : ""}`);
ok((await api("POST", "/probe", { folderId: folder.id, protocol: "ssh", hostname: "-oProxyCommand=x", port: 22 }))[0] === 400, "indirizzo con opzioni iniettate rifiutato");

// ---------- RDP (xrdp su 127.0.0.1:3390, se presente) ----------
const [rs, rdp] = await api("POST", "/probe", { folderId: folder.id, protocol: "rdp", hostname: "127.0.0.1", port: 3390 });
if (rs === 200) {
  console.log(`      certificato RDP: ${rdp.display.slice(0, 23)}…`);
  const mk = async (name, options) => (await api("POST", "/connections", { folderId: folder.id, name, protocol: "rdp", hostname: "127.0.0.1", port: 3390, options: { security: "tls", ...options } }))[1];
  const good = await session((await mk("RDP impronta confermata", { "cert-fingerprints": rdp.fingerprint })).id);
  ok(good.images > 0 && !good.error, `impronta confermata: sessione RDP aperta (${good.images} immagini)`);
  const wrong = await session((await mk("RDP impronta diversa", { "cert-fingerprints": "sha256:" + "00:".repeat(31) + "00" })).id);
  ok(wrong.images === 0, `certificato diverso da quello confermato: sessione bloccata${wrong.error ? ` (${wrong.error})` : ""}`);
  const none = await session((await mk("RDP senza impronta", {})).id);
  ok(none.images === 0, "certificato autofirmato senza impronta confermata: sessione bloccata");
} else {
  console.log("      (server RDP di prova non disponibile)", rdp.message);
}
