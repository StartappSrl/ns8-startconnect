// Aggiornamenti firmati dell'agente: pubblicazione, download, preparazione e installazione,
// con i tentativi di attacco (firma non valida, binario alterato, catena falsificata, versione precedente).
// Richiede: backend avviato come in e2e-agent.mjs; binari di prova 0.1.0 (AGENT), 0.2.0 e 0.0.5.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { newKeyPair, seal, payloadHash } from "../dist/envelope.js";
import { testSession } from "./helpers.mjs";

const W = process.env.WORK ?? "/tmp/updtest", BASE = "http://127.0.0.1:18080/api";
const AGENT = process.env.AGENT ?? "/tmp/agbin/startconnect-agent", BIN = process.env.BIN ?? "/tmp/agbin";
const ok = (c, l) => console.log((c ? "OK   " : "FAIL ") + l);
const now = () => Math.floor(Date.now() / 1000);
const tok = testSession(W + "/data/startconnect.sqlite", "admin", ["domain admins"], true);
const api = async (m, p, b) => { const r = await fetch(BASE + p, { method: m, headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: b && JSON.stringify(b) }); return [r.status, r.status === 204 ? null : await r.json()]; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = { ...process.env, STARTCONNECT_AGENT_DIR: W + "/agent" };

const A = newKeyPair(), rogue = newKeyPair();
const v1 = seal({ t: "trust", version: 1, prev: "", admins: [{ name: "admin", key: A.publicKey }], iat: now() }, A.privateKey, A.publicKey);
await api("PUT", "/trust", { env: v1 });
const [, folder] = await api("POST", "/folders", { name: "Cliente", parentId: null });
const [, en] = await api("POST", "/enrollments", { folderId: folder.id, hours: 1, uses: 1 });
execFileSync(AGENT, ["install", "--code", "SCE1-" + Buffer.from(JSON.stringify({ v: 1, u: "http://127.0.0.1:18080", sk: en.serverKey, th: payloadHash(v1), s: en.secret })).toString("base64url")], { env });
// L'agente gira come copia installata nella cartella di prova, come farebbe il servizio
execFileSync("cp", [AGENT, W + "/agent/startconnect-agent"]);
ok(existsSync(W + "/agent/anchor.json"), "ancora di fiducia scritta all'installazione");

const manifest = (key, file, version) => {
  const data = readFileSync(file);
  return { data, env: seal({ t: "update", version, platform: "linux-amd64", sha256: createHash("sha256").update(data).digest("hex"), size: data.length, iat: now() }, key.privateKey, key.publicKey) };
};
const publish = async ({ data, env: m }) => (await fetch(BASE + "/agent-updates/linux-amd64", { method: "PUT", headers: { authorization: "Bearer " + tok, "content-type": "application/octet-stream", "x-manifest": Buffer.from(JSON.stringify(m)).toString("base64url") }, body: data })).status;

ok(await publish(manifest(rogue, BIN + "/agent-0.2.0", "0.2.0")) === 400, "server: manifesto firmato da una chiave estranea rifiutato");
const good = manifest(A, BIN + "/agent-0.2.0", "0.2.0");
ok(await publish({ data: Buffer.concat([good.data, Buffer.from("x")]), env: good.env }) === 400, "server: binario diverso dal manifesto rifiutato");
ok(await publish(good) === 200, "aggiornamento 0.2.0 pubblicato da un amministratore fidato");

const apply = () => { try { execFileSync(AGENT, ["apply-update"], { env, stdio: "ignore" }); return true; } catch { return false; } };
const run = (bin) => { const p = spawn(bin, ["run"], { env, stdio: "ignore" }); return p; };
let ag = run(W + "/agent/startconnect-agent");
for (let i = 0; i < 20 && !existsSync(W + "/agent/update/ready"); i++) await sleep(500);
ok(existsSync(W + "/agent/update/ready") && readFileSync(W + "/agent/update/version", "utf8") === "0.2.0", "l'agente ha scaricato, verificato e preparato la 0.2.0");
ag.kill();

// Attacco 1: binario preparato alterato dopo la verifica dell'agente
const staged = readFileSync(W + "/agent/update/agent.new");
writeFileSync(W + "/agent/update/agent.new", Buffer.concat([staged.subarray(0, 1000), Buffer.from("XX"), staged.subarray(1002)]));
ok(!apply() && execFileSync(W + "/agent/startconnect-agent", ["version"]).toString().trim() === "0.1.0", "aggiornatore: binario alterato non installato");

// Attacco 2: agente compromesso prepara un binario firmato da una chiave aggiunta con una catena falsa
ag = run(W + "/agent/startconnect-agent");
await publish(good);
for (let i = 0; i < 20 && !existsSync(W + "/agent/update/ready"); i++) await sleep(500);
ag.kill();
const fakeV2 = seal({ t: "trust", version: 2, prev: payloadHash(v1), admins: [{ name: "x", key: rogue.publicKey }], iat: now() }, rogue.privateKey, rogue.publicKey);
const evil = manifest(rogue, BIN + "/agent-0.2.0", "0.2.0");
writeFileSync(W + "/agent/update/chain.json", JSON.stringify([fakeV2]));
writeFileSync(W + "/agent/update/manifest.json", JSON.stringify(evil.env));
ok(!apply() && execFileSync(W + "/agent/startconnect-agent", ["version"]).toString().trim() === "0.1.0", "aggiornatore: catena di fiducia falsificata rifiutata (ancora fuori portata dell'agente)");

// Installazione legittima
ag = run(W + "/agent/startconnect-agent");
await publish(good);
for (let i = 0; i < 20 && !existsSync(W + "/agent/update/ready"); i++) await sleep(500);
ag.kill();
ok(apply() && execFileSync(W + "/agent/startconnect-agent", ["version"]).toString().trim() === "0.2.0", "aggiornatore: versione 0.2.0 verificata e installata");
ok(!existsSync(W + "/agent/update"), "area di preparazione ripulita");

// Attacco 3: ritorno a una versione precedente firmata
const old = manifest(A, BIN + "/agent-0.0.5", "0.0.5");
ok(await publish(old) === 200, "server accetta la pubblicazione della 0.0.5 (la decisione è dell'agente)");
ag = run(W + "/agent/startconnect-agent");
await sleep(2500);
ag.kill();
ok(!existsSync(W + "/agent/update/ready"), "agente: versione precedente ignorata");
const log = readFileSync(W + "/agent/agent.log", "utf8");
ok(/installata la versione 0\.2\.0/.test(log) && /non installato/.test(log), "registro locale: installazioni e rifiuti tracciati");
process.exit(0);
