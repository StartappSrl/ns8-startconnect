// Prova di accesso con OpenLDAP reale: password, MFA (configurazione, verifica, riuso,
// codici di riserva, tentativi), sessioni revocabili, account disattivati e cambi di gruppo.
// Richiede slapd su 127.0.0.1:3890 (vedi README) e il backend avviato con LDAP_URL corrispondente.
import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import Database from "better-sqlite3";

const BASE = "http://127.0.0.1:18080/api";
const DB = process.env.DB ?? "/tmp/authtest/data/startconnect.sqlite";
const ok = (c, l) => console.log((c ? "OK   " : "FAIL ") + l);
const post = async (p, b, tok) => { const r = await fetch(BASE + p, { method: "POST", headers: { "content-type": "application/json", ...(tok ? { authorization: "Bearer " + tok } : {}) }, body: JSON.stringify(b ?? {}) }); return [r.status, r.status === 204 ? null : await r.json()]; };
const get = async (p, tok) => { const r = await fetch(BASE + p, { headers: { authorization: "Bearer " + tok } }); return [r.status, await r.json()]; };
function b32(s) { const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, v = 0; const out = []; for (const c of s) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
const nowStep = () => Math.floor(Date.now() / 30000);
const lastStep = new Map();
// Codice per un passo mai usato e dentro la finestra ±1 accettata dal server
async function next(secret) {
  let step = Math.max((lastStep.get(secret) ?? -1) + 1, nowStep() - 1);
  while (step > nowStep() + 1) await new Promise((r) => setTimeout(r, 1000));
  lastStep.set(secret, step);
  return totpAt(secret, step);
}
function totp(secret, offset = 0) { return totpAt(secret, nowStep() + offset); }
function totpAt(secret, step) { const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(step)); const h = createHmac("sha1", b32(secret)).update(m).digest(); const o = h[h.length - 1] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0"); }
const ldapmod = (ldif) => execFileSync("ldapmodify", ["-x", "-H", "ldap://127.0.0.1:3890", "-D", "cn=admin,dc=test,dc=lan", "-w", "secret"], { input: ldif });
const reset = (ldif) => { try { ldapmod(ldif); } catch { /* già nello stato iniziale */ } };
reset("dn: cn=domain admins,ou=Groups,dc=test,dc=lan\nchangetype: modify\ndelete: memberUid\nmemberUid: luca\n");
reset("dn: uid=luca,ou=People,dc=test,dc=lan\nchangetype: modify\ndelete: shadowExpire\n");
const ageCheck = () => new Database(DB).prepare("UPDATE user_sessions SET checked_at = 0").run();

ok((await post("/auth/login", { username: "mario", password: "sbagliata" }))[0] === 401, "password errata rifiutata");
ok((await post("/auth/login", { username: "anna", password: "Password1!" }))[0] === 401, "account scaduto nel dominio rifiutato");
ok((await post("/auth/login", { username: "mario", password: "" }))[0] === 401, "password vuota rifiutata (niente bind anonimo)");

let [, r] = await post("/auth/login", { username: "MARIO@test.lan", password: "Password1!" });
ok(r.status === "setup" && r.secret && r.uri.startsWith("otpauth://totp/"), "primo accesso: richiesta configurazione MFA (nessuna sessione senza secondo fattore)");
const secret = r.secret;
ok((await post("/auth/mfa/setup", { ticket: r.ticket, code: "000000" }))[0] === 401, "codice di configurazione errato rifiutato");
let [s, setup] = await post("/auth/mfa/setup", { ticket: r.ticket, code: totpAt(secret, nowStep()) });
lastStep.set(secret, nowStep());
ok(s === 200 && setup.token && setup.backupCodes.length === 10 && setup.user.admin, "MFA attivata: sessione, 10 codici di riserva, gruppo amministratori riconosciuto");
const backup = setup.backupCodes;
ok((await get("/catalog", setup.token))[0] === 200, "sessione valida");

[, r] = await post("/auth/login", { username: "mario", password: "Password1!" });
ok(r.status === "mfa" && !r.token, "accesso successivo: serve il codice");
ok((await post("/auth/mfa", { ticket: r.ticket, code: totpAt(secret, lastStep.get(secret)) }))[0] === 401, "stesso codice TOTP non riutilizzabile");
[s] = await post("/auth/mfa", { ticket: r.ticket, code: await next(secret) });
ok(s === 200, "codice del passo successivo accettato");

[, r] = await post("/auth/login", { username: "mario", password: "Password1!" });
[s] = await post("/auth/mfa", { ticket: r.ticket, code: backup[0] });
ok(s === 200, "codice di riserva accettato");
[, r] = await post("/auth/login", { username: "mario", password: "Password1!" });
ok((await post("/auth/mfa", { ticket: r.ticket, code: backup[0] }))[0] === 401, "codice di riserva non riutilizzabile");
for (let i = 0; i < 5; i++) await post("/auth/mfa", { ticket: r.ticket, code: "123456" });
ok((await post("/auth/mfa", { ticket: r.ticket, code: totpAt(secret, nowStep()) }))[0] === 401, "ticket bloccato dopo troppi tentativi");

// Tecnico: sessione, cambio gruppo, disattivazione
[, r] = await post("/auth/login", { username: "luca", password: "Password1!" });
const lucaSecret = r.secret;
const [, luca] = await post("/auth/mfa/setup", { ticket: r.ticket, code: totpAt(lucaSecret, nowStep()) });
lastStep.set(lucaSecret, nowStep());
ok(luca.token && !luca.user.admin, "tecnico collegato senza diritti di amministratore");
ldapmod("dn: cn=domain admins,ou=Groups,dc=test,dc=lan\nchangetype: modify\nadd: memberUid\nmemberUid: luca\n");
ageCheck();
const [, cat] = await get("/catalog", luca.token);
ok(cat.user?.admin === true, "aggiunto al gruppo nel dominio: diventa amministratore senza nuovo accesso");
ldapmod("dn: uid=luca,ou=People,dc=test,dc=lan\nchangetype: modify\nreplace: shadowExpire\nshadowExpire: 1\n");
ageCheck();
ok((await get("/catalog", luca.token))[0] === 401, "account disattivato nel dominio: sessione chiusa entro la verifica periodica");
ldapmod("dn: uid=luca,ou=People,dc=test,dc=lan\nchangetype: modify\ndelete: shadowExpire\n");

// Amministratore azzera la MFA di luca (telefono perso)
[, r] = await post("/auth/login", { username: "luca", password: "Password1!" });
const [sl, luca2] = await post("/auth/mfa", { ticket: r.ticket, code: await next(lucaSecret) });
if (sl !== 200) console.log("debug luca2", sl, luca2, r);
[, r] = await post("/auth/login", { username: "mario", password: "Password1!" });
const [sm, mario] = await post("/auth/mfa", { ticket: r.ticket, code: await next(secret) });
if (sm !== 200) console.log("debug mario", sm, mario);
const del = await fetch(BASE + "/users/luca/mfa", { method: "DELETE", headers: { authorization: "Bearer " + mario.token } });
ok(del.status === 200 && (await get("/catalog", luca2.token))[0] === 401, "MFA azzerata dall'amministratore: sessioni di luca chiuse");
[, r] = await post("/auth/login", { username: "luca", password: "Password1!" });
ok(r.status === "setup", "luca deve configurare di nuovo la MFA");

ok((await post("/auth/logout", {}, mario.token))[0] === 204 && (await get("/catalog", mario.token))[0] === 401, "uscita: sessione revocata sul server");
const rows = new Database(DB).prepare("SELECT token_hash FROM user_sessions").all();
ok(rows.every((x) => /^[0-9a-f]{64}$/.test(x.token_hash)), "nel database solo hash dei token");
const mfaRow = new Database(DB).prepare("SELECT secret FROM user_mfa WHERE username='mario'").get();
ok(!mfaRow.secret.includes(secret), "segreto TOTP cifrato nel database");
