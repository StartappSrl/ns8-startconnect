// Sessione di prova scritta direttamente nel database (le prove non hanno un dominio LDAP).
import { createHash, randomBytes } from "node:crypto";
import Database from "better-sqlite3";

export function testSession(dbPath, username, groups, admin) {
  const token = randomBytes(32).toString("base64url");
  const t = Date.now();
  const db = new Database(dbPath);
  db.prepare(`INSERT INTO user_sessions (token_hash, username, display_name, groups, admin, created_at, last_seen, checked_at, ip)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test')`)
    .run(createHash("sha256").update(token).digest("hex"), username, username, JSON.stringify(groups), admin ? 1 : 0, t, t, t);
  db.close();
  return token;
}
