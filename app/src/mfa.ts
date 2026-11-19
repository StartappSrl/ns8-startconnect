// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Secondo fattore per l'accesso a StartConnect.
//
// Dopo la password del dominio il server rilascia un "ticket" valido 5 minuti
// e 5 tentativi; la sessione nasce solo dopo il codice TOTP (o un codice di
// riserva). Al primo accesso l'utente configura l'app di autenticazione.

import { randomBytes } from "node:crypto";
import { Router } from "express";
import { createSession, isAdmin, loginAllowed, loginSucceeded, requireAdmin, requireUser, revokeSession, revokeUser, type User } from "./auth.js";
import { config } from "./config.js";
import { audit, db, now } from "./db.js";
import { authenticate } from "./ldap.js";
import { hashBackupCode, newBackupCodes, newSecret, openSecret, otpauthUri, base32Encode, sealSecret, verifyTotp } from "./totp.js";

interface Ticket {
  user: User;
  stage: "verify" | "setup";
  secret?: Buffer;
  expires: number;
  attempts: number;
  ip: string | undefined;
}

interface MfaRow {
  secret: string;
  enabled: number;
  last_step: number;
  backup_codes: string;
}

const tickets = new Map<string, Ticket>();
setInterval(() => {
  const t = Date.now();
  for (const [k, v] of tickets) if (v.expires < t) tickets.delete(k);
}, 60_000).unref();

export const authRouter = Router();

function fail(res: import("express").Response, status: number, code: string, message: string): void {
  res.status(status).json({ code, message });
}

function issue(res: import("express").Response, user: User, ip: string | undefined, extra: Record<string, unknown> = {}): void {
  const token = createSession(user, ip);
  audit(user.username, "login", null, { ip });
  res.json({ status: "ok", token, user, ...extra });
}

function takeTicket(id: unknown, stage: Ticket["stage"]): Ticket | null {
  if (typeof id !== "string") return null;
  const t = tickets.get(id);
  if (!t || t.stage !== stage || t.expires < Date.now()) return null;
  t.attempts += 1;
  if (t.attempts > 5) {
    tickets.delete(id);
    return null;
  }
  return t;
}

authRouter.post("/auth/login", async (req, res) => {
  const { username, password } = (req.body ?? {}) as { username?: unknown; password?: unknown };
  if (typeof username !== "string" || typeof password !== "string") return fail(res, 400, "bad_request", "Indicare utente e password.");
  if (!loginAllowed(`${req.ip}|${username.toLowerCase()}`)) return fail(res, 429, "rate_limited", "Troppi tentativi: riprova tra qualche minuto.");

  let found;
  try {
    found = await authenticate(username, password);
  } catch (e) {
    console.error("LDAP non raggiungibile:", (e as Error).message);
    return fail(res, 503, "directory_unavailable", "Il servizio utenti non risponde: riprova o avvisa un amministratore.");
  }
  if (!found) return fail(res, 401, "invalid_credentials", "Utente o password non corretti.");
  loginSucceeded(`${req.ip}|${username.toLowerCase()}`);
  const user: User = { ...found, admin: isAdmin(found.groups) };

  const mfa = db.prepare("SELECT enabled FROM user_mfa WHERE username = ?").get(user.username) as { enabled: number } | undefined;
  const ticket = randomBytes(24).toString("base64url");
  if (mfa?.enabled) {
    tickets.set(ticket, { user, stage: "verify", expires: Date.now() + 5 * 60_000, attempts: 0, ip: req.ip });
    return void res.json({ status: "mfa", ticket });
  }
  if (!config.mfaRequired) return issue(res, user, req.ip);

  // Primo accesso: si propone un nuovo segreto, attivato solo dopo un codice corretto
  const secret = newSecret();
  tickets.set(ticket, { user, stage: "setup", secret, expires: Date.now() + 10 * 60_000, attempts: 0, ip: req.ip });
  res.json({ status: "setup", ticket, secret: base32Encode(secret), uri: otpauthUri(secret, user.username) });
});

authRouter.post("/auth/mfa", (req, res) => {
  const body = (req.body ?? {}) as { ticket?: unknown; code?: unknown };
  const t = takeTicket(body.ticket, "verify");
  if (!t) return fail(res, 401, "ticket_expired", "Tempo scaduto o troppi tentativi: accedi di nuovo.");
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const row = db.prepare("SELECT secret, enabled, last_step, backup_codes FROM user_mfa WHERE username = ?").get(t.user.username) as MfaRow | undefined;
  if (!row?.enabled) return fail(res, 401, "ticket_expired", "Accedi di nuovo.");

  const step = verifyTotp(openSecret(row.secret), code);
  if (step !== null && step > row.last_step) {
    db.prepare("UPDATE user_mfa SET last_step = ? WHERE username = ?").run(step, t.user.username);
  } else {
    // Codice di riserva: valido una sola volta
    const codes = JSON.parse(row.backup_codes) as string[];
    const h = hashBackupCode(code);
    if (step !== null || !codes.includes(h)) {
      audit(t.user.username, "login.mfa_failed", null, { ip: req.ip });
      return fail(res, 401, "invalid_code", "Codice non valido o già usato.");
    }
    db.prepare("UPDATE user_mfa SET backup_codes = ? WHERE username = ?").run(JSON.stringify(codes.filter((c) => c !== h)), t.user.username);
    audit(t.user.username, "login.backup_code", null, { remaining: codes.length - 1 });
  }
  tickets.delete(body.ticket as string);
  issue(res, t.user, t.ip);
});

authRouter.post("/auth/mfa/setup", (req, res) => {
  const body = (req.body ?? {}) as { ticket?: unknown; code?: unknown };
  const t = takeTicket(body.ticket, "setup");
  if (!t?.secret) return fail(res, 401, "ticket_expired", "Tempo scaduto o troppi tentativi: accedi di nuovo.");
  const step = verifyTotp(t.secret, typeof body.code === "string" ? body.code.trim() : "");
  if (step === null) return fail(res, 401, "invalid_code", "Codice non valido: controlla l'ora del telefono e riprova.");
  const backup = newBackupCodes();
  db.prepare(`INSERT INTO user_mfa (username, secret, enabled, last_step, backup_codes, created_at) VALUES (?, ?, 1, ?, ?, ?)
              ON CONFLICT(username) DO UPDATE SET secret = excluded.secret, enabled = 1, last_step = excluded.last_step,
              backup_codes = excluded.backup_codes, created_at = excluded.created_at`)
    .run(t.user.username, sealSecret(t.secret), step, JSON.stringify(backup.hashes), now());
  tickets.delete(body.ticket as string);
  audit(t.user.username, "mfa.enroll", null, {});
  // I codici di riserva si vedono solo ora
  issue(res, t.user, t.ip, { backupCodes: backup.codes });
});

authRouter.post("/auth/logout", requireUser, (req, res) => {
  revokeSession(req.sessionHash!);
  audit(req.user!.username, "logout", null, {});
  res.status(204).end();
});

/** Amministratori: azzera la MFA di un utente (telefono perso) e chiude le sue sessioni. */
authRouter.delete("/users/:username/mfa", requireUser, requireAdmin, (req, res) => {
  const username = String(req.params.username).toLowerCase();
  const removed = db.prepare("DELETE FROM user_mfa WHERE username = ?").run(username).changes;
  const sessions = revokeUser(username);
  audit(req.user!.username, "mfa.reset", null, { user: username, sessions });
  if (!removed) return fail(res, 404, "not_found", "Questo utente non ha la MFA configurata.");
  res.json({ ok: true, sessions });
});
