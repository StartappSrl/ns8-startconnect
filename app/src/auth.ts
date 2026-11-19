// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Sessioni lato server, revocabili in ogni momento.
//
// Il client riceve un token casuale; nel database resta solo il suo hash.
// Ogni sessione scade dopo 10 ore o 2 ore di inattività, e ogni 10 minuti
// l'utente viene ricontrollato nel dominio: se è disattivato o eliminato le
// sue sessioni vengono chiuse, se cambiano i gruppi cambiano i permessi.

import { createHash, randomBytes } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "./config.js";
import { audit, db } from "./db.js";
import { lookupUser, type DirectoryUser } from "./ldap.js";

export interface User extends DirectoryUser {
  admin: boolean;
}

declare module "express-serve-static-core" {
  interface Request {
    user?: User;
    sessionHash?: string;
  }
}

interface SessionRow {
  token_hash: string;
  username: string;
  display_name: string;
  groups: string;
  admin: number;
  created_at: number;
  last_seen: number;
  checked_at: number;
}

const hash = (token: string) => createHash("sha256").update(token).digest("hex");

export function isAdmin(groups: string[]): boolean {
  return groups.includes(config.adminGroup);
}

export function createSession(user: User, ip: string | undefined): string {
  const token = randomBytes(32).toString("base64url");
  const t = Date.now();
  db.prepare(`INSERT INTO user_sessions (token_hash, username, display_name, groups, admin, created_at, last_seen, checked_at, ip)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(hash(token), user.username, user.displayName, JSON.stringify(user.groups), user.admin ? 1 : 0, t, t, t, ip ?? null);
  return token;
}

export function revokeSession(tokenHash: string): void {
  db.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
}

export function revokeUser(username: string): number {
  return db.prepare("DELETE FROM user_sessions WHERE username = ?").run(username).changes;
}

const unauthorized = (res: Response) =>
  res.status(401).json({ code: "unauthorized", message: "Sessione scaduta: accedi di nuovo." });

export async function requireUser(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return void unauthorized(res);
  const tokenHash = hash(token);
  const row = db.prepare("SELECT * FROM user_sessions WHERE token_hash = ?").get(tokenHash) as SessionRow | undefined;
  const t = Date.now();
  if (!row || t - row.created_at > config.sessionMaxHours * 3_600_000 || t - row.last_seen > config.sessionIdleMinutes * 60_000) {
    if (row) revokeSession(tokenHash);
    return void unauthorized(res);
  }

  let groups = JSON.parse(row.groups) as string[];
  let displayName = row.display_name;
  if (t - row.checked_at > config.directoryCheckMinutes * 60_000) {
    try {
      const found = await lookupUser(row.username);
      if (found.status !== "ok") {
        const closed = revokeUser(row.username);
        audit(row.username, "session.revoked", null, { reason: found.status === "disabled" ? "account disattivato" : "account eliminato", sessions: closed });
        return void unauthorized(res);
      }
      groups = found.user.groups;
      displayName = found.user.displayName;
      db.prepare("UPDATE user_sessions SET groups = ?, display_name = ?, admin = ?, checked_at = ? WHERE username = ?")
        .run(JSON.stringify(groups), displayName, isAdmin(groups) ? 1 : 0, t, row.username);
    } catch (e) {
      // Dominio non raggiungibile: la sessione resta valida, si riprova alla prossima richiesta
      console.error("Verifica utente non riuscita:", (e as Error).message);
    }
  }
  if (t - row.last_seen > 60_000) db.prepare("UPDATE user_sessions SET last_seen = ? WHERE token_hash = ?").run(t, tokenHash);

  req.user = { username: row.username, displayName, groups, admin: isAdmin(groups) };
  req.sessionHash = tokenHash;
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.user?.admin) return next();
  res.status(403).json({ code: "admin_required", message: "Operazione riservata agli amministratori." });
}

setInterval(() => {
  const t = Date.now();
  db.prepare("DELETE FROM user_sessions WHERE created_at < ? OR last_seen < ?")
    .run(t - config.sessionMaxHours * 3_600_000, t - config.sessionIdleMinutes * 60_000);
}, 10 * 60_000).unref();

// ---------- Limite dei tentativi ----------

// 10 tentativi ogni 5 minuti per chiave (IP + utente, oppure ticket MFA)
const attempts = new Map<string, { count: number; reset: number }>();

export function loginAllowed(key: string): boolean {
  const t = Date.now();
  const entry = attempts.get(key);
  if (!entry || entry.reset < t) {
    attempts.set(key, { count: 1, reset: t + 5 * 60_000 });
    return true;
  }
  entry.count += 1;
  return entry.count <= 10;
}

export function loginSucceeded(key: string): void {
  attempts.delete(key);
}

setInterval(() => {
  const t = Date.now();
  for (const [k, v] of attempts) if (v.reset < t) attempts.delete(k);
}, 60_000).unref();
