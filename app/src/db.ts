// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import Database from "better-sqlite3";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { config } from "./config.js";

const MIGRATIONS: string[] = [
  `
  CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    defaults TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
  );
  CREATE TABLE connections (
    id TEXT PRIMARY KEY,
    folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('rdp','ssh','vnc','telnet')),
    hostname TEXT NOT NULL,
    port INTEGER,
    credential TEXT,
    options TEXT NOT NULL DEFAULT '{}',
    notes TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX connections_folder ON connections(folder_id);
  CREATE TABLE folder_acl (
    folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    group_name TEXT NOT NULL COLLATE NOCASE,
    level TEXT NOT NULL CHECK (level IN ('use','edit')),
    PRIMARY KEY (folder_id, group_name)
  );
  CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    connection_id TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX audit_ts ON audit(ts);
  `,
  `
  CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE trust (
    version INTEGER PRIMARY KEY,
    envelope TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE user_keys (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    cert TEXT,
    cert_exp INTEGER
  );
  CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending','active','revoked')),
    enrolled_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    last_seen TEXT,
    agent_version TEXT,
    ports TEXT NOT NULL DEFAULT '[]',
    trust_version INTEGER NOT NULL DEFAULT 0,
    inventory TEXT NOT NULL DEFAULT '{}'
  );
  CREATE TABLE enrollments (
    id TEXT PRIMARY KEY,
    folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    uses_left INTEGER NOT NULL
  );
  ALTER TABLE connections ADD COLUMN device_id TEXT REFERENCES devices(id) ON DELETE CASCADE;
  `,
  `
  CREATE TABLE user_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    groups TEXT NOT NULL,
    admin INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    checked_at INTEGER NOT NULL,
    ip TEXT
  );
  CREATE INDEX user_sessions_user ON user_sessions(username);
  CREATE TABLE user_mfa (
    username TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT 0,
    backup_codes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
  );
  `,
];

function open(): Database.Database {
  mkdirSync(config.dataDir, { recursive: true });
  const file = join(config.dataDir, "startconnect.sqlite");
  const backup = join(config.dataDir, "backup.sqlite");
  // Dopo un ripristino da backup NS8 esiste solo la copia
  if (!existsSync(file) && existsSync(backup)) copyFileSync(backup, file);

  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  const version = db.pragma("user_version", { simple: true }) as number;
  for (let v = version; v < MIGRATIONS.length; v++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[v]!);
      db.pragma(`user_version = ${v + 1}`);
    })();
  }
  return db;
}

export const db = open();

export function now(): string {
  return new Date().toISOString();
}

export function kvGet(key: string): string | undefined {
  return (db.prepare("SELECT value FROM kv WHERE key = ?").get(key) as { value: string } | undefined)?.value;
}

export function kvSet(key: string, value: string): void {
  db.prepare("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(key, value);
}

export function audit(username: string, action: string, connectionId: string | null, detail: Record<string, unknown> = {}): void {
  db.prepare("INSERT INTO audit (ts, username, action, connection_id, detail) VALUES (?, ?, ?, ?, ?)")
    .run(now(), username, action, connectionId, JSON.stringify(detail));
}

/** Elimina le voci del registro più vecchie del periodo di conservazione. */
export function pruneAudit(days: number): number {
  const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
  return db.prepare("DELETE FROM audit WHERE ts < ?").run(cutoff).changes;
}
