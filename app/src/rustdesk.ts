// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// PC raggiungibili con RustDesk.
//
// StartConnect non apre le sessioni RustDesk e non ne conosce le password: tiene
// l'elenco dei PC, li colloca nelle cartelle dei clienti (con i loro permessi) e
// registra chi apre cosa. La sessione la apre il client RustDesk del tecnico.
//
// L'elenco arriva da due fonti:
// - il server RustDesk (rustdesk-api), letto periodicamente con un utente dedicato;
// - l'agente StartConnect, che riporta l'ID RustDesk del proprio dispositivo:
//   in quel caso il PC finisce da solo nella cartella del dispositivo.

import { config } from "./config.js";
import { db, now } from "./db.js";
import { sanitizeCredential, type CredentialRef, type Level } from "./model.js";

/** Integrazione attiva: indirizzo del server ID e chiave pubblica sono configurati. */
export function rustdeskEnabled(): boolean {
  return Boolean(config.rustdesk.idServer && config.rustdesk.key);
}

/** Dati pubblici per configurare i client RustDesk (tecnici e agenti). */
export function publicConfig() {
  const r = config.rustdesk;
  return { enabled: rustdeskEnabled(), idServer: r.idServer, relayServer: r.relayServer, apiServer: r.apiServer, key: r.key };
}

/** ID RustDesk: numerico di 9-10 cifre per gli ID generati, o personalizzato (lettere, cifre, - e _). */
const PEER_ID = /^[A-Za-z0-9_-]{6,32}$/;

export function validPeerId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const id = value.replace(/\s+/g, "");
  return PEER_ID.test(id) ? id : null;
}

export interface PeerRow {
  id: string;
  folder_id: string | null;
  name: string;
  device_id: string | null;
  credential: string | null;
  hostname: string | null;
  os: string | null;
  username: string | null;
  version: string | null;
  last_online: string | null;
  last_ip: string | null;
  source: "server" | "agent" | "manual";
  ignored: number;
  synced_at: string | null;
}

export function getPeer(id: string): PeerRow | undefined {
  return db.prepare("SELECT * FROM rustdesk_peers WHERE id = ?").get(id) as PeerRow | undefined;
}

/** Collegato se il client RustDesk ha contattato il server negli ultimi minuti. */
export function isOnline(p: Pick<PeerRow, "last_online">, at = Date.now()): boolean {
  if (!p.last_online) return false;
  const t = Date.parse(p.last_online);
  return Number.isFinite(t) && at - t < config.rustdesk.onlineWindowMs;
}

function parseCredential(raw: string | null): CredentialRef | null {
  if (!raw) return null;
  try {
    return sanitizeCredential(JSON.parse(raw));
  } catch {
    return null;
  }
}

/** Vista per il client di un PC (nessun segreto: solo il riferimento a StartCredentials). */
export function peerView(p: PeerRow, permission: Level | null) {
  return {
    id: p.id,
    folderId: p.folder_id,
    name: p.name || p.hostname || p.id,
    deviceId: p.device_id,
    credential: parseCredential(p.credential),
    hostname: p.hostname,
    os: p.os,
    username: p.username,
    version: p.version,
    lastOnline: p.last_online,
    lastIp: permission === "edit" ? p.last_ip : null,
    online: isOnline(p),
    source: p.source,
    permission,
  };
}

export type PeerView = ReturnType<typeof peerView>;

/** PC nelle cartelle visibili all'utente; agli amministratori anche quelli da assegnare. */
export function peersFor(levels: Map<string, Level | null>, admin: boolean): { peers: PeerView[]; unassigned: PeerView[] } {
  const rows = db.prepare("SELECT * FROM rustdesk_peers WHERE ignored = 0").all() as PeerRow[];
  const peers: PeerView[] = [];
  const unassigned: PeerView[] = [];
  for (const p of rows) {
    if (p.folder_id) {
      const level = levels.get(p.folder_id);
      if (level) peers.push(peerView(p, level));
    } else if (admin) {
      unassigned.push(peerView(p, "edit"));
    }
  }
  return { peers, unassigned };
}

/** Dati descrittivi dal server RustDesk: non toccano cartella, nome e credenziale. */
export interface ServerPeer {
  id: string;
  hostname?: string | null;
  os?: string | null;
  username?: string | null;
  version?: string | null;
  lastOnline?: string | null;
  lastIp?: string | null;
}

export function upsertFromServer(peers: ServerPeer[], at = now()): number {
  const stmt = db.prepare(`
    INSERT INTO rustdesk_peers (id, hostname, os, username, version, last_online, last_ip, source, synced_at, updated_at)
    VALUES (@id, @hostname, @os, @username, @version, @lastOnline, @lastIp, 'server', @at, @at)
    ON CONFLICT(id) DO UPDATE SET
      hostname = COALESCE(excluded.hostname, hostname),
      os = COALESCE(excluded.os, os),
      username = COALESCE(excluded.username, username),
      version = COALESCE(excluded.version, version),
      last_online = COALESCE(excluded.last_online, last_online),
      last_ip = COALESCE(excluded.last_ip, last_ip),
      synced_at = excluded.synced_at`);
  let count = 0;
  db.transaction(() => {
    for (const p of peers) {
      const id = validPeerId(p.id);
      if (!id) continue;
      const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
      stmt.run({
        id,
        hostname: text(p.hostname, 200),
        os: text(p.os, 200),
        username: text(p.username, 200),
        version: text(p.version, 40),
        lastOnline: p.lastOnline && Number.isFinite(Date.parse(p.lastOnline)) ? new Date(p.lastOnline).toISOString() : null,
        lastIp: text(p.lastIp, 64),
        at,
      });
      count++;
    }
  })();
  return count;
}

/**
 * L'agente ha riportato l'ID RustDesk del suo dispositivo: il PC viene collegato al
 * dispositivo e, se non è ancora assegnato, messo nella sua cartella con il suo nome.
 * Un PC già assegnato altrove non viene spostato (lo decide un tecnico).
 */
export function linkFromAgent(deviceId: string, rustdesk: unknown): void {
  if (!rustdesk || typeof rustdesk !== "object") return;
  const r = rustdesk as Record<string, unknown>;
  const id = validPeerId(r.id);
  if (!id) return;
  const device = db.prepare("SELECT id, folder_id, name, status, rustdesk_credential FROM devices WHERE id = ?").get(deviceId) as
    { id: string; folder_id: string; name: string; status: string; rustdesk_credential: string | null } | undefined;
  if (!device || device.status !== "active") return;
  const version = typeof r.version === "string" ? r.version.slice(0, 40) : null;
  const existing = getPeer(id);
  if (!existing) {
    db.prepare(`INSERT INTO rustdesk_peers (id, folder_id, name, device_id, credential, version, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'agent', ?)`)
      .run(id, device.folder_id, device.name, device.id, device.rustdesk_credential, version, now());
    return;
  }
  if (existing.device_id === device.id && existing.folder_id && existing.credential) return;
  db.prepare(`UPDATE rustdesk_peers SET device_id = ?, version = COALESCE(?, version),
                folder_id = COALESCE(folder_id, ?), name = CASE WHEN name = '' THEN ? ELSE name END,
                credential = COALESCE(credential, ?), ignored = 0, updated_at = ? WHERE id = ?`)
    .run(device.id, version, device.folder_id, device.name, device.rustdesk_credential, now(), id);
}
