// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import { db } from "./db.js";
import { isProtocol, PROTOCOLS, RULES, sanitizeOptions, type Protocol } from "./protocols.js";
import type { User } from "./auth.js";
import { hub } from "./agents.js";
import { fingerprint } from "./envelope.js";

// Riferimento a un elemento StartCredentials: identificativi, nessun segreto.
// "prompt" = le credenziali vengono chieste all'utente a ogni connessione.
export type CredentialRef =
  | { type: "item"; containerId: string; itemId: string; label: string }
  | { type: "prompt" };

export type Level = "use" | "edit";

export interface FolderDefaults {
  credential?: CredentialRef;
  options?: Partial<Record<Protocol, Record<string, string>>>;
}

export interface FolderRow {
  id: string;
  parent_id: string | null;
  name: string;
  position: number;
  defaults: string;
}

export interface ConnectionRow {
  id: string;
  folder_id: string;
  name: string;
  protocol: Protocol;
  hostname: string;
  port: number | null;
  credential: string | null;
  options: string;
  notes: string;
  position: number;
  device_id: string | null;
}

function parse<T>(json: string | null, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

const ID = /^[A-Za-z0-9_-]{1,128}$/;

export function sanitizeCredential(raw: unknown): CredentialRef | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  if (c.type === "prompt") return { type: "prompt" };
  if (c.type === "item" && typeof c.containerId === "string" && typeof c.itemId === "string"
      && ID.test(c.containerId) && ID.test(c.itemId)) {
    return { type: "item", containerId: c.containerId, itemId: c.itemId, label: String(c.label ?? "").slice(0, 200) };
  }
  return null;
}

export function sanitizeDefaults(raw: unknown): FolderDefaults {
  const out: FolderDefaults = {};
  if (!raw || typeof raw !== "object") return out;
  const d = raw as Record<string, unknown>;
  const credential = sanitizeCredential(d.credential);
  if (credential) out.credential = credential;
  if (d.options && typeof d.options === "object") {
    out.options = {};
    for (const p of PROTOCOLS) {
      const opts = sanitizeOptions(p, (d.options as Record<string, unknown>)[p]);
      if (Object.keys(opts).length) out.options[p] = opts;
    }
  }
  return out;
}

export interface Catalog {
  folders: Map<string, FolderRow>;
  connections: ConnectionRow[];
  acl: Map<string, { group: string; level: Level }[]>;
}

export function loadCatalog(): Catalog {
  const folders = new Map<string, FolderRow>();
  for (const f of db.prepare("SELECT id, parent_id, name, position, defaults FROM folders").all() as FolderRow[]) {
    folders.set(f.id, f);
  }
  const connections = db.prepare(
    "SELECT id, folder_id, name, protocol, hostname, port, credential, options, notes, position, device_id FROM connections",
  ).all() as ConnectionRow[];
  const acl = new Map<string, { group: string; level: Level }[]>();
  for (const a of db.prepare("SELECT folder_id, group_name, level FROM folder_acl").all() as
      { folder_id: string; group_name: string; level: Level }[]) {
    const list = acl.get(a.folder_id) ?? [];
    list.push({ group: a.group_name.toLowerCase(), level: a.level });
    acl.set(a.folder_id, list);
  }
  return { folders, connections, acl };
}

/** Catena dalla radice alla cartella indicata (inclusa). */
export function ancestry(catalog: Catalog, folderId: string): FolderRow[] {
  const chain: FolderRow[] = [];
  const seen = new Set<string>();
  let current = catalog.folders.get(folderId);
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    chain.unshift(current);
    current = current.parent_id ? catalog.folders.get(current.parent_id) : undefined;
  }
  return chain;
}

/** Permesso dell'utente su una cartella: il più alto concesso su di essa o su un antenato. */
export function folderLevel(catalog: Catalog, user: User, folderId: string): Level | null {
  if (user.admin) return "edit";
  const groups = new Set(user.groups);
  let level: Level | null = null;
  for (const f of ancestry(catalog, folderId)) {
    for (const entry of catalog.acl.get(f.id) ?? []) {
      if (!groups.has(entry.group)) continue;
      if (entry.level === "edit") return "edit";
      level = "use";
    }
  }
  return level;
}

export function effectiveSettings(catalog: Catalog, conn: ConnectionRow): {
  credential: CredentialRef;
  options: Record<string, string>;
  port: number;
} {
  let credential: CredentialRef | null = null;
  let options: Record<string, string> = {};
  for (const f of ancestry(catalog, conn.folder_id)) {
    const d = parse<FolderDefaults>(f.defaults, {});
    if (d.credential) credential = d.credential;
    options = { ...options, ...(d.options?.[conn.protocol] ?? {}) };
  }
  const own = parse<CredentialRef | null>(conn.credential, null);
  if (own) credential = own;
  options = { ...options, ...parse<Record<string, string>>(conn.options, {}) };
  return {
    credential: credential ?? { type: "prompt" },
    options: sanitizeOptions(conn.protocol, options),
    port: conn.port ?? RULES[conn.protocol].defaultPort,
  };
}

/** Vista del catalogo per un utente: solo ciò che può vedere. */
export function catalogFor(user: User) {
  const catalog = loadCatalog();
  const levels = new Map<string, Level | null>();
  for (const id of catalog.folders.keys()) levels.set(id, folderLevel(catalog, user, id));

  // Visibili: cartelle con permesso e i loro antenati (solo per navigare)
  const visible = new Set<string>();
  for (const [id, level] of levels) {
    if (!level) continue;
    for (const f of ancestry(catalog, id)) visible.add(f.id);
  }

  const folders = [...catalog.folders.values()]
    .filter((f) => visible.has(f.id))
    .map((f) => ({
      id: f.id,
      parentId: f.parent_id,
      name: f.name,
      position: f.position,
      permission: levels.get(f.id) ?? null,
      // Le impostazioni ereditate servono solo a chi modifica
      defaults: levels.get(f.id) === "edit" ? parse<FolderDefaults>(f.defaults, {}) : undefined,
    }));

  const connections = catalog.connections
    .filter((c) => levels.get(c.folder_id))
    .map((c) => {
      const level = levels.get(c.folder_id)!;
      const effective = effectiveSettings(catalog, c);
      return {
        id: c.id,
        folderId: c.folder_id,
        name: c.name,
        protocol: c.protocol,
        hostname: c.hostname,
        deviceId: c.device_id,
        port: effective.port,
        notes: c.notes,
        position: c.position,
        permission: level,
        credential: effective.credential,
        own: level === "edit"
          ? { port: c.port, credential: parse<CredentialRef | null>(c.credential, null), options: parse<Record<string, string>>(c.options, {}) }
          : undefined,
      };
    });

  const devices = (db.prepare(`SELECT id, folder_id, name, status, last_seen, agent_version, public_key,
                                       json_extract(inventory, '$.os.name') AS os, json_extract(inventory, '$.hostname') AS hostname
                                FROM devices`).all() as Record<string, string | null>[])
    .filter((d) => levels.get(d.folder_id!))
    .map((d) => ({
      id: d.id!,
      folderId: d.folder_id!,
      name: d.name!,
      status: d.status!,
      online: hub.isOnline(d.id!),
      lastSeen: d.last_seen,
      agentVersion: d.agent_version,
      os: d.os,
      hostname: d.hostname,
      fingerprint: fingerprint(d.public_key!),
      permission: levels.get(d.folder_id!)!,
    }));

  return { folders, connections, devices };
}

export function validName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim();
  return name.length >= 1 && name.length <= 200 ? name : null;
}

export function validHostname(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const host = value.trim();
  // Nome DNS, IPv4 o IPv6 (anche tra parentesi quadre)
  return /^(\[?[0-9A-Fa-f:.]+\]?|[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?)$/.test(host) && host.length <= 253
    ? host.replace(/^\[|\]$/g, "")
    : null;
}

export function validPort(value: unknown): number | null | undefined {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : undefined;
}

export { isProtocol };
