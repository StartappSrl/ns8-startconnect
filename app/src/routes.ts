// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import { randomUUID } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { requireAdmin, requireUser, type User } from "./auth.js";
import { audit, db, now } from "./db.js";
import {
  ancestry, catalogFor, effectiveSettings, folderLevel, isProtocol, loadCatalog, sanitizeCredential as sanitizeRef,
  sanitizeDefaults, validHostname, validName, validPort, type ConnectionRow, type Level,
} from "./model.js";
import { sanitizeOptions } from "./protocols.js";
import { createPending, guacSettings, sanitizeCredential } from "./sessions.js";
import { config } from "./config.js";
import { hub } from "./agents.js";
import { isEnvelope, type Envelope } from "./envelope.js";
import { authorizeCommand } from "./trust.js";
import { probeRdp, probeSsh } from "./probe.js";

export const VERSION = "0.1.0";
export const router = Router();

function fail(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ code, message });
}

function user(req: Request): User {
  return req.user!;
}

/** Permesso di modifica su una cartella; per la radice serve un amministratore. */
function canEdit(u: User, folderId: string | null): boolean {
  if (folderId === null) return u.admin;
  const catalog = loadCatalog();
  return catalog.folders.has(folderId) && folderLevel(catalog, u, folderId) === "edit";
}

router.get("/info", (_req, res) => {
  res.json({ name: "StartConnect", version: VERSION, host: config.publicHost });
});

router.use(requireUser);

router.get("/catalog", (req, res) => {
  res.json({ user: user(req), ...catalogFor(user(req)) });
});

// ---- Cartelle ----

router.post("/folders", (req, res) => {
  const u = user(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const parentId = typeof body.parentId === "string" ? body.parentId : null;
  const name = validName(body.name);
  if (!name) return fail(res, 400, "bad_request", "Il nome della cartella è obbligatorio.");
  if (!canEdit(u, parentId)) return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa cartella.");
  const id = randomUUID();
  db.prepare("INSERT INTO folders (id, parent_id, name, position, defaults, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(id, parentId, name, Number(body.position) || 0, JSON.stringify(sanitizeDefaults(body.defaults)), now());
  audit(u.username, "folder.create", null, { id, name, parentId });
  res.status(201).json({ id });
});

router.patch("/folders/:id", (req, res) => {
  const u = user(req);
  const catalog = loadCatalog();
  const folder = catalog.folders.get(req.params.id);
  if (!folder) return fail(res, 404, "not_found", "Cartella inesistente.");
  if (folderLevel(catalog, u, folder.id) !== "edit") return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa cartella.");
  const body = (req.body ?? {}) as Record<string, unknown>;

  let parentId = folder.parent_id;
  if ("parentId" in body) {
    parentId = typeof body.parentId === "string" ? body.parentId : null;
    if (!canEdit(u, parentId)) return fail(res, 403, "edit_required", "Non hai il permesso di modifica sulla cartella di destinazione.");
    if (parentId && ancestry(catalog, parentId).some((f) => f.id === folder.id)) {
      return fail(res, 400, "bad_request", "Una cartella non può essere spostata dentro se stessa.");
    }
  }
  const name = "name" in body ? validName(body.name) : folder.name;
  if (!name) return fail(res, 400, "bad_request", "Il nome della cartella è obbligatorio.");
  const defaults = "defaults" in body ? JSON.stringify(sanitizeDefaults(body.defaults)) : folder.defaults;
  const position = "position" in body ? Number(body.position) || 0 : folder.position;

  db.prepare("UPDATE folders SET parent_id = ?, name = ?, defaults = ?, position = ?, updated_at = ? WHERE id = ?")
    .run(parentId, name, defaults, position, now(), folder.id);
  audit(u.username, "folder.update", null, { id: folder.id, name });
  res.json({ id: folder.id });
});

router.delete("/folders/:id", (req, res) => {
  const u = user(req);
  const catalog = loadCatalog();
  const folder = catalog.folders.get(req.params.id);
  if (!folder) return fail(res, 404, "not_found", "Cartella inesistente.");
  if (!canEdit(u, folder.parent_id)) return fail(res, 403, "edit_required", "Non hai il permesso di eliminare questa cartella.");
  db.prepare("DELETE FROM folders WHERE id = ?").run(folder.id);
  audit(u.username, "folder.delete", null, { id: folder.id, name: folder.name });
  res.status(204).end();
});

router.get("/folders/:id/acl", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT group_name AS \"group\", level FROM folder_acl WHERE folder_id = ? ORDER BY group_name")
    .all(req.params.id);
  res.json({ entries: rows });
});

router.put("/folders/:id/acl", requireAdmin, (req, res) => {
  const u = user(req);
  if (!loadCatalog().folders.has(req.params.id as string)) return fail(res, 404, "not_found", "Cartella inesistente.");
  const entries = Array.isArray((req.body as { entries?: unknown })?.entries) ? (req.body as { entries: unknown[] }).entries : null;
  if (!entries) return fail(res, 400, "bad_request", "Elenco permessi non valido.");
  const clean: { group: string; level: Level }[] = [];
  for (const e of entries) {
    const entry = e as Record<string, unknown>;
    const group = typeof entry.group === "string" ? entry.group.trim().toLowerCase() : "";
    if (!group || group.length > 128 || (entry.level !== "use" && entry.level !== "edit")) {
      return fail(res, 400, "bad_request", "Ogni permesso richiede un gruppo e il livello use o edit.");
    }
    clean.push({ group, level: entry.level });
  }
  db.transaction(() => {
    db.prepare("DELETE FROM folder_acl WHERE folder_id = ?").run(req.params.id);
    const insert = db.prepare("INSERT OR REPLACE INTO folder_acl (folder_id, group_name, level) VALUES (?, ?, ?)");
    for (const e of clean) insert.run(req.params.id, e.group, e.level);
  })();
  audit(u.username, "folder.acl", null, { id: req.params.id, entries: clean });
  res.json({ entries: clean });
});

// ---- Connessioni ----

interface ConnectionInput {
  folderId: string;
  name: string;
  protocol: ConnectionRow["protocol"];
  hostname: string;
  port: number | null;
  credential: string | null;
  options: string;
  notes: string;
  position: number;
  deviceId: string | null;
}

function readConnection(body: Record<string, unknown>, current?: ConnectionRow): ConnectionInput | string {
  const protocol = "protocol" in body ? body.protocol : current?.protocol;
  if (!isProtocol(protocol)) return "Protocollo non supportato.";
  const folderId = "folderId" in body ? body.folderId : current?.folder_id;
  if (typeof folderId !== "string") return "La cartella è obbligatoria.";
  const name = "name" in body ? validName(body.name) : current?.name;
  if (!name) return "Il nome della connessione è obbligatorio.";
  const deviceId = "deviceId" in body ? (typeof body.deviceId === "string" && body.deviceId ? body.deviceId : null) : current?.device_id ?? null;
  // Tramite agente la destinazione è sempre il dispositivo stesso (127.0.0.1 lato agente)
  const hostname = deviceId ? "127.0.0.1" : "hostname" in body ? validHostname(body.hostname) : current?.hostname;
  if (!hostname) return "Indirizzo del server non valido.";
  const port = "port" in body ? validPort(body.port) : current?.port ?? null;
  if (port === undefined) return "Porta non valida (1-65535).";
  const credential = "credential" in body
    ? (body.credential === null ? null : JSON.stringify(sanitizeRef(body.credential)))
    : current?.credential ?? null;
  const options = "options" in body
    ? JSON.stringify(sanitizeOptions(protocol, body.options))
    : current?.options ?? "{}";
  const notes = "notes" in body ? String(body.notes ?? "").slice(0, 4000) : current?.notes ?? "";
  const position = "position" in body ? Number(body.position) || 0 : current?.position ?? 0;
  return { folderId, name, protocol, hostname, port, credential: credential === "null" ? null : credential, options, notes, position, deviceId };
}

router.post("/connections", (req, res) => {
  const u = user(req);
  const input = readConnection((req.body ?? {}) as Record<string, unknown>);
  if (typeof input === "string") return fail(res, 400, "bad_request", input);
  if (!canEdit(u, input.folderId)) return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa cartella.");
  if (!deviceAllowed(u, input.deviceId)) return fail(res, 403, "edit_required", "Dispositivo inesistente o non modificabile.");
  const id = randomUUID();
  db.prepare(`INSERT INTO connections (id, folder_id, name, protocol, hostname, port, credential, options, notes, position, device_id, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, input.folderId, input.name, input.protocol, input.hostname, input.port, input.credential, input.options, input.notes, input.position, input.deviceId, now());
  audit(u.username, "connection.create", id, { name: input.name, hostname: input.hostname, protocol: input.protocol });
  res.status(201).json({ id });
});

function findConnection(id: string): ConnectionRow | undefined {
  return db.prepare("SELECT id, folder_id, name, protocol, hostname, port, credential, options, notes, position, device_id FROM connections WHERE id = ?")
    .get(id) as ConnectionRow | undefined;
}

router.patch("/connections/:id", (req, res) => {
  const u = user(req);
  const current = findConnection(req.params.id);
  if (!current) return fail(res, 404, "not_found", "Connessione inesistente.");
  if (!canEdit(u, current.folder_id)) return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa connessione.");
  const input = readConnection((req.body ?? {}) as Record<string, unknown>, current);
  if (typeof input === "string") return fail(res, 400, "bad_request", input);
  if (input.folderId !== current.folder_id && !canEdit(u, input.folderId)) {
    return fail(res, 403, "edit_required", "Non hai il permesso di modifica sulla cartella di destinazione.");
  }
  if (input.deviceId !== current.device_id && !deviceAllowed(u, input.deviceId)) {
    return fail(res, 403, "edit_required", "Dispositivo inesistente o non modificabile.");
  }
  db.prepare(`UPDATE connections SET folder_id = ?, name = ?, protocol = ?, hostname = ?, port = ?, credential = ?, options = ?,
              notes = ?, position = ?, device_id = ?, updated_at = ? WHERE id = ?`)
    .run(input.folderId, input.name, input.protocol, input.hostname, input.port, input.credential, input.options, input.notes, input.position, input.deviceId, now(), current.id);
  audit(u.username, "connection.update", current.id, {
    name: input.name, hostname: input.hostname,
    // Cambi di destinazione registrati con il valore precedente
    previous: input.hostname !== current.hostname || input.port !== current.port || input.deviceId !== current.device_id
      ? `${current.device_id ? `agente:${current.device_id}` : current.hostname}:${current.port ?? ""}` : undefined,
  });
  res.json({ id: current.id });
});

router.delete("/connections/:id", (req, res) => {
  const u = user(req);
  const current = findConnection(req.params.id);
  if (!current) return fail(res, 404, "not_found", "Connessione inesistente.");
  if (!canEdit(u, current.folder_id)) return fail(res, 403, "edit_required", "Non hai il permesso di eliminare questa connessione.");
  db.prepare("DELETE FROM connections WHERE id = ?").run(current.id);
  audit(u.username, "connection.delete", current.id, { name: current.name, hostname: current.hostname });
  res.status(204).end();
});

function deviceAllowed(u: User, deviceId: string | null): boolean {
  if (!deviceId) return true;
  const d = db.prepare("SELECT folder_id FROM devices WHERE id = ?").get(deviceId) as { folder_id: string } | undefined;
  return !!d && canEdit(u, d.folder_id);
}

// ---- Identità dei server ----

const probeLimit = new Map<string, { count: number; reset: number }>();

router.post("/probe", async (req, res) => {
  const u = user(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const folderId = typeof body.folderId === "string" ? body.folderId : "";
  if (!canEdit(u, folderId)) return fail(res, 403, "edit_required", "Serve il permesso di modifica sulla cartella.");
  const hostname = validHostname(body.hostname);
  const port = validPort(body.port);
  if (!hostname || hostname.startsWith("-") || !port) return fail(res, 400, "bad_request", "Indirizzo o porta non validi.");
  const t = Date.now();
  const lim = probeLimit.get(u.username);
  if (lim && lim.reset > t && lim.count >= 20) return fail(res, 429, "rate_limited", "Troppe richieste: riprova tra qualche minuto.");
  probeLimit.set(u.username, lim && lim.reset > t ? { ...lim, count: lim.count + 1 } : { count: 1, reset: t + 5 * 60_000 });
  try {
    const result = body.protocol === "rdp" ? await probeRdp(hostname, port)
      : body.protocol === "ssh" ? await probeSsh(hostname, port)
      : null;
    if (!result) return fail(res, 400, "bad_request", "Rilevamento disponibile per RDP e SSH.");
    audit(u.username, "server.probe", null, { hostname, port, protocol: body.protocol });
    res.json(result);
  } catch (e) {
    fail(res, 502, "probe_failed", (e as Error).message);
  }
});

// ---- Sessioni ----

router.post("/sessions", async (req, res) => {
  const u = user(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const conn = typeof body.connectionId === "string" ? findConnection(body.connectionId) : undefined;
  if (!conn) return fail(res, 404, "not_found", "Connessione inesistente.");
  const catalog = loadCatalog();
  if (!folderLevel(catalog, u, conn.folder_id)) return fail(res, 403, "use_required", "Non hai accesso a questa connessione.");

  const effective = effectiveSettings(catalog, conn);
  const credential = sanitizeCredential(body.credential);
  const source = effective.credential.type === "item"
    ? `startcredentials:${effective.credential.containerId}/${effective.credential.itemId}`
    : "prompt";

  // Connessione tramite agente: serve un comando firmato sul PC del tecnico
  let target = { hostname: conn.hostname, port: effective.port };
  let via: string | undefined;
  if (conn.device_id) {
    const device = db.prepare("SELECT status FROM devices WHERE id = ?").get(conn.device_id) as { status: string } | undefined;
    if (device?.status !== "active") return fail(res, 409, "device_inactive", "Il dispositivo non è approvato o è stato revocato.");
    if (!hub.isOnline(conn.device_id)) return fail(res, 409, "device_offline", "L'agente del dispositivo non è collegato.");
    const auth = authorizeCommand(body.command, body.cert, { device: conn.device_id, port: effective.port, user: u.username });
    if (!auth.ok) return fail(res, 403, "command_rejected", auth.reason);
    const port = await hub.localTunnel(conn.device_id, body.command as Envelope, isEnvelope(body.cert) ? body.cert : null, u.username);
    target = { hostname: "127.0.0.1", port };
    via = conn.device_id;
  }

  const token = createPending({
    username: u.username,
    connectionId: conn.id,
    connectionName: conn.name,
    protocol: conn.protocol,
    hostname: via ? `agente:${via}` : conn.hostname,
    port: effective.port,
    credentialSource: source,
    guac: guacSettings(conn.protocol, target.hostname, target.port, effective.options, credential),
  });
  audit(u.username, "session.request", conn.id, { name: conn.name, credential: source, device: via });
  res.json({ token, tunnelPath: "/tunnel", expiresIn: config.pendingTtlMs / 1000 });
});

/** Esportazione CSV del registro (amministratori), con intervallo di date facoltativo. */
router.get("/audit/export", requireAdmin, (req, res) => {
  const from = typeof req.query.from === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.query.from) ? req.query.from : "0000";
  const to = typeof req.query.to === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.query.to) ? `${req.query.to}T99` : "9999";
  const rows = db.prepare("SELECT id, ts, username, action, connection_id, detail FROM audit WHERE ts >= ? AND ts <= ? ORDER BY id")
    .all(from, to) as { id: number; ts: string; username: string; action: string; connection_id: string | null; detail: string }[];
  // Campi tra virgolette; i valori che iniziano con = + - @ vengono neutralizzati (formule nei fogli di calcolo)
  const cell = (v: unknown) => {
    let text = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const lines = ["id;data;utente;azione;connessione;dettagli", ...rows.map((r) => [r.id, r.ts, r.username, r.action, r.connection_id, r.detail].map(cell).join(";"))];
  audit(user(req).username, "audit.export", null, { rows: rows.length, from, to: req.query.to ?? "" });
  res.set("content-type", "text/csv; charset=utf-8").send("\ufeff" + lines.join("\r\n"));
});

router.get("/audit", requireAdmin, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
  const before = Number(req.query.before) || Number.MAX_SAFE_INTEGER;
  const rows = (db.prepare("SELECT id, ts, username, action, connection_id AS connectionId, detail FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?")
    .all(before, limit) as { detail: string }[]).map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
  res.json({ entries: rows });
});
