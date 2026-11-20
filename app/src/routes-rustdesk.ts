// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// API dei PC RustDesk: assegnazione alle cartelle dei clienti e registro delle aperture.

import { Router, type Request, type Response } from "express";
import { requireUser, type User } from "./auth.js";
import { audit, db, now } from "./db.js";
import { folderLevel, loadCatalog, sanitizeCredential, validName } from "./model.js";
import { getPeer, peerView, publicConfig, rustdeskEnabled, validPeerId, type PeerRow } from "./rustdesk.js";
import { syncStatus } from "./rustdesk-sync.js";

export const rustdeskRouter = Router();
rustdeskRouter.use("/rustdesk", requireUser);

function fail(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ code, message });
}

function user(req: Request): User {
  return req.user!;
}

function levelOn(u: User, folderId: string | null) {
  if (folderId === null) return u.admin ? "edit" : null;
  const catalog = loadCatalog();
  return catalog.folders.has(folderId) ? folderLevel(catalog, u, folderId) : null;
}

/** Un PC si gestisce con il permesso di modifica sulla sua cartella; quelli da assegnare solo dagli amministratori. */
function canManage(u: User, peer: PeerRow): boolean {
  return levelOn(u, peer.folder_id) === "edit";
}

rustdeskRouter.get("/rustdesk/config", (req, res) => {
  res.json({ ...publicConfig(), sync: user(req).admin ? syncStatus() : undefined });
});

// Aggiunta manuale di un PC che non compare sul server RustDesk
rustdeskRouter.post("/rustdesk/peers", (req, res) => {
  const u = user(req);
  if (!rustdeskEnabled()) return fail(res, 409, "rustdesk_disabled", "Il server RustDesk non è configurato in StartConnect.");
  const body = (req.body ?? {}) as Record<string, unknown>;
  const id = validPeerId(body.id);
  const folderId = typeof body.folderId === "string" ? body.folderId : null;
  const name = validName(body.name);
  if (!id) return fail(res, 400, "bad_request", "ID RustDesk non valido.");
  if (!folderId || levelOn(u, folderId) !== "edit") return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa cartella.");
  const existing = getPeer(id);
  if (existing && existing.folder_id && !existing.ignored) {
    return fail(res, 409, "exists", "Questo PC RustDesk è già assegnato a una cartella.");
  }
  const credential = sanitizeCredential(body.credential);
  if (existing) {
    db.prepare("UPDATE rustdesk_peers SET folder_id = ?, name = ?, credential = ?, ignored = 0, updated_at = ? WHERE id = ?")
      .run(folderId, name ?? "", credential ? JSON.stringify(credential) : null, now(), id);
  } else {
    db.prepare(`INSERT INTO rustdesk_peers (id, folder_id, name, credential, source, updated_at)
                VALUES (?, ?, ?, ?, 'manual', ?)`)
      .run(id, folderId, name ?? "", credential ? JSON.stringify(credential) : null, now());
  }
  audit(u.username, "rustdesk.add", null, { id, folderId, name });
  res.status(201).json(peerView(getPeer(id)!, "edit"));
});

// Assegnazione a una cartella, nome e credenziale StartCredentials
rustdeskRouter.put("/rustdesk/peers/:id", (req, res) => {
  const u = user(req);
  const peer = getPeer(String(req.params.id));
  if (!peer || !canManage(u, peer)) return fail(res, 404, "not_found", "PC RustDesk inesistente.");
  const body = (req.body ?? {}) as Record<string, unknown>;
  const folderId = "folderId" in body ? (typeof body.folderId === "string" ? body.folderId : null) : peer.folder_id;
  if (folderId !== peer.folder_id && levelOn(u, folderId) !== "edit") {
    return fail(res, 403, "edit_required", "Non hai il permesso di modifica sulla cartella di destinazione.");
  }
  const name = "name" in body ? (validName(body.name) ?? "") : peer.name;
  const credential = "credential" in body
    ? (sanitizeCredential(body.credential) ? JSON.stringify(sanitizeCredential(body.credential)) : null)
    : peer.credential;
  db.prepare("UPDATE rustdesk_peers SET folder_id = ?, name = ?, credential = ?, updated_at = ? WHERE id = ?")
    .run(folderId, name, credential, now(), peer.id);
  audit(u.username, folderId === peer.folder_id ? "rustdesk.update" : "rustdesk.assign", null,
    { id: peer.id, from: peer.folder_id, folderId, name });
  res.json(peerView(getPeer(peer.id)!, "edit"));
});

// Toglie il PC dalla cartella (torna da assegnare). Gli amministratori possono
// nascondere un PC da assegnare: ricompare solo se lo riporta un agente.
rustdeskRouter.delete("/rustdesk/peers/:id", (req, res) => {
  const u = user(req);
  const peer = getPeer(String(req.params.id));
  if (!peer || !canManage(u, peer)) return fail(res, 404, "not_found", "PC RustDesk inesistente.");
  if (peer.folder_id) {
    db.prepare("UPDATE rustdesk_peers SET folder_id = NULL, updated_at = ? WHERE id = ?").run(now(), peer.id);
    audit(u.username, "rustdesk.unassign", null, { id: peer.id, from: peer.folder_id, name: peer.name });
  } else {
    db.prepare("UPDATE rustdesk_peers SET ignored = 1, updated_at = ? WHERE id = ?").run(now(), peer.id);
    audit(u.username, "rustdesk.ignore", null, { id: peer.id, hostname: peer.hostname });
  }
  res.status(204).end();
});

// Registro dell'apertura: la sessione la avvia il client RustDesk del tecnico
rustdeskRouter.post("/rustdesk/peers/:id/open", (req, res) => {
  const u = user(req);
  const peer = getPeer(String(req.params.id));
  const level = peer ? levelOn(u, peer.folder_id) : null;
  if (!peer || !peer.folder_id || !level) return fail(res, 404, "not_found", "PC RustDesk inesistente.");
  const body = (req.body ?? {}) as Record<string, unknown>;
  audit(u.username, "rustdesk.open", null, {
    id: peer.id, name: peer.name || peer.hostname, folderId: peer.folder_id,
    credential: body.credential === "item" ? "startcredentials" : "manuale",
  });
  res.json({ id: peer.id, config: publicConfig() });
});
