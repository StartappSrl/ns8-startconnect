// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { hub } from "./agents.js";
import { loginAllowed, requireAdmin, requireUser, type User } from "./auth.js";
import { audit, db, now } from "./db.js";
import { fingerprint, open, payloadHash, publicKeyFromRaw, verifyTrustChain, type Envelope } from "./envelope.js";
import { serverIdentity, serverSeal } from "./identity.js";
import { folderLevel, loadCatalog, sanitizeCredential, validName } from "./model.js";
import { linkFromAgent } from "./rustdesk.js";
import { currentTrust, MAX_CERT_DAYS, trustChain, type CertDoc, type TrustDocFull } from "./trust.js";

export const agentRouter = Router();

function fail(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ code, message });
}

const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const user = (req: Request): User => req.user!;

function canEdit(u: User, folderId: string): boolean {
  const catalog = loadCatalog();
  return catalog.folders.has(folderId) && folderLevel(catalog, u, folderId) === "edit";
}

interface DeviceRow {
  id: string;
  folder_id: string;
  name: string;
  public_key: string;
  status: string;
}

function findDevice(id: string): DeviceRow | undefined {
  return db.prepare("SELECT id, folder_id, name, public_key, status FROM devices WHERE id = ?").get(id) as DeviceRow | undefined;
}

// ---------- Endpoint usati dall'agente (senza sessione utente) ----------

agentRouter.get("/agent/identity", (_req, res) => {
  const key = serverIdentity().publicKey;
  res.json({ publicKey: key, fingerprint: fingerprint(key) });
});

agentRouter.post("/agent/enroll", (req, res) => {
  if (!loginAllowed(`enroll|${req.ip}`)) return fail(res, 429, "rate_limited", "Troppi tentativi.");
  const body = (req.body ?? {}) as Record<string, unknown>;
  const secret = typeof body.secret === "string" ? body.secret : "";
  const publicKey = typeof body.publicKey === "string" ? body.publicKey : "";
  const hostname = validName(body.hostname) ?? "dispositivo";
  if (!secret || !publicKeyFromRaw(publicKey)) return fail(res, 400, "bad_request", "Richiesta non valida.");

  const result = db.transaction(() => {
    const e = db.prepare("SELECT id, folder_id, created_by, expires_at, uses_left, rustdesk_credential FROM enrollments WHERE secret_hash = ?")
      .get(sha(secret)) as { id: string; folder_id: string; created_by: string; expires_at: number; uses_left: number; rustdesk_credential: string | null } | undefined;
    if (!e || e.uses_left < 1 || e.expires_at < Date.now()) return null;
    if (db.prepare("SELECT 1 FROM devices WHERE public_key = ?").get(publicKey)) return null;
    db.prepare("UPDATE enrollments SET uses_left = uses_left - 1 WHERE id = ?").run(e.id);
    const id = randomUUID();
    db.prepare(`INSERT INTO devices (id, folder_id, name, public_key, status, enrolled_at, rustdesk_credential) VALUES (?, ?, ?, ?, 'pending', ?, ?)`)
      .run(id, e.folder_id, hostname, publicKey, now(), e.rustdesk_credential);
    return { id, enrollment: e };
  })();

  if (!result) return fail(res, 403, "enrollment_invalid", "Codice di installazione non valido, scaduto o già usato.");
  audit("agent", "device.enroll", null, { device: result.id, name: hostname, fingerprint: fingerprint(publicKey), ip: req.ip, code: result.enrollment.id });
  res.json({
    deviceId: result.id,
    env: serverSeal({ t: "enroll-server", device: result.id, agentKey: publicKey, iat: Math.floor(Date.now() / 1000) }),
    chain: trustChain(),
  });
});

// ---------- Endpoint per i tecnici ----------

// Da qui in poi serve una sessione utente (applicata per rotta: questo router
// non deve bloccare le richieste destinate ad altri router)

agentRouter.get("/security", requireUser, (req, res) => {
  const u = user(req);
  const rows = db.prepare(`SELECT id, username, public_key AS publicKey, label, created_at AS createdAt, cert, cert_exp AS certExp
                           FROM user_keys ${u.admin ? "" : "WHERE username = ?"} ORDER BY username, created_at`)
    .all(...(u.admin ? [] : [u.username])) as { publicKey: string; cert: string | null }[];
  res.json({
    serverKey: serverIdentity().publicKey,
    chain: trustChain(),
    keys: rows.map((r) => ({ ...r, fingerprint: fingerprint(r.publicKey), cert: r.cert ? JSON.parse(r.cert) as Envelope : null })),
  });
});

/** Registra la chiave del PC del tecnico (la privata non lascia mai il PC). */
agentRouter.post("/me/keys", requireUser, (req, res) => {
  const u = user(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const key = typeof body.publicKey === "string" ? body.publicKey : "";
  if (!publicKeyFromRaw(key)) return fail(res, 400, "bad_request", "Chiave non valida.");
  const existing = db.prepare("SELECT username FROM user_keys WHERE public_key = ?").get(key) as { username: string } | undefined;
  if (existing && existing.username !== u.username) return fail(res, 409, "key_in_use", "Chiave già registrata da un altro utente.");
  if (!existing) {
    db.prepare("INSERT INTO user_keys (id, username, public_key, label, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(randomUUID(), u.username, key, String(body.label ?? "").slice(0, 200), now());
    audit(u.username, "key.register", null, { fingerprint: fingerprint(key) });
  }
  res.json({ fingerprint: fingerprint(key) });
});

/** Nuova versione dell'elenco degli amministratori, firmata sul PC di un amministratore. */
agentRouter.put("/trust", requireUser, requireAdmin, (req, res) => {
  const u = user(req);
  const env = (req.body as { env?: unknown })?.env as Envelope;
  const doc = open<TrustDocFull>(env, "trust");
  if (!doc) return fail(res, 400, "bad_signature", "Documento non firmato correttamente.");
  const chain = trustChain();
  const verified = verifyTrustChain([...chain, env]);
  if (!verified || verified.doc.version !== chain.length + 1) {
    return fail(res, 400, "bad_chain", "La nuova versione deve essere firmata da un amministratore della versione attuale.");
  }
  if (!doc.admins.every((a) => typeof a.name === "string" && publicKeyFromRaw(a.key) && (a.role === undefined || a.role === "recovery"))
      || !doc.admins.some((a) => a.role !== "recovery")) {
    return fail(res, 400, "bad_request", "Elenco non valido.");
  }
  db.prepare("INSERT INTO trust (version, envelope, hash, created_by, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(doc.version, JSON.stringify(env), payloadHash(env), u.username, now());
  audit(u.username, "trust.update", null, {
    version: doc.version, signer: fingerprint(env.k),
    admins: doc.admins.map((a) => `${a.name}${a.role ? ` (${a.role})` : ""} ${fingerprint(a.key)}`), revoked: doc.revokedKeys?.length ?? 0,
  });
  hub.pushTrustAll();
  res.json({ version: doc.version });
});

/** Certificato per la chiave di un tecnico, firmato sul PC di un amministratore. */
agentRouter.put("/keys/:id/cert", requireUser, requireAdmin, (req, res) => {
  const u = user(req);
  const row = db.prepare("SELECT username, public_key FROM user_keys WHERE id = ?").get(req.params.id) as { username: string; public_key: string } | undefined;
  if (!row) return fail(res, 404, "not_found", "Chiave inesistente.");
  const env = (req.body as { env?: unknown })?.env as Envelope;
  const cert = open<CertDoc>(env, "cert");
  const trust = currentTrust();
  if (!cert || !trust || !trust.doc.admins.some((a) => a.key === env.k && a.role !== "recovery")) {
    return fail(res, 400, "bad_signature", "Certificato non firmato da un amministratore fidato.");
  }
  if (cert.key !== row.public_key || cert.sub !== row.username || cert.role !== "tech" || cert.exp - cert.iat > MAX_CERT_DAYS * 86400) {
    return fail(res, 400, "bad_request", "Il certificato non corrisponde alla chiave.");
  }
  db.prepare("UPDATE user_keys SET cert = ?, cert_exp = ? WHERE id = ?").run(JSON.stringify(env), cert.exp, req.params.id);
  audit(u.username, "key.certify", null, { user: row.username, fingerprint: fingerprint(row.public_key), exp: cert.exp });
  res.json({ ok: true });
});

agentRouter.delete("/keys/:id", requireUser, requireAdmin, (req, res) => {
  const row = db.prepare("SELECT username, public_key FROM user_keys WHERE id = ?").get(req.params.id) as { username: string; public_key: string } | undefined;
  if (!row) return fail(res, 404, "not_found", "Chiave inesistente.");
  db.prepare("DELETE FROM user_keys WHERE id = ?").run(req.params.id);
  audit(user(req).username, "key.delete", null, { user: row.username, fingerprint: fingerprint(row.public_key) });
  res.status(204).end();
});

// ---------- Installazione e gestione dei dispositivi ----------

agentRouter.post("/enrollments", requireUser, (req, res) => {
  const u = user(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const folderId = typeof body.folderId === "string" ? body.folderId : "";
  if (!canEdit(u, folderId)) return fail(res, 403, "edit_required", "Non hai il permesso di modifica su questa cartella.");
  if (!currentTrust()) return fail(res, 409, "no_trust", "Prima un amministratore deve creare l'elenco degli amministratori fidati.");
  const hours = Math.min(Math.max(Number(body.hours) || 24, 1), 168);
  const uses = Math.min(Math.max(Number(body.uses) || 1, 1), 50);
  const secret = randomBytes(32).toString("base64url");
  const id = randomUUID();
  // Voce StartCredentials con la password RustDesk del pacchetto (solo identificativi)
  const rustdeskCredential = sanitizeCredential(body.rustdeskCredential);
  db.prepare(`INSERT INTO enrollments (id, folder_id, secret_hash, created_by, created_at, expires_at, uses_left, rustdesk_credential)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, folderId, sha(secret), u.username, now(), Date.now() + hours * 3600_000, uses,
      rustdeskCredential?.type === "item" ? JSON.stringify(rustdeskCredential) : null);
  audit(u.username, "enrollment.create", null, { id, folderId, hours, uses, rustdesk: Boolean(rustdeskCredential) });
  // Il segreto viene mostrato una sola volta; nel database resta solo l'hash
  res.status(201).json({ id, secret, serverKey: serverIdentity().publicKey, expiresAt: Date.now() + hours * 3600_000 });
});

agentRouter.get("/devices/:id", requireUser, (req, res) => {
  const u = user(req);
  const d = db.prepare("SELECT * FROM devices WHERE id = ?").get(req.params.id) as Record<string, string> | undefined;
  const catalog = loadCatalog();
  if (!d || !folderLevel(catalog, u, d.folder_id!)) return fail(res, 404, "not_found", "Dispositivo inesistente.");
  res.json({
    id: d.id, folderId: d.folder_id, name: d.name, status: d.status, online: hub.isOnline(d.id!),
    fingerprint: fingerprint(d.public_key!), enrolledAt: d.enrolled_at, approvedBy: d.approved_by, approvedAt: d.approved_at,
    lastSeen: d.last_seen, agentVersion: d.agent_version, ports: JSON.parse(d.ports!), trustVersion: d.trust_version,
    inventory: JSON.parse(d.inventory!),
  });
});

agentRouter.post("/devices/:id/approve", requireUser, (req, res) => {
  const u = user(req);
  const d = findDevice(req.params.id as string);
  if (!d || !canEdit(u, d.folder_id)) return fail(res, 404, "not_found", "Dispositivo inesistente.");
  if (d.status !== "pending") return fail(res, 409, "bad_state", "Il dispositivo non è in attesa di approvazione.");
  // L'impronta confermata dal tecnico deve coincidere con quella mostrata dall'agente
  if ((req.body as { fingerprint?: unknown })?.fingerprint !== fingerprint(d.public_key)) {
    return fail(res, 400, "fingerprint_mismatch", "L'impronta non corrisponde: non approvare questo dispositivo.");
  }
  db.prepare("UPDATE devices SET status = 'active', approved_by = ?, approved_at = ? WHERE id = ?").run(u.username, now(), d.id);
  audit(u.username, "device.approve", null, { device: d.id, name: d.name });
  // Il PC RustDesk installato dall'agente si collega solo a dispositivo approvato
  const inventory = db.prepare("SELECT json_extract(inventory, '$.rustdesk') AS r FROM devices WHERE id = ?").get(d.id) as { r: string | null };
  if (inventory?.r) {
    try {
      linkFromAgent(d.id, JSON.parse(inventory.r));
    } catch {
      // inventario non valido: il collegamento avverrà al prossimo invio
    }
  }
  res.json({ ok: true });
});

agentRouter.patch("/devices/:id", requireUser, (req, res) => {
  const u = user(req);
  const d = findDevice(req.params.id as string);
  if (!d || !canEdit(u, d.folder_id)) return fail(res, 404, "not_found", "Dispositivo inesistente.");
  const body = (req.body ?? {}) as Record<string, unknown>;
  const name = "name" in body ? validName(body.name) : d.name;
  const folderId = typeof body.folderId === "string" ? body.folderId : d.folder_id;
  if (!name) return fail(res, 400, "bad_request", "Nome non valido.");
  if (folderId !== d.folder_id && !canEdit(u, folderId)) return fail(res, 403, "edit_required", "Non hai il permesso sulla cartella di destinazione.");
  db.prepare("UPDATE devices SET name = ?, folder_id = ? WHERE id = ?").run(name, folderId, d.id);
  audit(u.username, "device.update", null, { device: d.id, name });
  res.json({ ok: true });
});

agentRouter.post("/devices/:id/revoke", requireUser, (req, res) => {
  const u = user(req);
  const d = findDevice(req.params.id as string);
  if (!d || !canEdit(u, d.folder_id)) return fail(res, 404, "not_found", "Dispositivo inesistente.");
  db.prepare("UPDATE devices SET status = 'revoked' WHERE id = ?").run(d.id);
  hub.disconnect(d.id);
  audit(u.username, "device.revoke", null, { device: d.id, name: d.name });
  res.json({ ok: true });
});

agentRouter.delete("/devices/:id", requireUser, (req, res) => {
  const u = user(req);
  const d = findDevice(req.params.id as string);
  if (!d || !canEdit(u, d.folder_id)) return fail(res, 404, "not_found", "Dispositivo inesistente.");
  db.prepare("DELETE FROM devices WHERE id = ?").run(d.id);
  hub.disconnect(d.id);
  audit(u.username, "device.delete", null, { device: d.id, name: d.name });
  res.status(204).end();
});
