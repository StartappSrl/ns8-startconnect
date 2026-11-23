// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Aggiornamenti del client desktop. Come per l'agente, il manifesto (versione,
// piattaforma, nome del file, SHA-256, dimensione) è firmato sul PC di un
// amministratore fidato: il server conserva installatore e manifesto e li
// distribuisce, ma ogni client verifica firma, elenco fidato e impronta prima
// di installare. Si conserva solo l'ultima versione per piattaforma.

import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import express, { Router } from "express";
import { requireAdmin, requireUser } from "./auth.js";
import { config } from "./config.js";
import { audit } from "./db.js";
import { fingerprint, isEnvelope, open, type Envelope } from "./envelope.js";
import { currentTrust } from "./trust.js";

/** win-x64: installatore NSIS; linux-x64: AppImage. */
export const CLIENT_PLATFORMS = ["win-x64", "linux-x64"] as const;
const MAX_SIZE = 400 * 1024 * 1024;

export interface ClientUpdateManifest {
  t: "client-update";
  version: string;
  platform: string;
  name: string;
  sha256: string;
  size: number;
  iat: number;
}

const dir = join(config.dataDir, "client-updates");
mkdirSync(dir, { recursive: true });

const isPlatform = (p: string) => (CLIENT_PLATFORMS as readonly string[]).includes(p);
const manifestPath = (p: string) => join(dir, `${p}.json`);
const binaryPath = (p: string) => join(dir, `${p}.bin`);

function readManifest(platform: string): Envelope | null {
  try {
    return JSON.parse(readFileSync(manifestPath(platform), "utf8")) as Envelope;
  } catch {
    return null;
  }
}

export const clientUpdatesRouter = Router();

// Elenco con i manifesti firmati: è il client a verificarli
clientUpdatesRouter.get("/client-updates", requireUser, (_req, res) => {
  res.json({
    updates: CLIENT_PLATFORMS.map((p) => {
      const env = readManifest(p);
      const m = env && open<ClientUpdateManifest>(env, "client-update");
      return m ? { platform: p, version: m.version, size: m.size, signer: fingerprint(env.k), published: new Date(m.iat * 1000).toISOString(), manifest: env } : null;
    }).filter(Boolean),
  });
});

clientUpdatesRouter.get("/client-updates/:platform/download", requireUser, (req, res) => {
  const platform = String(req.params.platform);
  if (!isPlatform(platform) || !existsSync(binaryPath(platform))) {
    return void res.status(404).json({ code: "not_found", message: "Nessun aggiornamento per questa piattaforma." });
  }
  res.set({
    "content-type": "application/octet-stream",
    "content-length": String(statSync(binaryPath(platform)).size),
  });
  createReadStream(binaryPath(platform)).pipe(res);
});

/** Caricamento dell'installatore con il suo manifesto firmato (intestazione X-Manifest, JSON in base64url). */
clientUpdatesRouter.put("/client-updates/:platform", requireUser, requireAdmin,
  express.raw({ type: "application/octet-stream", limit: MAX_SIZE }), (req, res) => {
    const platform = String(req.params.platform);
    let env: unknown;
    try {
      env = JSON.parse(Buffer.from(String(req.get("x-manifest") ?? ""), "base64url").toString("utf8"));
    } catch {
      env = null;
    }
    const m = isEnvelope(env) ? open<ClientUpdateManifest>(env, "client-update") : null;
    const trust = currentTrust();
    const signer = (env as Envelope | null)?.k;
    if (!m || !trust || !trust.doc.admins.some((a) => a.key === signer && a.role !== "recovery")) {
      return void res.status(400).json({ code: "bad_signature", message: "Manifesto non firmato da un amministratore fidato." });
    }
    if (trust.doc.revokedKeys?.includes(signer!)) {
      return void res.status(400).json({ code: "bad_signature", message: "Chiave revocata." });
    }
    const body = req.body as Buffer;
    if (m.platform !== platform || !isPlatform(platform) || !/^\d+\.\d+\.\d+$/.test(m.version)
        || !/^[\w .()-]{1,120}\.(exe|AppImage)$/.test(m.name)
        || !Buffer.isBuffer(body) || body.length !== m.size || createHash("sha256").update(body).digest("hex") !== m.sha256) {
      return void res.status(400).json({ code: "bad_request", message: "Installatore e manifesto non corrispondono." });
    }
    // Mai tornare indietro di versione con una pubblicazione
    const current = readManifest(platform);
    const currentVersion = current && open<ClientUpdateManifest>(current, "client-update")?.version;
    if (currentVersion && compareVersions(m.version, currentVersion) < 0) {
      return void res.status(409).json({ code: "older_version", message: `È già pubblicata la versione ${currentVersion}, più recente.` });
    }
    writeFileSync(binaryPath(platform) + ".tmp", body);
    writeFileSync(manifestPath(platform) + ".tmp", JSON.stringify(env));
    renameSync(binaryPath(platform) + ".tmp", binaryPath(platform));
    renameSync(manifestPath(platform) + ".tmp", manifestPath(platform));
    audit(req.user!.username, "client.update.publish", null, { platform, version: m.version, size: m.size, signer: fingerprint(signer!) });
    res.json({ ok: true, version: m.version });
  });

/** Ritiro dell'aggiornamento pubblicato (per esempio dopo un errore). */
clientUpdatesRouter.delete("/client-updates/:platform", requireUser, requireAdmin, (req, res) => {
  const platform = String(req.params.platform);
  if (!isPlatform(platform)) return void res.status(404).json({ code: "not_found", message: "Piattaforma sconosciuta." });
  for (const f of [binaryPath(platform), manifestPath(platform)]) if (existsSync(f)) unlinkSync(f);
  audit(req.user!.username, "client.update.withdraw", null, { platform });
  res.status(204).end();
});

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}
