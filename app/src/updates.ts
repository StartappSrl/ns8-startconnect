// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Aggiornamenti dell'agente. Il manifesto (versione, piattaforma, SHA-256) è
// firmato sul PC di un amministratore fidato; il server lo conserva con il
// binario e lo distribuisce, ma gli agenti verificano tutto da soli.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import express, { Router } from "express";
import { hub } from "./agents.js";
import { requireAdmin, requireUser } from "./auth.js";
import { config } from "./config.js";
import { audit } from "./db.js";
import { fingerprint, isEnvelope, open, type Envelope } from "./envelope.js";
import { currentTrust } from "./trust.js";

export const PLATFORMS = ["windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64"] as const;
export interface UpdateManifest {
  t: "update";
  version: string;
  platform: string;
  sha256: string;
  size: number;
  iat: number;
}

const dir = join(config.dataDir, "updates");
mkdirSync(dir, { recursive: true });

export function manifests(): Envelope[] {
  return PLATFORMS.map((p) => join(dir, `${p}.json`)).filter(existsSync)
    .map((f) => JSON.parse(readFileSync(f, "utf8")) as Envelope);
}

export function binaryFor(platform: string): Buffer | null {
  const f = join(dir, `${platform}.bin`);
  return (PLATFORMS as readonly string[]).includes(platform) && existsSync(f) ? readFileSync(f) : null;
}

export const updatesRouter = Router();

updatesRouter.get("/agent-updates", requireUser, (_req, res) => {
  res.json({
    updates: manifests().map((env) => {
      const m = open<UpdateManifest>(env, "update");
      return m && { platform: m.platform, version: m.version, size: m.size, signer: fingerprint(env.k), published: new Date(m.iat * 1000).toISOString() };
    }).filter(Boolean),
  });
});

/** Caricamento di un binario con il suo manifesto firmato (intestazione X-Manifest, JSON in base64url). */
updatesRouter.put("/agent-updates/:platform", requireUser, requireAdmin,
  express.raw({ type: "application/octet-stream", limit: "40mb" }), (req, res) => {
    const platform = String(req.params.platform);
    let env: unknown;
    try {
      env = JSON.parse(Buffer.from(String(req.get("x-manifest") ?? ""), "base64url").toString("utf8"));
    } catch {
      env = null;
    }
    const m = isEnvelope(env) ? open<UpdateManifest>(env, "update") : null;
    const trust = currentTrust();
    const body = req.body as Buffer;
    if (!m || !trust || !trust.doc.admins.some((a) => a.key === (env as Envelope).k && a.role !== "recovery")) {
      return void res.status(400).json({ code: "bad_signature", message: "Manifesto non firmato da un amministratore fidato." });
    }
    if (trust.doc.revokedKeys?.includes((env as Envelope).k)) {
      return void res.status(400).json({ code: "bad_signature", message: "Chiave revocata." });
    }
    if (m.platform !== platform || !(PLATFORMS as readonly string[]).includes(platform) || !/^\d+\.\d+\.\d+$/.test(m.version)
        || !Buffer.isBuffer(body) || body.length !== m.size || createHash("sha256").update(body).digest("hex") !== m.sha256) {
      return void res.status(400).json({ code: "bad_request", message: "Binario e manifesto non corrispondono." });
    }
    writeFileSync(join(dir, `${platform}.bin.tmp`), body);
    writeFileSync(join(dir, `${platform}.json.tmp`), JSON.stringify(env));
    renameSync(join(dir, `${platform}.bin.tmp`), join(dir, `${platform}.bin`));
    renameSync(join(dir, `${platform}.json.tmp`), join(dir, `${platform}.json`));
    audit(req.user!.username, "agent.update.publish", null, { platform, version: m.version, signer: fingerprint((env as Envelope).k) });
    hub.pushUpdates();
    res.json({ ok: true });
  });
