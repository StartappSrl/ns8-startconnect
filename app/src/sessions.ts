// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Sessioni in attesa di apertura del tunnel.
//
// Le credenziali del server di destinazione restano solo in memoria, per al
// massimo 60 secondi e per un solo utilizzo. Non finiscono nel token
// (guacamole-lite lo decifra come ASCII e corromperebbe le password con
// lettere accentate) né nel database o nei log.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { config } from "./config.js";
import type { Protocol } from "./protocols.js";

export interface TargetCredential {
  username?: string;
  password?: string;
  domain?: string;
  privateKey?: string;
  passphrase?: string;
}

export interface Pending {
  username: string;
  connectionId: string;
  connectionName: string;
  protocol: Protocol;
  hostname: string;
  port: number;
  credentialSource: string;
  guac: Record<string, string>;
  expires: number;
  claimed: boolean;
}

const pending = new Map<string, Pending>();

function clip(value: unknown, max: number): string | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  return value.length <= max ? value : undefined;
}

export function sanitizeCredential(raw: unknown): TargetCredential {
  const c = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  return {
    username: clip(c.username, 256),
    password: clip(c.password, 1024),
    domain: clip(c.domain, 256),
    privateKey: clip(c.privateKey, 16_384),
    passphrase: clip(c.passphrase, 1024),
  };
}

export function guacSettings(
  protocol: Protocol,
  hostname: string,
  port: number,
  options: Record<string, string>,
  cred: TargetCredential,
): Record<string, string> {
  const base: Record<string, string> = { ...options, hostname, port: String(port) };
  const set = (key: string, value: string | undefined) => {
    if (value !== undefined) base[key] = value;
  };

  let username = cred.username;
  let domain = cred.domain;
  // "DOMINIO\utente" -> dominio e utente separati, come si aspetta guacd per RDP
  if (protocol === "rdp" && username?.includes("\\") && !domain) {
    domain = username.slice(0, username.indexOf("\\"));
    username = username.slice(username.indexOf("\\") + 1);
  }

  switch (protocol) {
    case "rdp":
      base["resize-method"] ??= "display-update";
      base.security ??= "any";
      set("username", username);
      set("password", cred.password);
      set("domain", domain);
      break;
    case "ssh":
      set("username", username);
      set("password", cred.password);
      set("private-key", cred.privateKey);
      set("passphrase", cred.passphrase);
      break;
    case "vnc":
      set("username", username);
      set("password", cred.password);
      break;
    case "telnet":
      set("username", username);
      set("password", cred.password);
      break;
  }
  return base;
}

export function createPending(entry: Omit<Pending, "expires" | "claimed">): string {
  const nonce = randomBytes(24).toString("base64url");
  pending.set(nonce, { ...entry, expires: Date.now() + config.pendingTtlMs, claimed: false });
  return encryptToken({ connection: { type: entry.protocol, settings: {} }, nonce });
}

/** Primo passo all'apertura del WebSocket: un token vale per una sola connessione. */
export function claim(nonce: unknown): boolean {
  if (typeof nonce !== "string") return false;
  const entry = pending.get(nonce);
  if (!entry || entry.claimed || entry.expires < Date.now()) return false;
  entry.claimed = true;
  return true;
}

/** Secondo passo: consegna le impostazioni e cancella la voce. */
export function take(nonce: unknown): Pending | undefined {
  if (typeof nonce !== "string") return undefined;
  const entry = pending.get(nonce);
  pending.delete(nonce);
  return entry?.claimed ? entry : undefined;
}

setInterval(() => {
  const t = Date.now();
  for (const [nonce, entry] of pending) if (entry.expires < t) pending.delete(nonce);
}, 15_000).unref();

// Formato token compatibile con guacamole-lite (AES-256-CBC, JSON {iv, value} in base64)
export function encryptToken(data: unknown): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", Buffer.from(config.tunnelKey), iv);
  const value = Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final()]);
  return Buffer.from(JSON.stringify({ iv: iv.toString("base64"), value: value.toString("base64") })).toString("base64");
}

export function decryptToken(token: string): Record<string, unknown> {
  const outer = JSON.parse(Buffer.from(token, "base64").toString("utf8")) as { iv: string; value: string };
  const decipher = createDecipheriv("aes-256-cbc", Buffer.from(config.tunnelKey), Buffer.from(outer.iv, "base64"));
  const plain = Buffer.concat([decipher.update(Buffer.from(outer.value, "base64")), decipher.final()]);
  return JSON.parse(plain.toString("utf8")) as Record<string, unknown>;
}
