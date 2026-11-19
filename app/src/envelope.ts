// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Buste firmate Ed25519, comuni a server, client e agente.
//
//   { p: base64url(JSON), s: base64url(firma di p), k: base64url(chiave pubblica di chi firma) }
//
// La firma copre i byte esatti di p: nessun problema di serializzazione.
// Ogni payload ha un campo "t" (tipo) che separa i domini di firma:
// una firma per un tipo non vale mai per un altro.

import { createHash, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";

export interface Envelope {
  p: string;
  s: string;
  k: string;
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function b64u(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function fromB64u(text: string): Buffer {
  return Buffer.from(text, "base64url");
}

export function publicKeyFromRaw(raw: string): KeyObject | null {
  const bytes = fromB64u(raw);
  if (bytes.length !== 32) return null;
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, bytes]), format: "der", type: "spki" });
}

export function rawPublicKey(key: KeyObject): string {
  return b64u(key.export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length));
}

export function newKeyPair(): { privateKey: KeyObject; publicKey: string; privateDer: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey: rawPublicKey(publicKey), privateDer: privateKey.export({ format: "der", type: "pkcs8" }) };
}

export { PKCS8_PREFIX };

/** Impronta leggibile di una chiave: 8 gruppi di 4 cifre esadecimali. */
export function fingerprint(rawKey: string): string {
  const hex = createHash("sha256").update(fromB64u(rawKey)).digest("hex").slice(0, 32);
  return hex.match(/.{4}/g)!.join("-");
}

export function seal(payload: Record<string, unknown>, privateKey: KeyObject, publicKey: string): Envelope {
  const p = Buffer.from(JSON.stringify(payload), "utf8");
  return { p: b64u(p), s: b64u(sign(null, p, privateKey)), k: publicKey };
}

export function isEnvelope(value: unknown): value is Envelope {
  const e = value as Envelope;
  return !!e && typeof e.p === "string" && typeof e.s === "string" && typeof e.k === "string"
    && e.p.length < 65_536 && e.s.length < 200 && e.k.length < 100;
}

/** Verifica firma e tipo; restituisce il payload o null. */
export function open<T extends { t: string }>(env: unknown, type: string, expectedKey?: string): T | null {
  if (!isEnvelope(env)) return null;
  if (expectedKey !== undefined && env.k !== expectedKey) return null;
  const key = publicKeyFromRaw(env.k);
  if (!key) return null;
  const bytes = fromB64u(env.p);
  try {
    if (!verify(null, bytes, key, fromB64u(env.s))) return null;
    const payload = JSON.parse(bytes.toString("utf8")) as T;
    return payload && payload.t === type ? payload : null;
  } catch {
    return null;
  }
}

export function payloadHash(env: Envelope): string {
  return createHash("sha256").update(fromB64u(env.p)).digest("hex");
}

// ---------- Elenco degli amministratori fidati ("trust list") ----------

export interface TrustDoc {
  t: "trust";
  version: number;
  prev: string;               // hash del payload della versione precedente ("" per la prima)
  // role "recovery": chiave di emergenza, firma solo nuove versioni dell'elenco
  admins: { name: string; key: string; role?: string }[];
  iat: number;
}

/**
 * Verifica una catena di elenchi. La prima versione deve essere firmata da
 * uno dei suoi stessi amministratori; ogni versione successiva da un
 * amministratore della versione precedente. Se anchorHash e' indicato, la
 * catena viene verificata a partire dal documento con quell'hash.
 */
export function verifyTrustChain(chain: Envelope[], anchorHash?: string): { doc: TrustDoc; env: Envelope } | null {
  let current: { doc: TrustDoc; env: Envelope } | null = null;
  let anchored = anchorHash === undefined;
  for (const env of chain) {
    const doc = open<TrustDoc>(env, "trust");
    if (!doc || !Array.isArray(doc.admins) || !doc.admins.length) return null;
    if (!anchored) {
      if (payloadHash(env) !== anchorHash) continue;
      anchored = true;
      current = { doc, env };
      continue;
    }
    if (!current) {
      if (doc.version !== 1 || doc.prev !== "" || !doc.admins.some((a) => a.key === env.k)) return null;
    } else {
      if (doc.version !== current.doc.version + 1 || doc.prev !== payloadHash(current.env)) return null;
      if (!current.doc.admins.some((a) => a.key === env.k)) return null;
    }
    current = { doc, env };
  }
  return anchored ? current : null;
}
