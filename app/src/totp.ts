// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// TOTP (RFC 6238, SHA-1, 6 cifre, 30 secondi): compatibile con Microsoft e
// Google Authenticator, FreeOTP, 2FAS, Bitwarden e simili.

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("base32 non valido");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", secret).update(msg).digest();
  const offset = h[h.length - 1]! & 15;
  const code = (h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}

/**
 * Verifica un codice nella finestra ±1 passo. Restituisce il passo usato
 * oppure null; il chiamante rifiuta passi già usati (niente riutilizzo).
 */
export function verifyTotp(secret: Buffer, code: string, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const step = Math.floor(now / 30_000);
  for (const s of [step, step - 1, step + 1]) {
    const expected = Buffer.from(hotp(secret, s));
    if (timingSafeEqual(expected, Buffer.from(code))) return s;
  }
  return null;
}

export function newSecret(): Buffer {
  return randomBytes(20);
}

export function otpauthUri(secret: Buffer, username: string): string {
  const issuer = "StartConnect";
  const label = encodeURIComponent(`${issuer}:${username}${config.publicHost ? `@${config.publicHost}` : ""}`);
  return `otpauth://totp/${label}?secret=${base32Encode(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ---------- Cifratura del segreto nel database ----------

const key = Buffer.from(hkdfSync("sha256", config.masterSecret, Buffer.from("startconnect"), Buffer.from("mfa-secret-v1"), 32));
const pepper = Buffer.from(hkdfSync("sha256", config.masterSecret, Buffer.from("startconnect"), Buffer.from("mfa-backup-v1"), 32));

export function sealSecret(secret: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(secret), cipher.final()]);
  return [iv, cipher.getAuthTag(), enc].map((b) => b.toString("base64url")).join(".");
}

export function openSecret(sealed: string): Buffer {
  const [iv, tag, enc] = sealed.split(".").map((p) => Buffer.from(p, "base64url"));
  const decipher = createDecipheriv("aes-256-gcm", key, iv!);
  decipher.setAuthTag(tag!);
  return Buffer.concat([decipher.update(enc!), decipher.final()]);
}

// ---------- Codici di riserva (monouso) ----------

export function newBackupCodes(): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: 10 }, () => {
    const raw = base32Encode(randomBytes(7)).slice(0, 10);
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
  return { codes, hashes: codes.map(hashBackupCode) };
}

export function hashBackupCode(code: string): string {
  return createHmac("sha256", pepper).update(code.replace(/[\s-]/g, "").toUpperCase()).digest("hex");
}
