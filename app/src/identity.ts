// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Chiave Ed25519 del server: gli agenti la fissano all'installazione e
// verificano con essa che dall'altra parte ci sia davvero questo server.
// Non autorizza comandi: quelli richiedono la firma di un tecnico.

import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { kvGet, kvSet } from "./db.js";
import { newKeyPair, rawPublicKey, seal, type Envelope } from "./envelope.js";

let cached: { privateKey: KeyObject; publicKey: string } | null = null;

export function serverIdentity(): { privateKey: KeyObject; publicKey: string } {
  if (cached) return cached;
  let der = kvGet("server_identity");
  if (!der) {
    der = newKeyPair().privateDer.toString("base64");
    kvSet("server_identity", der);
  }
  const privateKey = createPrivateKey({ key: Buffer.from(der, "base64"), format: "der", type: "pkcs8" });
  cached = { privateKey, publicKey: rawPublicKey(createPublicKey(privateKey)) };
  return cached;
}

export function serverSeal(payload: Record<string, unknown>): Envelope {
  const id = serverIdentity();
  return seal(payload, id.privateKey, id.publicKey);
}
