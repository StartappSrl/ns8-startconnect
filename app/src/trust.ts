// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Elenco degli amministratori fidati e certificati dei tecnici.
// Il server li conserva e li distribuisce ma non puo' crearli: ogni documento
// e' firmato sul PC di un amministratore. Gli agenti verificano tutto da soli.

import { db } from "./db.js";
import { open, verifyTrustChain, type Envelope, type TrustDoc } from "./envelope.js";

export interface TrustDocFull extends TrustDoc {
  revokedKeys?: string[];
}

export interface CertDoc {
  t: "cert";
  sub: string;
  key: string;
  role: "tech";
  iat: number;
  exp: number;
}

export interface CommandDoc {
  t: "cmd";
  op: "tunnel.open";
  device: string;
  port: number;
  user: string;
  nonce: string;
  iat: number;
  exp: number;
}

export function trustChain(): Envelope[] {
  return (db.prepare("SELECT envelope FROM trust ORDER BY version").all() as { envelope: string }[])
    .map((r) => JSON.parse(r.envelope) as Envelope);
}

export function currentTrust(): { doc: TrustDocFull; env: Envelope } | null {
  const chain = trustChain();
  if (!chain.length) return null;
  return verifyTrustChain(chain) as { doc: TrustDocFull; env: Envelope } | null;
}

export const MAX_CERT_DAYS = 90;
export const MAX_COMMAND_SECONDS = 120;

/**
 * Stessa verifica che fa l'agente (il server la ripete come difesa in
 * profondita'): firma del comando, certificato valido emesso da un
 * amministratore fidato, chiave non revocata, scadenze brevi.
 */
export function authorizeCommand(
  cmdEnv: unknown, certEnv: unknown, expect: { device: string; port: number; user: string },
): { ok: true; cmd: CommandDoc; signer: string } | { ok: false; reason: string } {
  const trust = currentTrust();
  if (!trust) return { ok: false, reason: "Nessun elenco di amministratori fidati: un amministratore deve crearlo." };
  const cmd = open<CommandDoc>(cmdEnv, "cmd");
  if (!cmd) return { ok: false, reason: "Comando non firmato correttamente." };
  const signer = (cmdEnv as Envelope).k;
  const now = Math.floor(Date.now() / 1000);
  if (cmd.op !== "tunnel.open" || cmd.device !== expect.device || cmd.port !== expect.port || cmd.user !== expect.user) {
    return { ok: false, reason: "Il comando firmato non corrisponde alla connessione richiesta." };
  }
  if (cmd.exp < now || cmd.iat > now + 60 || cmd.exp - cmd.iat > MAX_COMMAND_SECONDS) {
    return { ok: false, reason: "Comando scaduto: controlla l'orologio del PC." };
  }
  if (trust.doc.revokedKeys?.includes(signer)) return { ok: false, reason: "La chiave di questo PC è stata revocata." };

  const operators = trust.doc.admins.filter((a) => a.role !== "recovery");
  if (operators.some((a) => a.key === signer && a.name === cmd.user)) return { ok: true, cmd, signer };

  const cert = open<CertDoc>(certEnv, "cert");
  const issuer = (certEnv as Envelope | undefined)?.k;
  if (!cert || !issuer || !operators.some((a) => a.key === issuer)) {
    return { ok: false, reason: "Questo PC non ha un certificato valido: chiedi a un amministratore di certificarlo." };
  }
  if (cert.key !== signer || cert.sub !== cmd.user || cert.role !== "tech" || cert.exp < now || cert.exp - cert.iat > MAX_CERT_DAYS * 86400) {
    return { ok: false, reason: "Certificato del PC scaduto o non valido: chiedi a un amministratore di rinnovarlo." };
  }
  return { ok: true, cmd, signer };
}
