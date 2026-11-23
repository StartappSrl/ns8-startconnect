// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Variabile d'ambiente ${name} mancante`);
  return value;
}

const tunnelKey = required("TUNNEL_KEY");
if (Buffer.byteLength(tunnelKey) !== 32) {
  throw new Error("TUNNEL_KEY deve essere lunga esattamente 32 byte (AES-256)");
}

const schema = process.env.LDAP_SCHEMA === "ad" ? "ad" : "rfc2307";

// guacamole-lite a livello DEBUG registra le istruzioni inviate a guacd,
// password comprese: il livello massimo consentito è NORMAL.
const LOG_LEVELS = ["QUIET", "ERRORS", "NORMAL"] as const;
const requestedLog = (process.env.TUNNEL_LOG_LEVEL ?? "ERRORS").toUpperCase();

export const config = {
  port: Number(process.env.PORT ?? 8080),
  dataDir: process.env.DATA_DIR ?? "/data",
  publicHost: process.env.PUBLIC_HOST ?? "",
  guacd: {
    host: process.env.GUACD_HOST ?? "127.0.0.1",
    port: Number(process.env.GUACD_PORT ?? 4822),
  },
  tunnelKey,
  tunnelLogLevel: (LOG_LEVELS as readonly string[]).includes(requestedLog) ? requestedLog : "ERRORS",
  // Segreto del modulo (secrets.env): da qui si derivano le chiavi interne
  masterSecret: Buffer.from(required("JWT_SECRET")),
  // Sessioni: durata massima, inattività massima, nuova verifica dell'utente nel dominio
  sessionMaxHours: 10,
  sessionIdleMinutes: 120,
  directoryCheckMinutes: 10,
  // MFA obbligatoria per tutti (MFA_REQUIRED=false solo per installazioni di prova)
  mfaRequired: process.env.MFA_REQUIRED !== "false",
  // Conservazione del registro attività (GDPR): da 30 giorni a 10 anni, predefinito 1 anno
  auditRetentionDays: Math.min(Math.max(Number(process.env.AUDIT_RETENTION_DAYS) || 365, 30), 3650),
  pendingTtlMs: 60_000,
  adminGroup: (process.env.ADMIN_GROUP ?? "domain admins").toLowerCase(),
  // Server RustDesk (facoltativo). I dati per i client sono pubblici; utente e password
  // servono solo a leggere l'elenco dei dispositivi da rustdesk-api (secrets.env).
  rustdesk: {
    idServer: process.env.RUSTDESK_ID_SERVER ?? "",
    relayServer: process.env.RUSTDESK_RELAY_SERVER ?? process.env.RUSTDESK_ID_SERVER ?? "",
    apiServer: process.env.RUSTDESK_API_SERVER ?? "",
    key: process.env.RUSTDESK_KEY ?? "",
    apiUser: process.env.RUSTDESK_API_USER ?? "",
    apiPassword: process.env.RUSTDESK_API_PASSWORD ?? "",
    syncSeconds: Math.min(Math.max(Number(process.env.RUSTDESK_SYNC_SECONDS) || 60, 30), 3600),
    // Un client RustDesk collegato al server API invia un segnale ogni 15 s (registrato al
    // massimo ogni 30 s): oltre questa finestra senza contatti il PC è "non collegato".
    onlineWindowMs: 2 * 60_000,
  },
  ldap: {
    url: required("LDAP_URL"),
    schema: schema as "ad" | "rfc2307",
    baseDn: required("LDAP_BASE_DN"),
    bindDn: required("LDAP_BIND_DN"),
    bindPassword: required("LDAP_BIND_PASSWORD"),
  },
};
