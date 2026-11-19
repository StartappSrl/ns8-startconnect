// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import GuacamoleLite from "guacamole-lite";
import { config } from "./config.js";
import { audit } from "./db.js";
import { claim, decryptToken, take, type Pending } from "./sessions.js";

const INFO = Symbol("startconnect-session");
const display = ["width", "height", "dpi", "timezone"];

export function attachTunnel(): { handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void; close(): void } {
  const guac = new GuacamoleLite(
    {
      // "server" presente (anche se vuoto) impedisce a guacamole-lite di aggiungere port: 8080
      server: undefined,
      noServer: true,
      maxPayload: 8 * 1024 * 1024,
      // Rifiuta l'upgrade se il token non è valido, scaduto o già usato:
      // così guacamole-lite non apre mai connessioni senza impostazioni.
      verifyClient: (info: { req: IncomingMessage }, done: (ok: boolean, code?: number, message?: string) => void) => {
        try {
          const token = new URL(info.req.url ?? "", "http://localhost").searchParams.get("token") ?? "";
          const data = decryptToken(token);
          if (claim(data.nonce)) return done(true);
        } catch {
          // token malformato
        }
        done(false, 401, "Unauthorized");
      },
    },
    config.guacd,
    {
      crypt: { cypher: "AES-256-CBC", key: config.tunnelKey },
      log: { level: config.tunnelLogLevel },
      maxInactivityTime: 30_000,
      // Dal client arrivano in chiaro solo i parametri di visualizzazione
      allowedUnencryptedConnectionSettings: { rdp: display, ssh: display, vnc: display, telnet: display, join: [] },
    },
    {
      processConnectionSettings: (settings, callback) => {
        const entry = take(settings.nonce);
        if (!entry) return callback(new Error("Sessione scaduta o già utilizzata"));
        settings.connection = { ...settings.connection, ...entry.guac };
        Object.defineProperty(settings, INFO, { value: { ...entry, guac: undefined, started: Date.now() }, enumerable: false });
        callback(undefined, settings);
      },
    },
  );

  guac.on("open", (connection) => {
    const info = connection.connectionSettings?.[INFO] as (Pending & { started: number }) | undefined;
    if (!info) return;
    audit(info.username, "session.start", info.connectionId, {
      name: info.connectionName, protocol: info.protocol, hostname: info.hostname, port: info.port,
      credential: info.credentialSource,
    });
  });

  guac.on("close", (connection, error) => {
    const info = connection.connectionSettings?.[INFO] as (Pending & { started: number }) | undefined;
    if (!info) return;
    audit(info.username, "session.end", info.connectionId, {
      name: info.connectionName, seconds: Math.round((Date.now() - info.started) / 1000),
      error: error ? String(error.message ?? error).slice(0, 200) : undefined,
    });
  });

  guac.on("error", () => undefined);
  const wss = (guac as unknown as { webSocketServer: { handleUpgrade: Function; emit: Function } }).webSocketServer;
  return {
    handleUpgrade(req, socket, head) {
      wss.handleUpgrade(req, socket, head, (ws: unknown) => wss.emit("connection", ws, req));
    },
    close: () => guac.close(),
  };
}
