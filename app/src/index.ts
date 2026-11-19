// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import { createServer } from "node:http";
import express, { type NextFunction, type Request, type Response } from "express";
import { config } from "./config.js";
import { pruneAudit } from "./db.js";
import { router, VERSION } from "./routes.js";
import { agentRouter } from "./routes-agent.js";
import { authRouter } from "./mfa.js";
import { updatesRouter } from "./updates.js";
import { hub } from "./agents.js";
import { attachTunnel } from "./tunnel.js";

const app = express();
app.disable("x-powered-by");
// Le richieste arrivano da Traefik sullo stesso host
app.set("trust proxy", "loopback, 10.0.2.2");
app.use((_req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  next();
});
app.use("/api", updatesRouter);
app.use(express.json({ limit: "64kb" }));
app.use("/api", authRouter);
app.use("/api", agentRouter);
app.use("/api", router);
app.use((_req, res) => {
  res.status(404).json({ code: "not_found", message: "Risorsa inesistente." });
});
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("Errore non gestito:", err.message);
  res.status(500).json({ code: "server_error", message: "Errore interno del server." });
});

const server = createServer(app);

// Conservazione del registro: pulizia all'avvio e ogni 6 ore
const prune = () => {
  const removed = pruneAudit(config.auditRetentionDays);
  if (removed) console.log(`Registro attività: eliminate ${removed} voci oltre ${config.auditRetentionDays} giorni`);
};
prune();
setInterval(prune, 6 * 3_600_000).unref();
const tunnel = attachTunnel();

// Due WebSocket sullo stesso server HTTP: /tunnel (guacd) e /agent (agenti)
server.on("upgrade", (req, socket, head) => {
  const path = (req.url ?? "").split("?")[0];
  if (path === "/tunnel") tunnel.handleUpgrade(req, socket, head);
  else if (path === "/agent") hub.handleUpgrade(req, socket, head);
  else socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
});

server.listen(config.port, () => {
  console.log(`StartConnect ${VERSION} in ascolto sulla porta ${config.port}`);
});

const shutdown = () => {
  tunnel.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("unhandledRejection", (reason) => {
  console.error("Promise rifiutata non gestita:", reason instanceof Error ? reason.message : reason);
});
