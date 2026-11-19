// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Collegamento con gli agenti installati sui dispositivi dei clienti.
//
// L'agente apre sempre lui la connessione (wss://host/agent), quindi sui
// clienti non servono porte aperte. Autenticazione reciproca:
//   1. il server firma con la sua chiave il nonce dell'agente;
//   2. l'agente firma il nonce del server con la chiave creata all'installazione.
// I tunnel passano solo con un comando firmato da un tecnico: l'agente lo
// verifica con gli amministratori fidati, che il server non puo' falsificare.

import { randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { createServer, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import { WebSocket, WebSocketServer } from "ws";
import { audit, db, now } from "./db.js";
import { open, type Envelope } from "./envelope.js";
import { serverSeal } from "./identity.js";
import { trustChain } from "./trust.js";
import { binaryFor, manifests } from "./updates.js";

interface DeviceRow {
  id: string;
  public_key: string;
  status: "pending" | "active" | "revoked";
  trust_version: number;
}

interface HelloAgent {
  t: "hello-agent";
  device: string;
  agentNonce: string;
  serverNonce: string;
  iat: number;
  version: string;
  ports: number[];
  trustVersion: number;
}

interface Stream {
  socket: Socket;
  opened: boolean;
}

const ID = /^[A-Za-z0-9-]{1,64}$/;
const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
const MAX_INVENTORY = 1024 * 1024;
const UPDATE_STREAM = 0xffffffff;

class AgentConnection {
  streams = new Map<number, Stream>();
  private nextStream = 1;
  private alive = true;

  constructor(readonly deviceId: string, readonly ws: WebSocket) {}

  send(message: Record<string, unknown>): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(message));
  }

  ping(): boolean {
    if (!this.alive) {
      this.ws.terminate();
      return false;
    }
    this.alive = false;
    this.ws.ping();
    return true;
  }

  pong(): void {
    this.alive = true;
  }

  /** Collega un socket locale (guacd) a una porta del dispositivo, se l'agente accetta il comando. */
  bridge(socket: Socket, cmd: Envelope, cert: Envelope | null, user: string): void {
    const id = this.nextStream++;
    const stream: Stream = { socket, opened: false };
    this.streams.set(id, stream);
    socket.pause();
    this.send({ type: "open", stream: id, cmd, cert });

    socket.on("data", (chunk: Buffer) => {
      if (this.ws.readyState !== WebSocket.OPEN) return socket.destroy();
      const frame = Buffer.allocUnsafe(4 + chunk.length);
      frame.writeUInt32BE(id, 0);
      chunk.copy(frame, 4);
      this.ws.send(frame);
      // Contropressione: se il WebSocket accumula troppo, sospende il socket locale
      if (this.ws.bufferedAmount > 8 * 1024 * 1024) {
        socket.pause();
        const wait = () => (this.ws.bufferedAmount < 1024 * 1024 ? socket.resume() : setTimeout(wait, 20));
        setTimeout(wait, 20);
      }
    });
    socket.on("close", () => {
      if (this.streams.delete(id)) this.send({ type: "close", stream: id });
    });
    socket.on("error", () => socket.destroy());
    void user;
  }

  onText(raw: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return;
    }
    const stream = typeof msg.stream === "number" ? this.streams.get(msg.stream) : undefined;
    switch (msg.type) {
      case "opened":
        if (stream) {
          stream.opened = true;
          stream.socket.resume();
        }
        break;
      case "open-failed":
      case "close":
        if (stream) {
          this.streams.delete(msg.stream as number);
          stream.socket.destroy();
        }
        if (msg.type === "open-failed") {
          audit("agent", "tunnel.refused", null, { device: this.deviceId, reason: String(msg.reason ?? "").slice(0, 200) });
        }
        break;
      case "inventory": {
        const data = JSON.stringify(msg.data ?? {});
        if (data.length <= MAX_INVENTORY) {
          db.prepare("UPDATE devices SET inventory = ?, last_seen = ? WHERE id = ?").run(data, now(), this.deviceId);
        }
        break;
      }
      case "update-get": {
        // Trasferimento del binario sul WebSocket già autenticato, a blocchi da 512 KB
        const bin = typeof msg.platform === "string" ? binaryFor(msg.platform) : null;
        if (!bin) break;
        this.send({ type: "update-begin", platform: msg.platform, size: bin.length });
        for (let off = 0; off < bin.length; off += 512 * 1024) {
          const chunk = bin.subarray(off, off + 512 * 1024);
          const frame = Buffer.allocUnsafe(4 + chunk.length);
          frame.writeUInt32BE(UPDATE_STREAM, 0);
          chunk.copy(frame, 4);
          this.ws.send(frame);
        }
        this.send({ type: "update-end", platform: msg.platform });
        break;
      }
      case "update-status":
        audit("agent", "agent.update.status", null, { device: this.deviceId, status: String(msg.status ?? "").slice(0, 40), version: String(msg.version ?? "").slice(0, 20), detail: String(msg.detail ?? "").slice(0, 200) });
        break;
      case "trust-ack":
        if (typeof msg.version === "number") {
          db.prepare("UPDATE devices SET trust_version = ? WHERE id = ?").run(msg.version, this.deviceId);
        }
        break;
    }
  }

  onBinary(data: Buffer): void {
    if (data.length < 4) return;
    const stream = this.streams.get(data.readUInt32BE(0));
    if (stream?.opened) stream.socket.write(data.subarray(4));
  }

  closeAll(): void {
    for (const s of this.streams.values()) s.socket.destroy();
    this.streams.clear();
  }
}

export class AgentHub {
  private wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024, perMessageDeflate: false });
  private connections = new Map<string, AgentConnection>();

  constructor() {
    setInterval(() => {
      for (const [id, c] of this.connections) {
        if (!c.ping()) this.connections.delete(id);
        else db.prepare("UPDATE devices SET last_seen = ? WHERE id = ?").run(now(), id);
      }
    }, 30_000).unref();
  }

  isOnline(deviceId: string): boolean {
    return this.connections.has(deviceId);
  }

  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    const url = new URL(req.url ?? "", "http://localhost");
    const deviceId = url.searchParams.get("device") ?? "";
    const agentNonce = url.searchParams.get("nonce") ?? "";
    const device = ID.test(deviceId)
      ? db.prepare("SELECT id, public_key, status, trust_version FROM devices WHERE id = ?").get(deviceId) as DeviceRow | undefined
      : undefined;
    if (!device || device.status === "revoked" || !NONCE.test(agentNonce)) {
      socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return;
    }
    this.wss.handleUpgrade(req, socket, head, (ws) => this.handshake(ws, device, agentNonce));
  }

  private handshake(ws: WebSocket, device: DeviceRow, agentNonce: string): void {
    const serverNonce = randomBytes(24).toString("base64url");
    ws.send(JSON.stringify({
      type: "hello",
      env: serverSeal({ t: "hello-server", device: device.id, agentNonce, serverNonce, iat: Math.floor(Date.now() / 1000) }),
    }));
    const timer = setTimeout(() => ws.close(4001, "timeout"), 10_000);

    ws.once("message", (raw, isBinary) => {
      clearTimeout(timer);
      let hello: HelloAgent | null = null;
      try {
        const msg = JSON.parse(raw.toString()) as { type?: string; env?: unknown };
        if (!isBinary && msg.type === "auth") hello = open<HelloAgent>(msg.env, "hello-agent", device.public_key);
      } catch {
        hello = null;
      }
      const t = Math.floor(Date.now() / 1000);
      if (!hello || hello.device !== device.id || hello.agentNonce !== agentNonce || hello.serverNonce !== serverNonce
          || Math.abs(hello.iat - t) > 300) {
        ws.close(4003, "auth");
        return;
      }
      this.accept(ws, device, hello);
    });
  }

  private accept(ws: WebSocket, device: DeviceRow, hello: HelloAgent): void {
    this.connections.get(device.id)?.ws.close(4000, "replaced");
    const conn = new AgentConnection(device.id, ws);
    this.connections.set(device.id, conn);

    const ports = Array.isArray(hello.ports) ? hello.ports.filter((p) => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 32) : [];
    db.prepare("UPDATE devices SET last_seen = ?, agent_version = ?, ports = ?, trust_version = ? WHERE id = ?")
      .run(now(), String(hello.version ?? "").slice(0, 32), JSON.stringify(ports), Number(hello.trustVersion) || 0, device.id);

    ws.on("pong", () => conn.pong());
    ws.on("message", (data, isBinary) => {
      if (isBinary) conn.onBinary(data as Buffer);
      else conn.onText(data.toString());
    });
    ws.on("close", () => {
      conn.closeAll();
      if (this.connections.get(device.id) === conn) this.connections.delete(device.id);
    });
    ws.on("error", () => ws.terminate());

    this.pushTrust(device.id, Number(hello.trustVersion) || 0);
    conn.send({ type: "inventory-request" });
    conn.send({ type: "updates", manifests: manifests() });
  }

  /** Invia le versioni dell'elenco fidato che l'agente non ha ancora. */
  pushTrust(deviceId: string, agentVersion?: number): void {
    const conn = this.connections.get(deviceId);
    if (!conn) return;
    const since = agentVersion ?? (db.prepare("SELECT trust_version FROM devices WHERE id = ?").get(deviceId) as { trust_version: number }).trust_version;
    const chain = trustChain();
    if (chain.length > since) conn.send({ type: "trust", chain });
  }

  pushUpdates(): void {
    const list = manifests();
    for (const c of this.connections.values()) c.send({ type: "updates", manifests: list });
  }

  pushTrustAll(): void {
    for (const id of this.connections.keys()) this.pushTrust(id);
  }

  disconnect(deviceId: string): void {
    this.connections.get(deviceId)?.ws.close(4003, "revoked");
    this.connections.delete(deviceId);
  }

  /**
   * Prepara una porta locale nel pod: guacd vi si collega e il traffico
   * passa all'agente. Accetta una sola connessione entro 60 secondi.
   */
  async localTunnel(deviceId: string, cmd: Envelope, cert: Envelope | null, user: string): Promise<number> {
    if (!this.connections.has(deviceId)) throw new Error("offline");
    const server = createServer();
    server.maxConnections = 1;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const timer = setTimeout(() => server.close(), 60_000);
    server.once("connection", (socket) => {
      clearTimeout(timer);
      server.close();
      const conn = this.connections.get(deviceId);
      if (!conn || socket.remoteAddress !== "127.0.0.1") return socket.destroy();
      conn.bridge(socket, cmd, cert, user);
    });
    return (server.address() as { port: number }).port;
  }
}

export const hub = new AgentHub();
