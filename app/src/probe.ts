// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Rilevamento dell'identità di un server (certificato RDP, chiave SSH) da far
// confermare al tecnico. Una volta salvata, guacd la verifica a ogni
// connessione: se cambia, la sessione non parte (possibile intercettazione).

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { connect as netConnect, isIP } from "node:net";
import { connect as tlsConnect } from "node:tls";

export interface RdpIdentity {
  kind: "rdp";
  fingerprint: string;   // formato FreeRDP: sha256:aa:bb:...
  display: string;       // per il tecnico
  subject: string;
  validTo: string;
}

export interface SshIdentity {
  kind: "ssh";
  keys: { type: string; line: string; fingerprint: string }[];
  /** Chiave da salvare: quella che libssh2 (dentro guacd) negozia per prima. */
  preferred: { type: string; line: string; fingerprint: string };
}

// Ordine di preferenza degli algoritmi di chiave del server in libssh2 1.11:
// guacd confronta solo la chiave negoziata, quindi va salvata quella.
const LIBSSH2_ORDER = ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519", "ssh-rsa"];

const TIMEOUT = 8000;

/** Certificato TLS di un server RDP: negoziazione X.224 con richiesta di TLS, poi handshake. */
export function probeRdp(host: string, port: number): Promise<RdpIdentity> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port, timeout: TIMEOUT });
    const fail = (msg: string) => {
      socket.destroy();
      reject(new Error(msg));
    };
    socket.once("timeout", () => fail("Il server non risponde."));
    socket.once("error", (e) => fail(`Connessione non riuscita: ${e.message}`));
    socket.once("connect", () => {
      // TPKT (4) + X.224 Connection Request (7) + RDP_NEG_REQ (8): TLS e NLA
      socket.write(Buffer.from("030000130ee000000000000100080003000000", "hex"));
    });
    let buf = Buffer.alloc(0);
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 4) return;
      const len = buf.readUInt16BE(2);
      if (buf.length < len) return;
      socket.off("data", onData);
      // RDP_NEG_RSP (tipo 2) o RDP_NEG_FAILURE (tipo 3) dopo TPKT e X.224
      if (len < 19 || buf[11] !== 0x02) return fail("Il server non accetta connessioni RDP con TLS.");
      const tls = tlsConnect({ socket, rejectUnauthorized: false, servername: isIP(host) ? undefined : host }, () => {
        const cert = tls.getPeerCertificate();
        tls.destroy();
        if (!cert?.fingerprint256) return reject(new Error("Certificato non ricevuto."));
        const hex = cert.fingerprint256.toLowerCase();
        resolve({
          kind: "rdp",
          fingerprint: `sha256:${hex}`,
          display: hex.toUpperCase(),
          subject: String(cert.subject?.CN ?? ""),
          validTo: cert.valid_to,
        });
      });
      tls.once("error", (e) => fail(`Handshake TLS non riuscito: ${e.message}`));
    };
    socket.on("data", onData);
  });
}

/** Chiavi SSH con ssh-keyscan, in formato known_hosts come si aspetta guacd. */
export function probeSsh(host: string, port: number): Promise<SshIdentity> {
  return new Promise((resolve, reject) => {
    execFile("ssh-keyscan", ["-T", "8", "-p", String(port), "-t", "ed25519,ecdsa,rsa", host],
      { timeout: 15_000, maxBuffer: 64 * 1024 }, (err, stdout) => {
        const keys = stdout.split("\n")
          .filter((l) => l && !l.startsWith("#"))
          .map((line) => {
            const [, type, b64] = line.trim().split(/\s+/);
            const fp = createHash("sha256").update(Buffer.from(b64 ?? "", "base64")).digest("base64").replace(/=+$/, "");
            return { type: type ?? "", line: line.trim(), fingerprint: `SHA256:${fp}` };
          })
          .filter((k) => k.type && k.line.length < 4096);
        if (!keys.length) return reject(new Error(err ? "Il server non risponde o non è un server SSH." : "Nessuna chiave ricevuta."));
        const rank = (t: string) => (LIBSSH2_ORDER.indexOf(t) + 1) || 99;
        const preferred = [...keys].sort((a, b) => rank(a.type) - rank(b.type))[0]!;
        resolve({ kind: "ssh", keys, preferred });
      });
  });
}
