// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Lettura periodica dei dispositivi dal server RustDesk (lejianwen/rustdesk-api v2.7).
//
// - POST /api/admin/login  {username, password}  -> data.token
// - GET  /api/admin/peer/list?page=&page_size=   (header "api-token")
// Tutte le risposte sono HTTP 200: l'esito è nel campo "code" (0 = ok, 403 = accesso scaduto).
// L'elenco completo richiede un utente amministratore di rustdesk-api; il token si
// rinnova da solo a ogni chiamata, quindi il login avviene solo all'avvio o se scade.
//
// Attenzione al blocco degli accessi di rustdesk-api: dopo 3 login falliti in 10 minuti
// chiede un captcha, dopo 5 blocca l'IP per 30 minuti su tutte le rotte. Per questo,
// dopo un login fallito la sincronizzazione si ferma per 30 minuti invece di riprovare.

import { config } from "./config.js";
import { now } from "./db.js";
import { upsertFromServer, type ServerPeer } from "./rustdesk.js";

const PAGE_SIZE = 200;
const LOGIN_BACKOFF_MS = 30 * 60_000;

interface ApiReply<T> {
  code: number;
  message?: string;
  data?: T;
}

interface ApiPeer {
  id?: string;
  hostname?: string;
  os?: string;
  username?: string;
  version?: string;
  last_online_time?: number;
  last_online_ip?: string;
}

const status = { ok: false, at: null as string | null, count: 0, error: null as string | null };
let token: string | null = null;
let loginBlockedUntil = 0;
let running = false;

export function syncStatus() {
  return { ...status };
}

function configured(): boolean {
  const r = config.rustdesk;
  return Boolean(r.apiServer && r.apiUser && r.apiPassword);
}

async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<ApiReply<T>> {
  const res = await fetch(new URL(path, config.rustdesk.apiServer), {
    method,
    headers: { "content-type": "application/json", ...(token ? { "api-token": token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
    redirect: "error",
  });
  if (!res.ok) throw new Error(`il server RustDesk ha risposto HTTP ${res.status}`);
  return (await res.json()) as ApiReply<T>;
}

async function login(): Promise<void> {
  if (Date.now() < loginBlockedUntil) {
    throw new Error("accesso al server RustDesk sospeso dopo un errore di login: nuovo tentativo più tardi");
  }
  token = null;
  const r = await call<{ token?: string }>("POST", "/api/admin/login", {
    username: config.rustdesk.apiUser,
    password: config.rustdesk.apiPassword,
    platform: "",
    captcha: "",
    captcha_id: "",
  });
  if (r.code !== 0 || !r.data?.token) {
    loginBlockedUntil = Date.now() + LOGIN_BACKOFF_MS;
    throw new Error(`login sul server RustDesk non riuscito (${r.message ?? r.code}): controlla utente e password`);
  }
  token = r.data.token;
}

async function listPage(page: number): Promise<{ list: ApiPeer[]; total: number }> {
  const path = `/api/admin/peer/list?page=${page}&page_size=${PAGE_SIZE}`;
  let r = await call<{ list?: ApiPeer[]; total?: number }>("GET", path);
  if (r.code === 403) {
    // Token scaduto o revocato: un solo nuovo login
    await login();
    r = await call("GET", path);
  }
  if (r.code !== 0) throw new Error(`elenco dei dispositivi non disponibile (${r.message ?? r.code})`);
  return { list: r.data?.list ?? [], total: Number(r.data?.total) || 0 };
}

function toServerPeer(p: ApiPeer): ServerPeer | null {
  if (typeof p.id !== "string") return null;
  const seconds = Number(p.last_online_time);
  return {
    id: p.id,
    hostname: p.hostname,
    os: p.os,
    username: p.username,
    version: p.version,
    lastOnline: seconds > 0 ? new Date(seconds * 1000).toISOString() : null,
    lastIp: p.last_online_ip,
  };
}

export async function syncOnce(): Promise<void> {
  if (!configured() || running) return;
  running = true;
  try {
    if (!token) await login();
    const peers: ServerPeer[] = [];
    for (let page = 1; page <= 100; page++) {
      const { list, total } = await listPage(page);
      for (const p of list) {
        const peer = toServerPeer(p);
        if (peer) peers.push(peer);
      }
      if (!list.length || page * PAGE_SIZE >= total) break;
    }
    status.count = upsertFromServer(peers);
    status.ok = true;
    status.error = null;
  } catch (e) {
    status.ok = false;
    status.error = (e as Error).message.slice(0, 300);
    console.error("Sincronizzazione RustDesk:", status.error);
  } finally {
    status.at = now();
    running = false;
  }
}

export function startRustdeskSync(): void {
  if (!configured()) return;
  void syncOnce();
  setInterval(() => void syncOnce(), config.rustdesk.syncSeconds * 1000).unref();
}
