// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

import { Client, InvalidCredentialsError } from "ldapts";
import { config } from "./config.js";

export interface DirectoryUser {
  username: string;
  displayName: string;
  groups: string[];
}

export type LookupResult =
  | { status: "ok"; user: DirectoryUser; dn: string }
  | { status: "missing" | "disabled" };

// RFC 4515: escape dei valori inseriti nei filtri LDAP
function escapeFilter(value: string): string {
  return value.replace(/[\\*()\0]/g, (c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));
}

// Accetta "mario", "DOMINIO\mario" o "mario@dominio.it"
export function normalizeUsername(input: string): string | null {
  let name = input.trim();
  if (name.includes("\\")) name = name.slice(name.lastIndexOf("\\") + 1);
  if (name.includes("@")) name = name.slice(0, name.indexOf("@"));
  return /^[A-Za-z0-9._-]{1,64}$/.test(name) ? name.toLowerCase() : null;
}

function first(value: unknown): string {
  if (Array.isArray(value)) return String(value[0] ?? "");
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return value == null ? "" : String(value);
}

function newClient(): Client {
  return new Client({ url: config.ldap.url, timeout: 10_000, connectTimeout: 5_000 });
}

async function withServiceBind<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const client = newClient();
  try {
    await client.bind(config.ldap.bindDn, config.ldap.bindPassword);
    return await fn(client);
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

/**
 * Cerca l'utente nel dominio e ne verifica lo stato:
 * - Active Directory: account disattivato (userAccountControl, bit 2);
 * - OpenLDAP: account bloccato (pwdAccountLockedTime) o scaduto (shadowExpire).
 */
export async function lookupUser(username: string): Promise<LookupResult> {
  const ad = config.ldap.schema === "ad";
  const base = config.ldap.baseDn;
  return withServiceBind(async (client) => {
    const { searchEntries } = await client.search(ad ? base : `ou=People,${base}`, {
      scope: "sub",
      filter: ad
        ? `(&(objectClass=user)(sAMAccountName=${escapeFilter(username)}))`
        : `(&(objectClass=posixAccount)(uid=${escapeFilter(username)}))`,
      attributes: ["dn", "displayName", "cn", "userAccountControl", "pwdAccountLockedTime", "shadowExpire"],
      sizeLimit: 2,
    });
    if (searchEntries.length !== 1) return { status: "missing" } as const;
    const entry = searchEntries[0]!;
    if (ad && (Number(first(entry.userAccountControl)) & 2)) return { status: "disabled" } as const;
    if (!ad) {
      if (first(entry.pwdAccountLockedTime)) return { status: "disabled" } as const;
      const expire = Number(first(entry.shadowExpire));
      if (expire > 0 && expire * 86_400_000 < Date.now()) return { status: "disabled" } as const;
    }
    const { searchEntries: groupEntries } = await client.search(ad ? base : `ou=Groups,${base}`, {
      scope: "sub",
      // In AD la regola 1.2.840.113556.1.4.1941 include i gruppi annidati
      filter: ad
        ? `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=${escapeFilter(entry.dn)}))`
        : `(&(objectClass=posixGroup)(memberUid=${escapeFilter(username)}))`,
      attributes: ["cn"],
    });
    return {
      status: "ok",
      dn: entry.dn,
      user: {
        username,
        displayName: first(entry.displayName) || first(entry.cn) || username,
        groups: groupEntries.map((e) => first(e.cn).toLowerCase()).filter(Boolean),
      },
    } as const;
  });
}

export async function authenticate(rawUsername: string, password: string): Promise<DirectoryUser | null> {
  const username = normalizeUsername(rawUsername);
  // Una password vuota produrrebbe un bind anonimo riuscito: va rifiutata
  if (!username || !password) return null;
  const found = await lookupUser(username);
  if (found.status !== "ok") return null;

  const userClient = newClient();
  try {
    await userClient.bind(found.dn, password);
  } catch (e) {
    if (e instanceof InvalidCredentialsError) return null;
    throw e;
  } finally {
    await userClient.unbind().catch(() => undefined);
  }
  return found.user;
}
