// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Parametri guacd ammessi per protocollo. Tutto il resto viene scartato:
// chi modifica una connessione non può, ad esempio, attivare la mappatura
// di dischi o la registrazione delle sessioni sul server.

export type Protocol = "rdp" | "ssh" | "vnc" | "telnet";
export const PROTOCOLS: Protocol[] = ["rdp", "ssh", "vnc", "telnet"];

type Rule = "bool" | "int" | "text" | readonly string[];

const common: Record<string, Rule> = {
  "disable-copy": "bool",
  "disable-paste": "bool",
};
const terminal: Record<string, Rule> = {
  ...common,
  "color-scheme": "text",
  "font-name": "text",
  "font-size": "int",
  scrollback: "int",
  locale: "text",
  timezone: "text",
};

export const RULES: Record<Protocol, { defaultPort: number; options: Record<string, Rule> }> = {
  rdp: {
    defaultPort: 3389,
    options: {
      ...common,
      security: ["any", "nla", "nla-ext", "tls", "vmconnect", "rdp"],
      "ignore-cert": "bool",
      // Impronte accettate del certificato (formato FreeRDP "sha256:aa:bb:..."), rilevate e confermate dal tecnico
      "cert-fingerprints": "text",
      "server-layout": "text",
      console: "bool",
      "initial-program": "text",
      "color-depth": ["8", "16", "24", "32"],
      "resize-method": ["display-update", "reconnect"],
      "enable-wallpaper": "bool",
      "enable-theming": "bool",
      "enable-font-smoothing": "bool",
      "enable-full-window-drag": "bool",
      "enable-desktop-composition": "bool",
      "enable-menu-animations": "bool",
      "disable-audio": "bool",
      "enable-audio-input": "bool",
      timezone: "text",
      "load-balance-info": "text",
      "gateway-hostname": "text",
      "gateway-port": "int",
      "gateway-domain": "text",
    },
  },
  ssh: {
    defaultPort: 22,
    options: {
      ...terminal,
      "host-key": "text",
      command: "text",
      "server-alive-interval": "int",
    },
  },
  vnc: {
    defaultPort: 5900,
    options: {
      ...common,
      "color-depth": ["8", "16", "24", "32"],
      "swap-red-blue": "bool",
      cursor: ["local", "remote"],
      "read-only": "bool",
      encodings: "text",
    },
  },
  telnet: {
    defaultPort: 23,
    options: {
      ...terminal,
      "username-regex": "text",
      "password-regex": "text",
      "login-success-regex": "text",
      "login-failure-regex": "text",
    },
  },
};

export function isProtocol(value: unknown): value is Protocol {
  return typeof value === "string" && (PROTOCOLS as string[]).includes(value);
}

export function sanitizeOptions(protocol: Protocol, raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== "object") return out;
  const rules = RULES[protocol].options;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const rule = rules[key];
    if (!rule || value === null || value === undefined || value === "") continue;
    const text = String(value).slice(0, 4096);
    if (rule === "bool") {
      if (value === true || text === "true") out[key] = "true";
      else if (value === false || text === "false") out[key] = "false";
    } else if (rule === "int") {
      if (/^\d{1,6}$/.test(text)) out[key] = text;
    } else if (rule === "text") {
      if (!/[\0\r\n]/.test(text) || key === "host-key") out[key] = text;
    } else if (rule.includes(text)) {
      out[key] = text;
    }
  }
  return out;
}
