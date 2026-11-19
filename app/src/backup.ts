// Copyright (C) 2026 Startapp Srl
// SPDX-License-Identifier: GPL-3.0-or-later

// Uso: node dist/backup.js /data/backup.sqlite  (chiamato da module-dump-state)
import Database from "better-sqlite3";
import { join } from "node:path";

const target = process.argv[2];
if (!target) {
  console.error("Indicare il file di destinazione");
  process.exit(1);
}
const source = new Database(join(process.env.DATA_DIR ?? "/data", "startconnect.sqlite"), { readonly: true });
await source.backup(target);
source.close();
console.log("Backup completato:", target);
