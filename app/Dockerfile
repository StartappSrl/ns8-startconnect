# Copyright (C) 2026 Startapp Srl
# SPDX-License-Identifier: GPL-3.0-or-later

# Debian 13 (trixie): base supportata più a lungo di bookworm
FROM docker.io/library/node:24.22.1-trixie-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM docker.io/library/node:24.22.1-trixie-slim
# Aggiornamenti di sicurezza della base e rimozione di npm, corepack e yarn:
# servono solo per compilare e portano dipendenze proprie con vulnerabilità note.
# openssh-client: ssh-keyscan per rilevare le chiavi dei server SSH
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-*
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
USER node
EXPOSE 8080
CMD ["node", "dist/index.js"]
