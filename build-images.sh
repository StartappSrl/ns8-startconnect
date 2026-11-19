#!/bin/bash

#
# Copyright (C) 2026 Startapp Srl
# Derived from NethServer/ns8-kickstart, Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

set -e

images=()
repobase="${REPOBASE:-ghcr.io/startappsrl}"
reponame="startconnect"
imagetag="${IMAGETAG:-latest}"
# renovate: datasource=npm packageName=corepack
corepack_version=0.36.0

#
# 0. guacd: Apache Guacamole 1.6.0 ricompilato dalla ricetta ufficiale, con:
#    - base Alpine 3.22 (l'immagine ufficiale usa Alpine 3.18 e OpenSSL 1.1, fuori supporto);
#    - FreeRDP 3 aggiornato (3.31.0 e 3.32.2 correggono numerose vulnerabilità del client);
#    - le correzioni ufficiali GUACAMOLE-2072 e GUACAMOLE-2328 dal ramo 1.6.1: senza la seconda
#      guacd 1.6.0 va in crash su ogni connessione RDP con FreeRDP 3.31 e successivi;
#    - FreeRDP compilato in modalità Release (GUACAMOLE-2264): le asserzioni di debug
#      interromperebbero le sessioni;
#    - libwebsockets fissata alla serie 4.x: la ricetta prende l'ultima versione e la 5.x
#      richiede GnuTLS, assente nella ricetta (guacamole 1.6.0 è scritto per la 4.x).
#
guacd_version=1.6.0
guacd_ctx=$(mktemp -d)
git clone --quiet --depth 1 --branch "${guacd_version}" https://github.com/apache/guacamole-server.git "${guacd_ctx}"
git -C "${guacd_ctx}" apply "${PWD}"/guacd/patches/*.patch
# La ricetta resta su Alpine 3.18 solo per OpenSSL 1.1, richiesto da FreeRDP 2: con FreeRDP 3 si usa OpenSSL 3
sed -i 's/openssl1.1-compat-dev/openssl-dev/' "${guacd_ctx}/Dockerfile"
# Alpine 3.22 non ha più webkit2gtk-dev (WebKitGTK 4.0): c'è solo webkit2gtk-4.1-dev.
# WebKit serve solo alla finestra di login Azure del client SDL di FreeRDP, che guacd non usa:
# la WebView si disattiva, così la compilazione non dipende dalla versione di WebKitGTK.
sed -i 's/webkit2gtk-dev/webkit2gtk-4.1-dev/' "${guacd_ctx}/Dockerfile"
# Su Alpine 3.22 i file CMake di cjson-dev rimandano anche a libcjson.a (pacchetto cjson-static):
# senza, la configurazione di FreeRDP si interrompe.
sed -i 's/cjson-dev/cjson-dev cjson-static/' "${guacd_ctx}/Dockerfile"
sed -i 's/-DBUILTIN_CHANNELS=OFF/-DCMAKE_BUILD_TYPE=Release -DWITH_WEBVIEW=OFF -DBUILTIN_CHANNELS=OFF/' "${guacd_ctx}/Dockerfile"
buildah bud --layers \
    --build-arg ALPINE_BASE_IMAGE=3.22 \
    --build-arg FREERDP_VERSION=3 \
    --build-arg 'WITH_FREERDP=3\.32\.\d+' \
    --build-arg 'WITH_LIBWEBSOCKETS=v4\.\d+(\.\d+)+' \
    -t "${repobase}/${reponame}-guacd" "${guacd_ctx}"
rm -rf "${guacd_ctx}"
images+=("${repobase}/${reponame}-guacd")

#
# 1. Backend image (API + tunnel Guacamole), built from app/Dockerfile
#
buildah bud --layers -t "${repobase}/${reponame}-app" app
images+=("${repobase}/${reponame}-app")

#
# 2. Module image (imageroot + UI di amministrazione NS8)
#
container=$(buildah from scratch)

if ! buildah containers --format "{{.ContainerName}}" | grep -q nodebuilder-startconnect; then
    echo "Pulling NodeJS runtime..."
    buildah from --name nodebuilder-startconnect -v "${PWD}:/usr/src:Z" docker.io/library/node:24.22.0-slim
    buildah run nodebuilder-startconnect sh -c "npm install -g corepack@${corepack_version} && corepack enable"
fi

echo "Build static UI files with node..."
buildah run \
    --workingdir=/usr/src/ui \
    --env="NODE_OPTIONS=--openssl-legacy-provider" \
    nodebuilder-startconnect \
    sh -c "yarn install && yarn build"

buildah add "${container}" imageroot /imageroot
buildah add "${container}" ui/dist /ui
# cluster:accountconsumer serve per leggere il dominio utenti (LDAP) di NS8
buildah config --entrypoint=/ \
    --label="org.nethserver.authorizations=traefik@node:routeadm cluster:accountconsumer" \
    --label="org.nethserver.tcp-ports-demand=1" \
    --label="org.nethserver.rootfull=0" \
    --label="org.nethserver.min-core=3.12.4-0" \
    --label="org.nethserver.images=${repobase}/${reponame}-guacd:${imagetag} ${repobase}/${reponame}-app:${imagetag}" \
    "${container}"
buildah commit "${container}" "${repobase}/${reponame}"
images+=("${repobase}/${reponame}")

# Scansione delle vulnerabilità (se Trivy è installato): blocca su HIGH/CRITICAL correggibili
if command -v trivy >/dev/null; then
    for image in "${images[@]}"; do
        trivy image --quiet --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 "${image}"
    done
fi

if [[ -n "${CI}" ]]; then
    printf "images=%s\n" "${images[*],,}" >> "${GITHUB_OUTPUT}"
else
    printf "Publish the images with:\n\n"
    for image in "${images[@],,}"; do printf "  buildah push %s docker://%s:%s\n" "${image}" "${image}" "${imagetag}" ; done
    printf "\n"
fi
