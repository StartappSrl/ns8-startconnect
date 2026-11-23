#!/bin/bash
# Esegue tutte le prove del backend. Prerequisiti (vedi README del progetto):
#  - agente compilato:            AGENT=/percorso/startconnect-agent (versione 0.1.0)
#  - binari 0.2.0 e 0.0.5:        BIN=/cartella (per e2e-update)
#  - OpenLDAP di prova su 127.0.0.1:3890 (e2e-auth)
#  - guacd reale su 127.0.0.1:14823, sshd su 2222 (utente tester), xrdp su 3390 (e2e-identity, e2e-guacd-ssh)
#  - rec.mjs generato con esbuild (vedi e2e-recovery.mjs)
cd "$(dirname "$0")/.."
npm run build >/dev/null
run() {
  local name=$1 file=$2 ldap=$3 gport=${4:-14823} W=/tmp/startconnect-test-$1
  rm -rf "$W"; mkdir -p "$W"
  if [ "$ldap" = ldap ]; then L=(LDAP_URL=ldap://127.0.0.1:3890 LDAP_SCHEMA=rfc2307 LDAP_BASE_DN=dc=test,dc=lan LDAP_BIND_DN=cn=admin,dc=test,dc=lan LDAP_BIND_PASSWORD=secret)
  else L=(LDAP_URL=ldap://127.0.0.1:1 LDAP_BASE_DN=dc=x LDAP_BIND_DN=cn=x LDAP_BIND_PASSWORD=x); fi
  env TUNNEL_KEY=0123456789abcdef0123456789abcdef JWT_SECRET=test-secret-test-secret-test-secret "${L[@]}" \
    DATA_DIR="$W/data" PORT=18080 GUACD_PORT="$gport" node dist/index.js > "$W/server.log" 2>&1 &
  local srv=$!; sleep 1.5
  WORK="$W" DB="$W/data/startconnect.sqlite" timeout 150 node "test/$file" > "$W/out.txt" 2>&1
  kill $srv; wait $srv 2>/dev/null
  printf "%-22s OK %2s  FAIL %s\n" "$file" "$(grep -c '^OK' "$W/out.txt")" "$(grep -c '^FAIL' "$W/out.txt")"
  grep '^FAIL' "$W/out.txt"
}
run auth e2e-auth.mjs ldap
run agent e2e-agent.mjs no 14822
run ssh e2e-guacd-ssh.mjs
run identity e2e-identity.mjs
run update e2e-update.mjs
run recovery e2e-recovery.mjs

# Autonoma: avvia da sé backend e rustdesk-api simulato
printf "%-22s " e2e-rustdesk.mjs
if node test/e2e-rustdesk.mjs > /tmp/startconnect-test-rustdesk.txt 2>&1; then
  echo "OK $(grep -c '^OK' /tmp/startconnect-test-rustdesk.txt)"
else
  echo FAIL; grep '^FAIL' /tmp/startconnect-test-rustdesk.txt
fi

printf "%-22s " e2e-client-updates.mjs
if node test/e2e-client-updates.mjs > /tmp/startconnect-test-client-updates.txt 2>&1; then
  echo "OK $(grep -c '^OK' /tmp/startconnect-test-client-updates.txt)"
else
  echo FAIL; grep '^FAIL' /tmp/startconnect-test-client-updates.txt
fi
