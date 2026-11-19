# ns8-startconnect

Modulo NethServer 8 di **StartConnect**: catalogo condiviso delle connessioni remote
(RDP, SSH, VNC, Telnet), permessi per gruppi del dominio utenti NS8 e gateway
Guacamole (guacd) verso i server dei clienti. Si usa con il client desktop
StartConnect per Windows e Linux e con l'agente, che si trovano nel repository `startconnect`.

Derivato dal template [ns8-kickstart](https://github.com/NethServer/ns8-kickstart)
(GPL-3.0-or-later) e, per la parte LDAP, da [ns8-guacamole](https://github.com/mrmarkuz/ns8-guacamole).

## Componenti

| Container | Immagine | Ruolo |
|---|---|---|
| `startconnect-app` | `ghcr.io/startappsrl/startconnect-app` | API REST, permessi, registro, tunnel WebSocket |
| `guacd` | `ghcr.io/startappsrl/startconnect-guacd` | apre le sessioni RDP/SSH/VNC/Telnet; Apache Guacamole 1.6.0 ricompilato su Alpine 3.22 con FreeRDP 3 |

Il pod pubblica solo `127.0.0.1:${TCP_PORT}` verso Traefik; guacd non è raggiungibile dall'esterno.

Sullo stesso nome host il backend espone:

- `/api/…` per il client desktop e, senza sessione, `/api/agent/enroll` e `/api/agent/identity` per gli agenti;
- `/tunnel` (WebSocket) per le sessioni del client;
- `/agent` (WebSocket) per gli agenti. Le connessioni tramite agente usano una porta locale
  temporanea nel pod, aperta per una sola connessione di guacd.

La chiave d'identità del server per gli agenti è generata al primo avvio e conservata nel database
(quindi nel backup). Gli agenti la fissano all'installazione: ripristinare il backup la conserva,
mentre perderla obbliga a reinstallare gli agenti.

## Installazione

```bash
add-module ghcr.io/startappsrl/startconnect:latest 1
api-cli run module/startconnect1/configure-module --data '{
  "host": "connect.example.org",
  "http2https": true,
  "lets_encrypt": true,
  "ldap_domain": "ad.example.org",
  "admin_group": "domain admins"
}'
```

Parametri di `configure-module` (disponibili anche nella pagina Impostazioni del modulo):

- `host`: nome di dominio (FQDN) con cui i client raggiungono StartConnect.
- `http2https`, `lets_encrypt`: come per gli altri moduli NS8.
- `ldap_domain`: dominio utenti NS8 usato per l'accesso; i permessi delle cartelle si riferiscono ai suoi gruppi.
- `admin_group`: i membri di questo gruppo gestiscono tutto (predefinito `domain admins`).

Alla prima configurazione vengono generati in `state/secrets.env` la chiave dei token del tunnel
e quella delle sessioni API. Il file è incluso nel backup.

## guacd

L'immagine `startconnect-guacd` è ricompilata da `build-images.sh` dalla ricetta ufficiale di
guacamole-server 1.6.0 con Alpine 3.22, OpenSSL 3 e FreeRDP 3.32.x, applicando le correzioni in
`guacd/patches/` (GUACAMOLE-2072 e GUACAMOLE-2328 dal ramo 1.6.1). Senza GUACAMOLE-2328, guacd 1.6.0
va in crash su ogni connessione RDP con FreeRDP 3.31 e successivi. Alla pubblicazione di guacd 1.6.1
le correzioni vanno rimosse.

## Registro attività

Conservazione configurabile (`audit_retention_days` in configure-module, da 30 a 3650 giorni,
predefinito 365). Esportazione CSV per gli amministratori da `GET /api/audit/export`.

## Accesso e sessioni

- L'accesso richiede la password del dominio e un codice TOTP (configurato dal client al primo
  accesso). Solo per installazioni di prova si può disattivare con `MFA_REQUIRED=false`.
- Le sessioni sono nel database (tabella `user_sessions`, solo hash dei token): 10 ore al massimo,
  2 ore di inattività, nuova verifica dell'utente nel dominio ogni 10 minuti. Se il dominio non
  risponde le sessioni restano valide e la verifica viene ripetuta alla richiesta successiva.
- Per chiudere subito tutte le sessioni di un utente basta disattivarlo nel dominio (effetto entro
  10 minuti) oppure azzerarne la MFA dal client.

## Backup

`module-dump-state` crea una copia coerente del database SQLite (`state/data/backup.sqlite`);
dopo un ripristino il backend la usa automaticamente se il database principale manca.

## Sviluppo del backend

```bash
cd app
npm ci
npm run typecheck
```

Le variabili d'ambiente richieste sono in `app/src/config.ts`.
Il livello di log del tunnel è limitato a `NORMAL`: a livello `DEBUG` guacamole-lite
registrerebbe le password inviate a guacd.
