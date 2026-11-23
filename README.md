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

## RustDesk (facoltativo)

StartConnect può elencare i PC del server RustDesk dell'azienda (modulo `ns8-rustdesk`, con
rustdesk-api) e metterli nelle cartelle dei clienti, con gli stessi permessi delle connessioni.
La sessione la apre il client RustDesk del tecnico; StartConnect registra chi apre cosa.

    api-cli run module/startconnect1/configure-module --data '{
      ...impostazioni attuali...,
      "rustdesk": {
        "id_server": "rds.example.org",
        "api_server": "https://rds.example.org",
        "key": "<contenuto di id_ed25519.pub di hbbs>",
        "api_user": "startconnect-sync",
        "api_password": "<password>"
      }
    }'

- `id_server`, `relay_server` (vuoto = come `id_server`), `api_server` e `key` sono dati pubblici: li
  ricevono i client e gli agenti. La chiave si legge con
  `api-cli run module/rustdesk1/get-configuration | jq -r .public_key`.
- `api_user`/`api_password`: utente **amministratore** di rustdesk-api (solo un amministratore vede
  l'elenco completo dei dispositivi). Restano in `rustdesk.env` (0600, incluso nel backup) e non
  compaiono mai in `get-configuration`; omettendo `api_password` si mantiene quella attuale.
- L'IP del nodo StartConnect deve essere in `admin_allowlist` del modulo RustDesk: `/api/admin` è
  protetta dalla stessa lista della console.
- La sincronizzazione (`GET /api/admin/peer/list`) avviene ogni 60 secondi. Dopo un login fallito si
  ferma per 30 minuti: rustdesk-api blocca per 30 minuti l'IP che sbaglia 5 accessi in 10 minuti.
- Un PC è "collegato" se il suo client RustDesk ha contattato il server API negli ultimi 2 minuti.
- I PC installati dall'agente StartConnect (opzione nel pacchetto) si collegano da soli al
  dispositivo e alla sua cartella, con la voce StartCredentials della password creata dal tecnico.

## Aggiornamenti del client desktop

Un amministratore fidato pubblica la nuova versione del client dal proprio client (finestra
"Sicurezza agenti"): installatore e manifesto firmato con la chiave del suo PC finiscono in
`state/data/client-updates/` (solo l'ultima versione per piattaforma, `win-x64` e `linux-x64`).

- `GET /api/client-updates`: versione e manifesto firmato; `GET .../:platform/download`: installatore.
- Il server accetta solo manifesti firmati da un amministratore dell'elenco fidato, con impronta e
  dimensione corrispondenti, e non permette di tornare a una versione precedente.
- Ogni client verifica da sé firma, elenco fidato e impronta prima di installare: un server
  compromesso non può distribuire un client falso. Se il client installato è firmato
  (Authenticode), accetta solo installatori firmati dallo stesso editore.
- Gli installatori non sono nel backup del modulo: dopo un ripristino si ripubblicano.


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
