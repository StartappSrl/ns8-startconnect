# Correzioni a guacamole-server 1.6.0

Commit ufficiali del ramo `staging/1.6.1` di [apache/guacamole-server](https://github.com/apache/guacamole-server)
(licenza Apache-2.0), applicati da `build-images.sh` prima della compilazione:

- `0001` GUACAMOLE-2072: caricamento di RAIL e dei plugin statici nella callback LoadChannels
  (prerequisito della correzione successiva).
- `0002` GUACAMOLE-2328: inizializzazione della GDI di FreeRDP in PostConnect. Senza questa
  correzione guacd 1.6.0 va in crash (`gdi_init_ex`) su ogni connessione RDP con FreeRDP 3.31 e successivi.

Il conflitto della seconda patch con la 1.6.0 è stato risolto mantenendo solo lo spostamento di
`gdi_init`. Verificato con FreeRDP 3.32.2 su sessioni RDP reali. Da rimuovere al rilascio di guacd 1.6.1.
