# Container-Scan: app-proxy

- Image: nginx:1.31-alpine (sha256:b50897d5c7b1)  
- OS: Alpine Linux v3.24  
- Zeitpunkt: 2026-11-25 09:54  
- Scanner: container-security-scan 1.2.0  
- Datenbank: OSV, Stand 2026-11-24 13:43 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**1 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-4738** (HIGH) in zlib 1.3.2-r1 – behoben in 1.4-r0 – genutzt von nginx:80

Gefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| nginx:80 | nginx 1.31.10 | Port 80/tcp (alle) veröffentlicht als 0.0.0.0:8080, :::8080; Konfiguration: listen 80 server_name shop.example.org root /srv/app/public; Backend http://app-node:3000 -> Container app-node; Backend app-php:9000 -> Container app-php |

## Webadressen

Aus der Konfiguration der Webserver (server_name, ServerName/ServerAlias, listen bzw. vHost, TLS) in diesem Container, in anderen Containern und direkt auf dem Host; Pfade, die ein Proxy weiterleitet, beim Ziel. „Erreichbar“ wie der Port, über den die Anfrage hereinkommt.

| Webadresse | Erreichbar | Dienst | Weg | Website | Docroot / Ziel |
|---|---|---|---|---|---|
| http://shop.example.org:8080/ | ja | nginx:80 | nginx:80 | /etc/nginx/conf.d/default.conf | /srv/app/public |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 0 | 1 | 1 | 0 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 0 | 0 | 0 | 0 | 0 |

## Befunde (2 von 2; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2026-4738 | zlib | 1.3.2-r1 | 1.4-r0 | nginx:80 | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |
| 1 | MEDIUM | CVE-2025-1695 | nginx | 1.31.10 | kein Fix | nginx:80 | NGINX Unit Java Vulnerability |

## Nicht automatisch geprüft – bitte gesondert prüfen

Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. Für sie gibt es in OSV keine (eindeutigen) Paketdaten.

| Typ | Name | Version | Fundort | Genutzt von |
|---|---|---|---|---|
| host | linux-kernel | 7.0.14-linuxkit | Host | Host |
| host | docker-engine | 29.10.0 | Host | Host |
| host | containerd | v2.4.2 | Host | Host |
| host | runc | 1.5.3 | Host | Host |
| host | docker-init | 0.19.0 | Host | Host |

## Anhang

### Komponenten (gesamt / von Diensten mit offenem Port genutzt)

| Typ | gesamt | genutzt | dev |
|---|---|---|---|
| host | 5 | 0 | 0 |
| os-paket | 72 | 6 | 0 |
| server | 1 | 1 | 0 |

### Container

```
ID:        ae32e7bf0315e9786c39887dc629b5d06037f27510746920aff5e4503c8c281e
Gestartet: 2026-11-25T09:54:13.184330507Z
Kommando:  ["/docker-entrypoint.sh"] ["nginx", "-g", "daemon off;"]
Mounts:    /w/beispiele/umgebung/nginx.conf->/etc/nginx/conf.d/default.conf
Host:      Kernel 7.0.14-linuxkit
```

### Laufende Prozesse

```
PID                 USER                COMMAND
6360                root                nginx: master process nginx -g daemon off;
6429                nginx               nginx: worker process
6430                nginx               nginx: worker process
6431                nginx               nginx: worker process
6432                nginx               nginx: worker process
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

- PID 22 (/usr/sbin/nginx): /[aio] (deleted)
- PID 23 (/usr/sbin/nginx): /[aio] (deleted)
- PID 24 (/usr/sbin/nginx): /[aio] (deleted)
- PID 25 (/usr/sbin/nginx): /[aio] (deleted)

ACHTUNG: Diese Prozesse nutzen noch alte Dateiversionen – Dienst neu starten.

### Webserver-Konfiguration (Auszug)

```
--- /usr/sbin/nginx -T (Auszug)
# configuration file /etc/nginx/nginx.conf:
# configuration file /etc/nginx/mime.types:
# configuration file /etc/nginx/conf.d/default.conf:
server {
    listen 80;
    server_name shop.example.org;
    root /srv/app/public;
    location / {
        proxy_pass http://app-node:3000;
    location ~ \.php$ {
        fastcgi_pass app-php:9000;
# configuration file /etc/nginx/fastcgi_params:
```
