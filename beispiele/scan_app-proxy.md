# Container-Scan: app-proxy

- Image: nginx:1.31-alpine (sha256:713fc2ebfd92)  
- OS: Alpine Linux v3.24  
- Zeitpunkt: 2026-11-13 11:39  
- Scanner: container-security-scan 0.2.2  
- Datenbank: OSV, Stand 2026-11-13 03:23 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**2 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-4738** (HIGH) in zlib 1.3.2-r1 – behoben in 1.4-r0 – genutzt von nginx:80
- **CVE-2026-125350** (HIGH KEV) in libxslt 1.1.43-r3 – behoben in 1.1.43-r4 – genutzt von – – **aktiv ausgenutzt** (KEV seit 2026-11-10)

Gefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| nginx:80 | nginx 1.31.8 | Port 80/tcp (alle) veröffentlicht als 127.0.0.1:8080 (nur lokal – vermutlich hinter einem Reverse Proxy auf dem Host); Konfiguration: listen 80 server_name shop.example.org root /srv/app/public; Backend http://app-node:3000 -> Container app-node; Backend app-php:9000 -> Container app-php |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 0 | 1 | 1 | 0 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 0 | 3 | 1 | 0 | 0 |

## Befunde (5 von 6; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2026-4738 | zlib | 1.3.2-r1 | 1.4-r0 | nginx:80 | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |
| 1 | MEDIUM | CVE-2025-1695 | nginx | 1.31.8 | kein Fix | nginx:80 | NGINX Unit Java Vulnerability |
| 4 | HIGH KEV | CVE-2026-125350 | libxslt | 1.1.43-r3 | 1.1.43-r4 | – | Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to |
| 4 | HIGH | CVE-2026-87636 | libxslt | 1.1.43-r3 | 1.1.43-r4 | – | Type confusion in XML in Google Chrome prior to 153.0.8010.36 allowed a remote attacker to |
| 4 | HIGH | CVE-2026-9947 | libxslt | 1.1.43-r3 | 1.1.43-r4 | – | Use after free in XML in Google Chrome prior to 148.0.7778.216 allowed a remote attacker t |

KEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).

## Nicht automatisch geprüft – bitte gesondert prüfen

Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. Für sie gibt es in OSV keine (eindeutigen) Paketdaten.

| Typ | Name | Version | Fundort | Genutzt von |
|---|---|---|---|---|
| host | linux-kernel | 6.12.8+ | Host | Host |
| host | docker-engine | 29.1.3 | Host | Host |
| host | containerd | 2.2.1 | Host | Host |
| host | runc | 1.3.4-0ubuntu1~24.04.1 | Host | Host |
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
ID:        1226883f32da0fb54ffe7f74e794fdefc7c01c2ba90d24777287b93b10e3d07f
Gestartet: 2026-11-13T11:39:10.802902704Z
Kommando:  ["/docker-entrypoint.sh"] ["nginx", "-g", "daemon off;"]
Mounts:    /workspaces/container-security-scan/dla-marbach/container-security-scan/beispiele/umgebung/nginx.conf->/etc/nginx/conf.d/default.conf
Host:      Kernel 6.12.8+
```

### Laufende Prozesse

```
PID                 USER                COMMAND
3504                root                nginx: master process nginx -g daemon off;
3580                101                 nginx: worker process
3581                101                 nginx: worker process
4376                nobody              timeout 50 httpd -v
4415                nobody              timeout 50 apache2 -v
4456                nobody              timeout 50 java -XX:-UsePerfData -version
4498                nobody              timeout 50 mariadbd --version
4538                nobody              timeout 50 mysqld --version
4578                nobody              timeout 50 postgres --version
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

- PID 20 (/usr/sbin/nginx): /[aio] (deleted)
- PID 21 (/usr/sbin/nginx): /[aio] (deleted)

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
