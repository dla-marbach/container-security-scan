# Container-Scan: app-proxy

- Image: nginx:1.31-alpine (sha256:713fc2ebfd92)  
- OS: Alpine Linux v3.24  
- Zeitpunkt: 2026-11-07 21:15  
- Scanner: container-security-scan 0.2.0  
- Datenbank: OSV, Stand 2026-11-07 14:13 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**1 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-4738** (HIGH) in zlib 1.3.2-r1 – behoben in 1.4-r0 – genutzt von nginx:80

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
| P4 nicht genutzt / dev | 0 | 0 | 0 | 0 | 0 |

## Befunde (2 von 2; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2026-4738 | zlib | 1.3.2-r1 | 1.4-r0 | nginx:80 | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |
| 1 | MEDIUM | CVE-2025-1695 | nginx | 1.31.8 | kein Fix | nginx:80 | NGINX Unit Java Vulnerability |

## Nicht automatisch geprüft – bitte gesondert prüfen

Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. Für sie gibt es in OSV keine (eindeutigen) Paketdaten.

| Typ | Name | Version | Fundort | Genutzt von |
|---|---|---|---|---|
| host | linux-kernel | 6.18.44-fc-v310 | Host | Host |
| host | docker-engine | 29.9.2 | Host | Host |
| host | containerd | v2.4.2 | Host | Host |
| host | runc | 1.5.2 | Host | Host |
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
ID:        12c7ba5a9394522fd2bb6cc4579bb556b687e83d8ae6e2f8fae687a5c8c01c82
Gestartet: 2026-11-07T21:15:09.156553722Z
Kommando:  ["/docker-entrypoint.sh"] ["nginx", "-g", "daemon off;"]
Mounts:    /home/user/container-security-scan/beispiele/umgebung/nginx.conf->/etc/nginx/conf.d/default.conf
Host:      Kernel 6.18.44-fc-v310
```

### Laufende Prozesse

```
PID                 USER                COMMAND
2212                root                nginx: master process nginx -g daemon off;
2268                redis               nginx: worker process
2269                redis               nginx: worker process
2270                redis               nginx: worker process
2271                redis               nginx: worker process
2839                nobody              timeout 50 python -I -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
2868                nobody              timeout 50 python -E -s -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
2897                nobody              timeout 50 nginx -v
2926                nobody              timeout 50 httpd -v
2956                nobody              timeout 50 apache2 -v
2986                nobody              timeout 50 java -XX:-UsePerfData -version
3017                nobody              timeout 50 mariadbd --version
3046                nobody              timeout 50 mysqld --version
3077                nobody              timeout 50 postgres --version
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

- PID 20 (/usr/sbin/nginx): /[aio] (deleted)
- PID 21 (/usr/sbin/nginx): /[aio] (deleted)
- PID 22 (/usr/sbin/nginx): /[aio] (deleted)
- PID 23 (/usr/sbin/nginx): /[aio] (deleted)

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
