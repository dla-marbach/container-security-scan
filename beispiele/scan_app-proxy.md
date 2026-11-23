# Container-Scan: app-proxy

- Image: nginx:1.31-alpine (sha256:fb4658584bd9)  
- OS: Alpine Linux v3.24  
- Zeitpunkt: 2026-11-23 16:38  
- Scanner: container-security-scan 0.5.1  
- Datenbank: OSV, Stand 2026-11-23 12:40 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**9 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-107496** (HIGH) in libcrypto3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-88823** (HIGH) in libcrypto3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-95691** (HIGH) in libcrypto3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-95692** (HIGH) in libcrypto3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-107496** (HIGH) in libssl3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-88823** (HIGH) in libssl3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-95691** (HIGH) in libssl3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-95692** (HIGH) in libssl3 3.5.9-r0 – behoben in 3.5.9-r1 – genutzt von nginx:80
- **CVE-2026-4738** (HIGH) in zlib 1.3.2-r1 – behoben in 1.4-r0 – genutzt von nginx:80

Gefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| nginx:80 | nginx 1.31.9 | Port 80/tcp (alle) veröffentlicht als 127.0.0.1:8080 (nur lokal – vermutlich hinter einem Reverse Proxy auf dem Host); Konfiguration: listen 80 server_name shop.example.org root /srv/app/public; Backend http://app-node:3000 -> Container app-node; Backend app-php:9000 -> Container app-php |

## Webadressen

Aus der Konfiguration der Webserver (server_name, ServerName/ServerAlias, listen bzw. vHost, TLS) in diesem Container, in anderen Containern und direkt auf dem Host; Pfade, die ein Proxy weiterleitet, beim Ziel. „Erreichbar“ wie der Port, über den die Anfrage hereinkommt.

| Webadresse | Erreichbar | Dienst | Weg | Website | Docroot / Ziel |
|---|---|---|---|---|---|
| http://shop.example.org:8080/ | ja | nginx:80 | nginx:80 | /etc/nginx/conf.d/default.conf | /srv/app/public |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 0 | 9 | 3 | 0 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 0 | 1 | 0 | 0 | 0 |

## Befunde (13 von 13; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2026-107496 | libcrypto3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: Encrypting a CMS message to an EC certificate whose group order |
| 1 | HIGH | CVE-2026-88823 | libcrypto3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: The AES-GCM-SIV implementation treats a zero-length Additional |
| 1 | HIGH | CVE-2026-95691 | libcrypto3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: A retransmitted QUIC CRYPTO frame can release packet storage |
| 1 | HIGH | CVE-2026-95692 | libcrypto3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: Setting an AES-GCM-SIV IV shorter than the expected nonce |
| 1 | HIGH | CVE-2026-107496 | libssl3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: Encrypting a CMS message to an EC certificate whose group order |
| 1 | HIGH | CVE-2026-88823 | libssl3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: The AES-GCM-SIV implementation treats a zero-length Additional |
| 1 | HIGH | CVE-2026-95691 | libssl3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: A retransmitted QUIC CRYPTO frame can release packet storage |
| 1 | HIGH | CVE-2026-95692 | libssl3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: Setting an AES-GCM-SIV IV shorter than the expected nonce |
| 1 | HIGH | CVE-2026-4738 | zlib | 1.3.2-r1 | 1.4-r0 | nginx:80 | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |
| 1 | MEDIUM | CVE-2026-88822 | libcrypto3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: QUIC, when performing automated peer detection, may allow |
| 1 | MEDIUM | CVE-2026-88822 | libssl3 | 3.5.9-r0 | 3.5.9-r1 | nginx:80 | Issue summary: QUIC, when performing automated peer detection, may allow |
| 1 | MEDIUM | CVE-2025-1695 | nginx | 1.31.9 | kein Fix | nginx:80 | NGINX Unit Java Vulnerability |
| 4 | HIGH | CVE-2026-86144 | libxml2 | 2.13.9-r2 | 2.13.9-r3 | – | In xinclude in libxml2 before 2.15.4, xmlXIncludeProcess and xmlXIncludeProcessTree do not |

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
ID:        11ebb40fa95e862cd506afbc74a9e0b4687cb4950041de2eebe217e03de28155
Gestartet: 2026-11-23T16:38:29.310415256Z
Kommando:  ["/docker-entrypoint.sh"] ["nginx", "-g", "daemon off;"]
Mounts:    /w/beispiele/umgebung/nginx.conf->/etc/nginx/conf.d/default.conf
Host:      Kernel 7.0.14-linuxkit
```

### Laufende Prozesse

```
PID                 USER                COMMAND
746                 root                nginx: master process nginx -g daemon off;
802                 101                 nginx: worker process
803                 101                 nginx: worker process
804                 101                 nginx: worker process
805                 101                 nginx: worker process
1239                root                timeout 50 /usr/sbin/nginx -v
1269                nobody              timeout 50 node -e console.log(JSON.stringify({exe: require("fs").realpathSync(process.execPath), versions: process.versions}))
1300                nobody              timeout 50 php -r $r = array("exe" => realpath(PHP_BINARY) ?: PHP_BINARY, "version" => PHP_VERSION, "sapi" => PHP_SAPI, "ext" => array(), "libs" => array()); foreach (get_loaded_extensions() as $e) { $v = phpversion($e); if ($v && strpos($v, PHP_VERSION) === false && $e !== "dom") $r["ext"][$e] = $v; } if (defined("OPENSSL_VERSION_TEXT")) { $p = explode(" ", OPENSSL_VERSION_TEXT); $r["libs"][strtolower($p[0])] = $p[1]; } if (function_exists("curl_version")) { $c = curl_version(); $r["libs"]["curl"] = $c["version"]; } if (defined("LIBXML_DOTTED_VERSION")) $r["libs"]["libxml2"] = LIBXML_DOTTED_VERSION; if (defined("PCRE_VERSION")) { $p = explode(" ", PCRE_VERSION); $r["libs"]["pcre2"] = $p[0]; } if (defined("INTL_ICU_VERSION")) $r["libs"]["icu"] = INTL_ICU_VERSION; if (class_exists("SQLite3")) { $s = SQLite3::version(); $r["libs"]["sqlite"] = $s["versionString"]; } if (defined("SODIUM_LIBRARY_VERSION")) $r["libs"]["libsodium"] = SODIUM_LIBRARY_VERSION; if (defined("ZLIB_VERSION")) $r["libs"]["zlib"] = ZLIB_VERSION; echo json_encode($r);
1329                nobody              timeout 50 python3 -I -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
1359                nobody              timeout 50 python3 -E -s -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
1388                nobody              timeout 50 python -I -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
1419                nobody              timeout 50 python -E -s -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
1448                nobody              timeout 50 nginx -v
1478                nobody              timeout 50 httpd -v
1507                nobody              timeout 50 apache2 -v
1537                nobody              timeout 50 java -XX:-UsePerfData -version
1568                nobody              timeout 50 mariadbd --version
1597                nobody              timeout 50 mysqld --version
1627                nobody              timeout 50 postgres --version
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

- PID 21 (/usr/sbin/nginx): /[aio] (deleted)
- PID 22 (/usr/sbin/nginx): /[aio] (deleted)
- PID 23 (/usr/sbin/nginx): /[aio] (deleted)
- PID 24 (/usr/sbin/nginx): /[aio] (deleted)

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
