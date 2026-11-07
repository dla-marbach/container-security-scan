# Container-Scan: app-php

- Image: php:8.3.30-fpm-bookworm (sha256:e7ca6c7f5a59)  
- OS: Debian GNU/Linux 12 (bookworm)  
- Zeitpunkt: 2026-11-07 21:15  
- Scanner: container-security-scan 0.2.0  
- Datenbank: OSV, Stand 2026-11-07 14:12 UTC (daten)  
- Erfassung: OS-Pakete dpkg; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer); 1 Kernel-Pakete nicht geprüft (Container nutzen den Kernel des Hosts)

## Ergebnis

**Warnung:** Öffentlicher Dienst php-fpm:9000 läuft als root (UID 0, ohne unprivilegierte Worker) – eine Lücke darin gibt root im Container; Benutzer setzen (user:, USER) oder non-root-Image  
**Warnung:** Supportende: jquery 1.12.4 (jquery 1, Datum unbekannt; /srv/app/public/js/jquery-1.12.4.min.js)  
**65 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-111497** (CRITICAL KEV) in libbrotli1 1.0.9-2+b6 – behoben in 1.0.9-2+deb12u1 – genutzt von php-fpm:9000 – **aktiv ausgenutzt** (KEV seit 2026-10-27)
- **CVE-2026-33845** (CRITICAL) in libgnutls30 3.7.9-2+deb12u6 – behoben in 3.7.9-2+deb12u7 – genutzt von php-fpm:9000
- **CVE-2026-42010** (CRITICAL) in libgnutls30 3.7.9-2+deb12u6 – behoben in 3.7.9-2+deb12u7 – genutzt von php-fpm:9000
- **CVE-2026-34182** (CRITICAL) in libssl3 3.0.19-1~deb12u2 – behoben in 3.0.20-1~deb12u2 – genutzt von php-fpm:9000
- **CVE-2026-75803** (CRITICAL) in libssl3 3.0.19-1~deb12u2 – behoben in 3.0.22-1~deb12u1 – genutzt von php-fpm:9000
- **CVE-2025-14179** (CRITICAL) in php 8.3.30 – behoben in 8.3.31 – genutzt von php-fpm:9000
- **CVE-2026-109618** (CRITICAL KEV) in php 8.3.30 – behoben in 8.3.36 – genutzt von php-fpm:9000 – **aktiv ausgenutzt** (KEV seit 2026-10-26)
- **CVE-2026-109619** (CRITICAL KEV) in php 8.3.30 – behoben in 8.3.36 – genutzt von php-fpm:9000 – **aktiv ausgenutzt** (KEV seit 2026-10-26)
- **CVE-2026-17543** (CRITICAL) in php 8.3.30 – behoben in 8.3.33 – genutzt von php-fpm:9000
- **CVE-2026-6722** (CRITICAL) in php 8.3.30 – behoben in 8.3.31 – genutzt von php-fpm:9000
- **CVE-2026-7261** (CRITICAL) in php 8.3.30 – behoben in 8.3.31 – genutzt von php-fpm:9000
- **CVE-2022-29248** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.3 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2022-31042** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.4 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2022-31043** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.4 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2022-31090** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.5 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2022-31091** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.5 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2026-69246** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.15.2 – genutzt von php-fpm:9000 (Docroot unbekannt)
- **CVE-2025-15281** (HIGH) in libc-bin 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-0861** (HIGH) in libc-bin 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-0915** (HIGH) in libc-bin 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-4046** (HIGH) in libc-bin 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-4437** (HIGH) in libc-bin 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2025-15281** (HIGH) in libc6 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-0861** (HIGH) in libc6 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-0915** (HIGH) in libc6 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-4046** (HIGH) in libc6 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-4437** (HIGH) in libc6 2.36-9+deb12u13 – behoben in 2.36-9+deb12u14 – genutzt von php-fpm:9000
- **CVE-2026-5773** (HIGH) in libcurl4 7.88.1-10+deb12u14 – behoben in 7.88.1-10+deb12u15 – genutzt von php-fpm:9000
- **CVE-2026-33846** (HIGH) in libgnutls30 3.7.9-2+deb12u6 – behoben in 3.7.9-2+deb12u7 – genutzt von php-fpm:9000
- **CVE-2026-3833** (HIGH) in libgnutls30 3.7.9-2+deb12u6 – behoben in 3.7.9-2+deb12u7 – genutzt von php-fpm:9000
- … weitere 35 in der Tabelle unten

Gefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.

Nicht gezählt (wären sonst relevant):
- CVE-2026-17545 (HIGH) in php 8.3.30 – betrifft laut Titel nur Windows

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| php-fpm:9000 | php-fpm 8.3.30 | Port 9000/tcp (alle) öffentlich über nginx:80 in app-proxy; Arbeitsverzeichnis: /var/www/html |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 25 | 100 | 102 | 70 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 32 | 156 | 165 | 645 | 0 |

## Befunde (486 von 1295; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | CRITICAL KEV | CVE-2026-111497 | libbrotli1 | 1.0.9-2+b6 | 1.0.9-2+deb12u1 | php-fpm:9000 | A buffer overflow vulnerability in the Brotli decoder (c/dec/decode.c) in Google Brotli ve |
| 1 | CRITICAL | CVE-2026-33845 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw in GnuTLS DTLS handshake parsing allows malformed fragments with zero length and no |
| 1 | CRITICAL | CVE-2026-42010 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. Servers configured with RSA-PSK (Rivest–Shamir–Adleman – Pre-S |
| 1 | CRITICAL | CVE-2026-34182 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue Summary: Cryptographic Message Services (CMS) processing fails to perform sufficient |
| 1 | CRITICAL | CVE-2026-75803 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty ciphertext can repor |
| 1 | CRITICAL | CVE-2025-14179 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | SQL injection in pdo_firebird via NUL bytes in quoted strings |
| 1 | CRITICAL KEV | CVE-2026-109618 | php | 8.3.30 | 8.3.36 | php-fpm:9000 | RCE via OOM corruption |
| 1 | CRITICAL KEV | CVE-2026-109619 | php | 8.3.30 | 8.3.36 | php-fpm:9000 | RCE via stale global state |
| 1 | CRITICAL | CVE-2026-17543 | php | 8.3.30 | 8.3.33 | php-fpm:9000 | SQL injection in ext-pgsql via E'...' backslash breakout |
| 1 | CRITICAL | CVE-2026-6722 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | Use-After-Free in SOAP using Apache map |
| 1 | CRITICAL | CVE-2026-7261 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | SoapServer session-persisted object use-after-free via SOAP header fault |
| 1 | CRITICAL | CVE-2026-5450 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C L |
| 1 | CRITICAL | CVE-2026-5450 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C L |
| 1 | CRITICAL | CVE-2026-10536 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A use-after-free vulnerability exists in libcurl when an application configures an HTTP/2  |
| 1 | CRITICAL | CVE-2026-11856 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | Successfully using libcurl to do a transfer to a specific HTTP origin (`hostA`) with **Dig |
| 1 | CRITICAL | CVE-2026-18924 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A flaw in libcurl's handling of HTTP/2 Server Push streams, when the parent handle is set  |
| 1 | CRITICAL | CVE-2026-19931 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A flaw in libcurl makes it wrongly reuse an HTTP connection setup for a given hostname usi |
| 1 | CRITICAL | CVE-2026-86414 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | An HTTP proxy can trick libcurl into sending the origin's credentials (Basic password, or  |
| 1 | CRITICAL | CVE-2026-8924 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A flaw in curl’s cookie parsing logic allows a malicious HTTP server to set "super cookies |
| 1 | CRITICAL | CVE-2026-8927 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When reusing a libcurl handle for sequential transfers driven by environment-variable prox |
| 1 | CRITICAL | CVE-2026-92388 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When an FTP wildcard `LIST` operation fails, libcurl omits the restoration path meant for  |
| 1 | CRITICAL | CVE-2025-7458 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | An integer overflow in the sqlite3KeyInfoFromExprList function in SQLite versions 3.39.2 t |
| 1 | CRITICAL | CVE-2026-6653 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | Use After Free in libxml2's xmlParseInternalSubset from GNOME libxml2 version 2.9.11 to 2. |
| 1 | CRITICAL | CVE-2023-45853 | zlib1g | 1:1.2.13.dfsg-1 | kein Fix | php-fpm:9000 | MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overfl |
| 1 | CRITICAL | CVE-2026-85091 | zlib1g | 1:1.2.13.dfsg-1 | kein Fix | php-fpm:9000 | zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz |
| 1 | HIGH | CVE-2022-29248 | guzzlehttp/guzzle | 7.4.0 | 7.4.3 | php-fpm:9000 (Docroot unbekannt) | Cross-domain cookie leakage in Guzzle |
| 1 | HIGH | CVE-2022-31042 | guzzlehttp/guzzle | 7.4.0 | 7.4.4 | php-fpm:9000 (Docroot unbekannt) | Failure to strip the Cookie header on change in host or HTTP downgrade |
| 1 | HIGH | CVE-2022-31043 | guzzlehttp/guzzle | 7.4.0 | 7.4.4 | php-fpm:9000 (Docroot unbekannt) | Failure to strip the Cookie header on change in host or HTTP downgrade |
| 1 | HIGH | CVE-2022-31090 | guzzlehttp/guzzle | 7.4.0 | 7.4.5 | php-fpm:9000 (Docroot unbekannt) | CURLOPT_HTTPAUTH option not cleared on change of origin |
| 1 | HIGH | CVE-2022-31091 | guzzlehttp/guzzle | 7.4.0 | 7.4.5 | php-fpm:9000 (Docroot unbekannt) | Change in port should be considered a change in origin |
| 1 | HIGH | CVE-2026-69246 | guzzlehttp/guzzle | 7.4.0 | 7.15.2 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Noncanonical host can bypass host-based checks |
| 1 | HIGH | CVE-2025-15281 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling wordexp with WRDE_REUSE in conjunction with WRDE_APPEND in the GNU C Library versi |
| 1 | HIGH | CVE-2026-0861 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Passing too large an alignment to the memalign suite of functions (memalign, posix_memalig |
| 1 | HIGH | CVE-2026-0915 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the  |
| 1 | HIGH | CVE-2026-4046 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an as |
| 1 | HIGH | CVE-2026-4437 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 1 | HIGH | CVE-2025-15281 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling wordexp with WRDE_REUSE in conjunction with WRDE_APPEND in the GNU C Library versi |
| 1 | HIGH | CVE-2026-0861 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Passing too large an alignment to the memalign suite of functions (memalign, posix_memalig |
| 1 | HIGH | CVE-2026-0915 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the  |
| 1 | HIGH | CVE-2026-4046 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an as |
| 1 | HIGH | CVE-2026-4437 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 1 | HIGH | CVE-2026-5773 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | libcurl might in some circumstances reuse the wrong connection for SMB(S) transfers.  libc |
| 1 | HIGH | CVE-2026-33846 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A heap buffer overflow vulnerability exists in the DTLS handshake fragment reassembly logi |
| 1 | HIGH | CVE-2026-3833 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. This vulnerability occurs because gnutls performs case-sensiti |
| 1 | HIGH | CVE-2026-42009 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. A remote attacker could exploit an issue in the Datagram Trans |
| 1 | HIGH | CVE-2026-42011 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. This vulnerability occurs because permitted name constraints w |
| 1 | HIGH | CVE-2026-42012 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. A remote attacker could exploit this vulnerability by presenti |
| 1 | HIGH | CVE-2026-42013 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. When validating certificates, an oversized Subject Alternative |
| 1 | HIGH | CVE-2026-5260 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in libgnutls. A remote attacker, by sending an extremely short premaster  |
| 1 | HIGH | CVE-2026-40355 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is a NULL pointer dereference if an appl |
| 1 | HIGH | CVE-2026-40356 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is an integer underflow and resultant ou |
| 1 | HIGH | CVE-2026-40355 | libk5crypto3 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is a NULL pointer dereference if an appl |
| 1 | HIGH | CVE-2026-40356 | libk5crypto3 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is an integer underflow and resultant ou |
| 1 | HIGH | CVE-2026-40355 | libkrb5-3 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is a NULL pointer dereference if an appl |
| 1 | HIGH | CVE-2026-40356 | libkrb5-3 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is an integer underflow and resultant ou |
| 1 | HIGH | CVE-2026-40355 | libkrb5support0 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is a NULL pointer dereference if an appl |
| 1 | HIGH | CVE-2026-40356 | libkrb5support0 | 1.20.1-2+deb12u4 | 1.20.1-2+deb12u5 | php-fpm:9000 | In MIT Kerberos 5 (aka krb5) before 1.22.3, there is an integer underflow and resultant ou |
| 1 | HIGH | CVE-2026-27135 | libnghttp2-14 | 1.52.0-1+deb12u2 | 1.52.0-1+deb12u3 | php-fpm:9000 | nghttp2 is an implementation of the Hypertext Transfer Protocol version 2 in C. Prior to v |
| 1 | HIGH | CVE-2026-107161 | libsasl2-2 | 2.1.28+dfsg-10 | 2.1.28+dfsg-10+deb12u1 | php-fpm:9000 | A heap-based buffer overflow flaw was found in Cyrus SASL. The add_to_challenge() function |
| 1 | HIGH | CVE-2026-58050 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | libssh2 through 1.11.1 reads an attacker-controlled 32-bit attribute count from a publicke |
| 1 | HIGH | CVE-2026-58051 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | libssh2 through 1.11.1 grows its publickey list with SSH2_REALLOC but does not zero-initia |
| 1 | HIGH | CVE-2026-66032 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | libssh2 through 1.11.1, fixed in commit 5e47761, contains a double-free vulnerability in t |
| 1 | HIGH | CVE-2026-66034 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | libssh2 through 1.11.1, fixed in commit a13bb6c, contains a missing bounds check vulnerabi |
| 1 | HIGH | CVE-2026-7598 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | A security vulnerability has been detected in libssh2 up to 1.11.1. The impacted element i |
| 1 | HIGH | CVE-2026-34180 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: Parsing a crafted DER-encoded ASN.1 structure with a primitive element whos |
| 1 | HIGH | CVE-2026-45445 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: When an application drives an AES-OCB context through the public EVP_Cipher |
| 1 | HIGH | CVE-2026-45447 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: A specially crafted PKCS#7 or S/MIME signed message could trigger a use-aft |
| 1 | HIGH | CVE-2026-54874 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: Receiving a DTLS record for a future epoch while a handshake is in progress |
| 1 | HIGH | CVE-2026-63072 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based on querying |
| 1 | HIGH | CVE-2026-63076 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: OpenSSL CMP password based protection verification only checks whether the  |
| 1 | HIGH | CVE-2026-7383 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: A signed integer overflow when sizing the destination buffer for Unicode ou |
| 1 | HIGH | CVE-2026-84782 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: The DTLS retransmission logic does not correctly handle a handshake message |
| 1 | HIGH | CVE-2026-9076 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: When CMS password-based decryption (RFC 3211 / PWRI key unwrap) processes a |
| 1 | HIGH | CVE-2026-17545 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | [nicht gezählt: betrifft laut Titel nur Windows] PHP on Windows: Reserved Device Names Are Not Rejected Before File/Stream I/O which can ca |
| 1 | HIGH | CVE-2026-6735 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | XSS within PHP-FPM status endpoint |
| 1 | HIGH | CVE-2026-7258 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | Out-of-bounds read in urldecode() on NetBSD |
| 1 | HIGH | CVE-2026-7262 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | NULL pointer dereference in SOAP apache:Map decoder with missing <value> |
| 1 | HIGH | CVE-2026-7568 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | Signed integer overflow in metaphone() |
| 1 | HIGH | CVE-2026-91765 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | SOAP: Unbounded Recursion in Server-Side cleanup_xml_node |
| 1 | HIGH | CVE-2026-19499 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the |
| 1 | HIGH | CVE-2026-5435 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 1 | HIGH | CVE-2026-5928 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling the ungetwc function on a FILE stream with wide characters encoded in a character  |
| 1 | HIGH | CVE-2026-6791 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | When expanding paths that begin with a tilde (~) followed by a username, the internal pars |
| 1 | HIGH | CVE-2026-84243 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE |
| 1 | HIGH | CVE-2026-19499 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the |
| 1 | HIGH | CVE-2026-5435 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 1 | HIGH | CVE-2026-5928 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling the ungetwc function on a FILE stream with wide characters encoded in a character  |
| 1 | HIGH | CVE-2026-6791 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | When expanding paths that begin with a tilde (~) followed by a username, the internal pars |
| 1 | HIGH | CVE-2026-84243 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE |
| 1 | HIGH | CVE-2026-107928 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When curl is built with GnuTLS, a malicious WebSocket server can make curl send memory pas |
| 1 | HIGH | CVE-2026-12064 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When a user invokes curl using a schemeless URL combined with `--proto-default` sftp (or s |
| 1 | HIGH | CVE-2026-13608 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A flaw in the libcurl SASL negotiation for LDAP authentication allows an incomplete handsh |
| 1 | HIGH | CVE-2026-6276 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | Using libcurl, when a custom `Host:` header is first set for an HTTP request and a second  |
| 1 | HIGH | CVE-2026-80230 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When `CURLOPT_PINNEDPUBLICKEY` is configured alongside options that disable standard peer  |
| 1 | HIGH | CVE-2026-82209 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When libpsl support is enabled, libcurl fails to enforce the Public Suffix List boundary c |
| 1 | HIGH | CVE-2026-8286 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A vulnerability exists where a new transfer that uses STARTTLS to upgrade the connection m |
| 1 | HIGH | CVE-2026-86409 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | Setting `CURLOPT_AWS_SIGV4` to NULL but does not disable SigV4 authentication, contrary to |
| 1 | HIGH | CVE-2026-86410 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A flaw in the curl command line tool's logic makes it only set SSH host verification optio |
| 1 | HIGH | CVE-2026-87864 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | Enabling `CURLOPT_CRLF` causes curl to advertise the raw input byte count in the `IMAP APP |
| 1 | HIGH | CVE-2026-87865 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When libcurl uses libssh2 with a hashed `known_hosts` file, an unrelated initial entry can |
| 1 | HIGH | CVE-2026-8932 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl would reuse a previously created connection even when some mTLS config related opt |
| 1 | HIGH | CVE-2026-92389 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl's TFTP state machine fails to validate state transitions against the requested tra |
| 1 | HIGH | CVE-2026-92390 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When invoked with `--remote-header-name` (`-J`), curl fails to preserve its documented ant |
| 1 | HIGH | CVE-2026-92391 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A deeply nested multipart MIME structure constructed via the public API causes a stack ove |
| 1 | HIGH | CVE-2026-94266 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl could accidentally return a URL for `curl_easy_getinfo()`'s `CURLINFO_EFFECTIVE_UR |
| 1 | HIGH | CVE-2026-102010 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 1 | HIGH | CVE-2026-95619 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 1 | HIGH | CVE-2023-2953 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | A vulnerability was found in openldap. This security flaw causes a null pointer dereferenc |
| 1 | HIGH | CVE-2026-112060 | librtmp1 | 2.4+20151223.gitfa8646d.1-2+b2 | kein Fix | php-fpm:9000 | librtmp in RTMPDump through 2.6 contains an out-of-bounds read and heap out-of-bounds writ |
| 1 | HIGH | CVE-2026-11824 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.53.2 contains a heap-based buffer overflow vulnerability in the FTS5 full- |
| 1 | HIGH | CVE-2026-119373 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 built with FTS5 contains a heap buffer overflow in fts5MergeRowidList |
| 1 | HIGH | CVE-2026-119374 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 built with FTS5 contains a heap buffer overflow in fts5DoSecureDelete |
| 1 | HIGH | CVE-2026-119379 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 built with the session extension contains a heap buffer overflow vuln |
| 1 | HIGH | CVE-2026-119586 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite command-line shell through 3.54.1 contains a command injection vulnerability in the |
| 1 | HIGH | CVE-2026-102010 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 1 | HIGH | CVE-2026-95619 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 1 | HIGH | CVE-2025-13151 | libtasn1-6 | 4.19.0-2+deb12u1 | kein Fix | php-fpm:9000 | Stack-based buffer overflow in libtasn1 version: v4.20.0. The function fails to validate t |
| 1 | HIGH | CVE-2025-69720 | libtinfo6 | 6.4-4 | kein Fix | php-fpm:9000 | The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer over |
| 1 | HIGH | CVE-2026-74860 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | A flaw was found in libxml2 with Python bindings enabled. A remote attacker could exploit  |
| 1 | HIGH | CVE-2026-86138 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | In libxml2 before 2.15.4, xmlDictAddQString in dict.c has an integer overflow and resultan |
| 1 | HIGH | CVE-2026-86140 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | In libxml2 before 2.15.4, xmlSnprintfElements in valid.c has a strcat stack-based buffer o |
| 1 | HIGH | CVE-2026-86142 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | In libxml2 before 2.15.4, there is a heap-based buffer overflow in xmlXPtrEvalXPtrPart bec |
| 1 | HIGH | CVE-2026-86143 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | In xmlIO in libxml2 before 2.15.4, an inconsistency in xmlOutputWriteCallback and xmlBufUs |
| 1 | HIGH | CVE-2026-86144 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | In xinclude in libxml2 before 2.15.4, xmlXIncludeProcess and xmlXIncludeProcessTree do not |
| 1 | HIGH | CVE-2026-76844 | zlib1g | 1:1.2.13.dfsg-1 | kein Fix | php-fpm:9000 | zlib 1.2.11 through 1.3.2 contains a heap buffer overflow: after an underlying write() fai |
| 1 | MEDIUM | CVE-2026-55568 | guzzlehttp/guzzle | 7.4.0 | 7.12.1 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/guzzle: Silent HTTPS-Proxy Downgrade to Cleartext |
| 1 | MEDIUM | CVE-2026-55767 | guzzlehttp/guzzle | 7.4.0 | 7.12.1 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/guzzle: Dot-Only Cookie Domains Match All Hosts |
| 1 | MEDIUM | CVE-2026-59883 | guzzlehttp/guzzle | 7.4.0 | 7.12.3 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Cookie Disclosure and Injection via IP-Address Domains |
| 1 | MEDIUM | CVE-2026-67339 | guzzlehttp/guzzle | 7.4.0 | 7.14.2 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Proxy-Authorization headers can be sent to origin servers |
| 1 | MEDIUM | CVE-2026-67353 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Unbounded response cookies risk denial of service |
| 1 | MEDIUM | CVE-2026-67354 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000 (Docroot unbekannt) | Guzzle: URI fragments disclosed in redirect Referer headers |
| 1 | MEDIUM | CVE-2026-67355 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Host-only cookie scope is not preserved |
| 1 | MEDIUM | CVE-2026-69245 | guzzlehttp/guzzle | 7.4.0 | 7.15.2 | php-fpm:9000 (Docroot unbekannt) | Guzzle: Noncanonical cookie domain keeps subdomain scope |
| 1 | MEDIUM | CVE-2022-24775 | guzzlehttp/psr7 | 2.1.0 | 2.1.1 | php-fpm:9000 (Docroot unbekannt) | Improper Input Validation in guzzlehttp/psr7 |
| 1 | MEDIUM | CVE-2023-29197 | guzzlehttp/psr7 | 2.1.0 | 2.4.5 | php-fpm:9000 (Docroot unbekannt) | Improper header name validation in guzzlehttp/psr7 |
| 1 | MEDIUM | CVE-2026-48998 | guzzlehttp/psr7 | 2.1.0 | 2.10.2 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/psr7 has Host Confusion via Authority Reinterpretation |
| 1 | MEDIUM | CVE-2026-49214 | guzzlehttp/psr7 | 2.1.0 | 2.10.2 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/psr7 has CRLF Injection via URI Host Component |
| 1 | MEDIUM | CVE-2026-55766 | guzzlehttp/psr7 | 2.1.0 | 2.12.1 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/psr7: CRLF Injection in HTTP Start-Line Serialization |
| 1 | MEDIUM | CVE-2026-59882 | guzzlehttp/psr7 | 2.1.0 | 2.12.3 | php-fpm:9000 (Docroot unbekannt) | guzzlehttp/psr7: Host Confusion via Weak URI Host Validation |
| 1 | MEDIUM | CVE-2026-4438 | libc-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 1 | MEDIUM | CVE-2026-4438 | libc6 | 2.36-9+deb12u13 | 2.36-9+deb12u14 | php-fpm:9000 | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 1 | MEDIUM | CVE-2025-10148 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | curl's WebSocket code did not update the 32-bit mask pattern for each new outgoing frame a |
| 1 | MEDIUM | CVE-2025-14524 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer performs a  |
| 1 | MEDIUM | CVE-2025-14819 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | When doing TLS related transfers with reused easy or multi handles and altering the `CURLS |
| 1 | MEDIUM | CVE-2026-3783 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer performs a  |
| 1 | MEDIUM | CVE-2026-3784 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | curl would wrongly reuse an existing HTTP proxy connection doing CONNECT to a server, even |
| 1 | MEDIUM | CVE-2026-7168 | libcurl4 | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | php-fpm:9000 | Successfully using libcurl to do a transfer over a specific HTTP proxy (`proxyA`) with **D |
| 1 | MEDIUM | CVE-2026-42014 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in GnuTLS. The `gnutls_pkcs11_token_set_pin` function, used for changing  |
| 1 | MEDIUM | CVE-2026-42015 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. An off-by-one error exists in the PKCS#12 bag element bounds c |
| 1 | MEDIUM | CVE-2026-34743 | liblzma5 | 5.4.1-1 | 5.4.1-1+deb12u1 | php-fpm:9000 | XZ Utils provide a general-purpose data-compression library plus command-line tools. Prior |
| 1 | MEDIUM | CVE-2025-15661 | libssh2-1 | 1.10.0-3+b1 | 1.10.0-3+deb12u1 | php-fpm:9000 | libssh2 through 1.11.1, fixed in commit 2dae302, contains an out-of-bounds heap read vulne |
| 1 | MEDIUM | CVE-2026-35189 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: A certificate with many nameRelativeToCRLIssuer CRL distribution points cau |
| 1 | MEDIUM | CVE-2026-42766 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: A specially crafted password-encrypted CMS message can trigger a NULL point |
| 1 | MEDIUM | CVE-2026-42767 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: An attacker-controlled CMP (Certificate Management Protocol) server could t |
| 1 | MEDIUM | CVE-2026-45446 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: The implementations of AES-SIV (RFC 5297) and AES-GCM-SIV (RFC 8452) mishan |
| 1 | MEDIUM | CVE-2026-63074 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | php-fpm:9000 | Issue summary: The OpenSSL Certificate Management Protocol (CMP) caches additional certifi |
| 1 | MEDIUM | CVE-2026-75805 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: A CMP client that requests certificate revocation on the basis of a PKCS#10 |
| 1 | MEDIUM | CVE-2026-75806 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: An established DTLS 1.2 association using an AEAD cipher suite can be termi |
| 1 | MEDIUM | CVE-2026-0990 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | 2.9.14+dfsg-1.3~deb12u6 | php-fpm:9000 | A flaw was found in libxml2, an XML parsing library. This uncontrolled recursion vulnerabi |
| 1 | MEDIUM | CVE-2026-1757 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | 2.9.14+dfsg-1.3~deb12u6 | php-fpm:9000 | A flaw was identified in the interactive shell of the xmllint utility, part of the libxml2 |
| 1 | MEDIUM | CVE-2025-1218 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Various packet overreads in mysqlnd_writeprotocol.c |
| 1 | MEDIUM | CVE-2025-14181 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Integer overflow to buffer overflow in soap HTTP parsing |
| 1 | MEDIUM | CVE-2026-14355 | php | 8.3.30 | 8.3.32 | php-fpm:9000 | ext/openssl: Memory corruption in openssl_encrypt with AES-WRAP-PAD |
| 1 | MEDIUM | CVE-2026-6103 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Phar TAR phar_tar_number() Integer Overflow - Archive Entry Injection |
| 1 | MEDIUM | CVE-2026-7259 | php | 8.3.30 | 8.3.31 | php-fpm:9000 | Null pointer dereference in php_mb_check_encoding() via mb_ereg_search_init() |
| 1 | MEDIUM | CVE-2026-7260 | php | 8.3.30 | 8.3.33 | php-fpm:9000 | Stack overflow in phar with circular symlinks |
| 1 | MEDIUM | CVE-2026-91766 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Cross-origin credential leak in HTTP stream wrapper redirects |
| 1 | MEDIUM | CVE-2026-91767 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Heap-buffer-overflow in php_openssl_matches_wildcard_name on crafted server cert wildcard  |
| 1 | MEDIUM | CVE-2026-91768 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | IPv6 ACL bypass in FastCGI listen.allowed_clients due to partial address comparison (memcm |
| 1 | MEDIUM | CVE-2026-91769 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | TLS Hostname Verification Falls Back to CN After SAN Mismatch |
| 1 | MEDIUM | CVE-2026-92842 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | OOB read / info leak in convert.* stream filters when line-break-chars contains NUL |
| 1 | MEDIUM | CVE-2026-93682 | php | 8.3.30 | 8.3.35 | php-fpm:9000 | Out-of-bounds read in the HTTP stream wrapper when following a redirect with an empty Loca |
| 1 | MEDIUM | CVE-2026-18374 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument i |
| 1 | MEDIUM | CVE-2026-19542 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may w |
| 1 | MEDIUM | CVE-2026-6238 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 1 | MEDIUM | CVE-2026-6368 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can caus |
| 1 | MEDIUM | CVE-2026-77117 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding,  |
| 1 | MEDIUM | CVE-2026-80489 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, fo |
| 1 | MEDIUM | CVE-2026-8674 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environ |
| 1 | MEDIUM | CVE-2026-86805 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of th |
| 1 | MEDIUM | CVE-2026-89092 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The nscd service in the GNU C Library 2.3.4 onwards may crash due to a  stack overflow whe |
| 1 | MEDIUM | CVE-2026-18374 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument i |
| 1 | MEDIUM | CVE-2026-19542 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may w |
| 1 | MEDIUM | CVE-2026-6238 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 1 | MEDIUM | CVE-2026-6368 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can caus |
| 1 | MEDIUM | CVE-2026-77117 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding,  |
| 1 | MEDIUM | CVE-2026-80489 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, fo |
| 1 | MEDIUM | CVE-2026-8674 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environ |
| 1 | MEDIUM | CVE-2026-86805 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of th |
| 1 | MEDIUM | CVE-2026-89092 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The nscd service in the GNU C Library 2.3.4 onwards may crash due to a  stack overflow whe |
| 1 | MEDIUM | CVE-2026-1965 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl can in some circumstances reuse the wrong connection when asked to do an Negotiate |
| 1 | MEDIUM | CVE-2026-4873 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | A vulnerability exists where a connection requiring TLS incorrectly reuses an existing une |
| 1 | MEDIUM | CVE-2026-5545 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl might in some circumstances reuse the wrong connection when asked to do an authent |
| 1 | MEDIUM | CVE-2026-6253 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | curl might erroneously pass on credentials for a first proxy to a second proxy.  This can  |
| 1 | MEDIUM | CVE-2026-6429 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When asked to both use a `.netrc` file for credentials and to follow HTTP redirects, libcu |
| 1 | MEDIUM | CVE-2026-8458 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl might in some circumstances reuse the wrong connection when asked to do Negotiate- |
| 1 | MEDIUM | CVE-2026-114690 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC. An out-of-bounds memory access vulnerability exists in the libstd |
| 1 | MEDIUM | CVE-2026-114691 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in the libstdc++ component of GCC. An attacker who can provide an excessi |
| 1 | MEDIUM | CVE-2026-115455 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC libstdc++. When an application extracts data into a bitset from a  |
| 1 | MEDIUM | CVE-2026-107708 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get |
| 1 | MEDIUM | CVE-2026-107778 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list |
| 1 | MEDIUM | CVE-2026-107708 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get |
| 1 | MEDIUM | CVE-2026-107778 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list |
| 1 | MEDIUM | CVE-2026-107708 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get |
| 1 | MEDIUM | CVE-2026-107778 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list |
| 1 | MEDIUM | CVE-2026-107708 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get |
| 1 | MEDIUM | CVE-2026-107778 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list |
| 1 | MEDIUM | CVE-2026-58055 | libnghttp2-14 | 1.52.0-1+deb12u2 | kein Fix | php-fpm:9000 | nghttp2's nghttpx proxy through 1.69.0 forwards an HTTP/1.1 Upgrade request that also carr |
| 1 | MEDIUM | CVE-2026-13757 | libp11-kit0 | 0.24.1-2 | kein Fix | php-fpm:9000 | A flaw was found in p11-kit. The RPC message attribute parsing functions p11_rpc_message_g |
| 1 | MEDIUM | CVE-2026-18938 | libp11-kit0 | 0.24.1-2 | kein Fix | php-fpm:9000 | A flaw was found in p11-kit. A local attacker, or one with equivalent access to a reachabl |
| 1 | MEDIUM | CVE-2026-112061 | librtmp1 | 2.4+20151223.gitfa8646d.1-2+b2 | kein Fix | php-fpm:9000 | librtmp (RTMPDump) through 2.6 contains a heap out-of-bounds read vulnerability in AMFProp |
| 1 | MEDIUM | CVE-2025-7709 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | An integer overflow exists in the  FTS5 https://sqlite.org/fts5.html  extension. It occurs |
| 1 | MEDIUM | CVE-2026-11822 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.53.2 contains an out-of-bounds read vulnerability in the FTS5 full-text se |
| 1 | MEDIUM | CVE-2026-119371 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains a stack exhaustion vulnerability that allows attackers to by |
| 1 | MEDIUM | CVE-2026-119372 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 built with FTS3/FTS4 and SQLITE_ENABLE_FTS3_PARENTHESIS contains a us |
| 1 | MEDIUM | CVE-2026-119375 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains an information disclosure vulnerability that allows attacker |
| 1 | MEDIUM | CVE-2026-119376 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains a stack exhaustion vulnerability that allows attackers to by |
| 1 | MEDIUM | CVE-2026-119378 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains a use-after-free vulnerability in the R-Tree extension that  |
| 1 | MEDIUM | CVE-2026-119591 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains a stack exhaustion vulnerability in countOfViewOptimization( |
| 1 | MEDIUM | CVE-2026-50812 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite tru |
| 1 | MEDIUM | CVE-2026-50813 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain s |
| 1 | MEDIUM | CVE-2026-114690 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC. An out-of-bounds memory access vulnerability exists in the libstd |
| 1 | MEDIUM | CVE-2026-114691 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in the libstdc++ component of GCC. An attacker who can provide an excessi |
| 1 | MEDIUM | CVE-2026-115455 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | A flaw was found in GCC libstdc++. When an application extracts data into a bitset from a  |
| 1 | MEDIUM | CVE-2023-50495 | libtinfo6 | 6.4-4 | kein Fix | php-fpm:9000 | NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_ |
| 1 | MEDIUM | CVE-2026-76781 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | A flaw was found in libxml2. A local user or an attacker providing a specially crafted XML |
| 1 | MEDIUM | CVE-2026-27171 | zlib1g | 1:1.2.13.dfsg-1 | kein Fix | php-fpm:9000 | zlib before 1.3.2 allows CPU consumption via crc32_combine64 and crc32_combine_gen64 becau |
| 1 | LOW | CVE-2026-5419 | libgnutls30 | 3.7.9-2+deb12u6 | 3.7.9-2+deb12u7 | php-fpm:9000 | A flaw was found in gnutls. The PKCS#7 padding check, performed during decryption, was not |
| 1 | LOW | CVE-2026-42770 | libssl3 | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | php-fpm:9000 | Issue summary: When EVP_PKEY_derive_set_peer() is called with a DHX (X9.42) peer key, the  |
| 1 | LOW | CVE-2026-54872 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: The generic elliptic-curve scalar multiplication used for ECDSA and SM2 sig |
| 1 | LOW | CVE-2026-77696 | libssl3 | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | php-fpm:9000 | Issue summary: SM2 signature generation uses non-constant-time arithmetic on secret values |
| 1 | LOW | CVE-2025-8732 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | 2.9.14+dfsg-1.3~deb12u6 | php-fpm:9000 | A vulnerability was found in libxml2 up to 2.14.5. It has been declared as problematic. Th |
| 1 | LOW | CVE-2026-0989 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | 2.9.14+dfsg-1.3~deb12u6 | php-fpm:9000 | A flaw was identified in the RelaxNG parser of libxml2 related to how external schema incl |
| 1 | LOW | CVE-2026-0992 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | 2.9.14+dfsg-1.3~deb12u6 | php-fpm:9000 | A flaw was found in the libxml2 library. This uncontrolled resource consumption vulnerabil |
| 1 | LOW | CVE-2010-4756 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authentica |
| 1 | LOW | CVE-2018-20796 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in pos |
| 1 | LOW | CVE-2019-1010022 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass sta |
| 1 | LOW | CVE-2019-1010023 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file |
| 1 | LOW | CVE-2019-1010024 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASL |
| 1 | LOW | CVE-2019-1010025 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the  |
| 1 | LOW | CVE-2019-9192 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in pos |
| 1 | LOW | CVE-2026-95818 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) v |
| 1 | LOW | CVE-2026-97399 | libc-bin | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 arch |
| 1 | LOW | CVE-2010-4756 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authentica |
| 1 | LOW | CVE-2018-20796 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in pos |
| 1 | LOW | CVE-2019-1010022 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass sta |
| 1 | LOW | CVE-2019-1010023 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file |
| 1 | LOW | CVE-2019-1010024 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASL |
| 1 | LOW | CVE-2019-1010025 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the  |
| 1 | LOW | CVE-2019-9192 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in pos |
| 1 | LOW | CVE-2026-95818 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) v |
| 1 | LOW | CVE-2026-97399 | libc6 | 2.36-9+deb12u13 | kein Fix | php-fpm:9000 | The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 arch |
| 1 | LOW | CVE-2024-2379 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | libcurl skips the certificate verification for a QUIC connection under certain conditions, |
| 1 | LOW | CVE-2025-0725 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When libcurl is asked to perform automatic gzip decompression of content-encoded HTTP resp |
| 1 | LOW | CVE-2025-10966 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | curl's code for managing SSH connections when SFTP was done using the wolfSSH powered back |
| 1 | LOW | CVE-2025-14017 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When doing multi-threaded LDAPS transfers (LDAP over TLS) with libcurl, changing TLS optio |
| 1 | LOW | CVE-2025-15079 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When doing SSH-based transfers using either SCP or SFTP, and setting the known_hosts file, |
| 1 | LOW | CVE-2025-15224 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When doing SSH-based transfers using either SCP or SFTP, and asked to do public key authen |
| 1 | LOW | CVE-2026-87866 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When built with wolfSSL, curl can successfully validate a pinned public key hash against a |
| 1 | LOW | CVE-2026-9547 | libcurl4 | 7.88.1-10+deb12u14 | kein Fix | php-fpm:9000 | When a libcurl-based application performs transfers via `SCP://` or `SFTP://` and utilizes |
| 1 | LOW | CVE-2022-27943 | libgcc-s1 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as d |
| 1 | LOW | CVE-2011-3389 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Int |
| 1 | LOW | CVE-2026-67693 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | GnuTLS v3.8.13 does not reject end-entity X.509 certificates that contain a contradictory  |
| 1 | LOW | CVE-2026-88647 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | GnuTLS v3.8.13 can perhaps unexpectedly trust a certificate on the basis of Common Name wh |
| 1 | LOW | CVE-2026-88648 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | In GnuTLS v3.8.13, an excluded msUPN/SRV otherName is never checked. NOTE: the Supplier do |
| 1 | LOW | CVE-2026-95184 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | GnuTLS v3.8.13 does not properly enforce name constraints, as demonstrated by a permitted  |
| 1 | LOW | CVE-2026-95209 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | An issue in gnutls v3.8.13 causes legitimate CA certificates to be rejected, leading to a  |
| 1 | LOW | CVE-2026-95210 | libgnutls30 | 3.7.9-2+deb12u6 | kein Fix | php-fpm:9000 | GnuTLS v3.8.13 does not reject a critical keyUsage extension when it cannot be processed,  |
| 1 | LOW | CVE-2018-5709 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "db |
| 1 | LOW | CVE-2024-26458 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c. |
| 1 | LOW | CVE-2024-26461 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/ |
| 1 | LOW | CVE-2026-11850 | libgssapi-krb5-2 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function  |
| 1 | LOW | CVE-2018-5709 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "db |
| 1 | LOW | CVE-2024-26458 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c. |
| 1 | LOW | CVE-2024-26461 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/ |
| 1 | LOW | CVE-2026-11850 | libk5crypto3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function  |
| 1 | LOW | CVE-2018-5709 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "db |
| 1 | LOW | CVE-2024-26458 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c. |
| 1 | LOW | CVE-2024-26461 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/ |
| 1 | LOW | CVE-2026-11850 | libkrb5-3 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function  |
| 1 | LOW | CVE-2018-5709 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "db |
| 1 | LOW | CVE-2024-26458 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c. |
| 1 | LOW | CVE-2024-26461 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/ |
| 1 | LOW | CVE-2026-11850 | libkrb5support0 | 1.20.1-2+deb12u4 | kein Fix | php-fpm:9000 | An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function  |
| 1 | LOW | CVE-2015-3276 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | The nss_parse_ciphers function in libraries/libldap/tls_m.c in OpenLDAP does not properly  |
| 1 | LOW | CVE-2017-14159 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non |
| 1 | LOW | CVE-2017-17740 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | contrib/slapd-modules/nops/nops.c in OpenLDAP through 2.4.45, when both the nops module an |
| 1 | LOW | CVE-2020-15719 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | libldap in certain third-party OpenLDAP packages has a certificate-validation flaw when th |
| 1 | LOW | CVE-2026-22185 | libldap-2.5-0 | 2.5.13+dfsg-5 | kein Fix | php-fpm:9000 | OpenLDAP Lightning Memory-Mapped Database (LMDB) versions 0.9.14 before 0.9.34, prior to c |
| 1 | LOW | CVE-2021-45346 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via malicio |
| 1 | LOW | CVE-2025-29088 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-lan |
| 1 | LOW | CVE-2025-70873 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | An information disclosure issue in the zipfileInflate function in the zipfile extension in |
| 1 | LOW | CVE-2026-119377 | libsqlite3-0 | 3.40.1-2+deb12u2 | kein Fix | php-fpm:9000 | SQLite before 3.54.0 contains an authorization bypass vulnerability in lookupName() that i |
| 1 | LOW | CVE-2025-27587 | libssl3 | 3.0.19-1~deb12u2 | kein Fix | php-fpm:9000 | OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, |
| 1 | LOW | CVE-2022-27943 | libstdc++6 | 12.2.0-14+deb12u1 | kein Fix | php-fpm:9000 | libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as d |
| 1 | LOW | CVE-2025-6141 | libtinfo6 | 6.4-4 | kein Fix | php-fpm:9000 | A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problem |
| 1 | LOW | CVE-2026-11979 | libxml2 | 2.9.14+dfsg-1.3~deb12u5 | kein Fix | php-fpm:9000 | libxml2 is vulnerable to multiple stack-based buffer overflows in the xmlcatalog utility w |
| 4 | CRITICAL | CVE-2026-12087 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Socket versions before 2.041 for Perl have an out-of-bounds heap read.  In Socket.xs, pack |
| 4 | CRITICAL | CVE-2026-13221 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.10 |
| 4 | CRITICAL | CVE-2026-42496 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract symlinks with attacker controlled targe |
| 4 | CRITICAL | CVE-2026-57433 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Storable versions before 3.41 for Perl have a signed integer overflow when deserializing a |
| 4 | CRITICAL | CVE-2026-8376 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | CRITICAL | CVE-2026-34182 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue Summary: Cryptographic Message Services (CMS) processing fails to perform sufficient |
| 4 | CRITICAL | CVE-2026-75803 | openssl | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | – | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty ciphertext can repor |
| 4 | CRITICAL | CVE-2026-12087 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Socket versions before 2.041 for Perl have an out-of-bounds heap read.  In Socket.xs, pack |
| 4 | CRITICAL | CVE-2026-13221 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.10 |
| 4 | CRITICAL | CVE-2026-42496 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract symlinks with attacker controlled targe |
| 4 | CRITICAL | CVE-2026-57433 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Storable versions before 3.41 for Perl have a signed integer overflow when deserializing a |
| 4 | CRITICAL | CVE-2026-8376 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | CRITICAL | CVE-2026-12087 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Socket versions before 2.041 for Perl have an out-of-bounds heap read.  In Socket.xs, pack |
| 4 | CRITICAL | CVE-2026-13221 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.10 |
| 4 | CRITICAL | CVE-2026-42496 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract symlinks with attacker controlled targe |
| 4 | CRITICAL | CVE-2026-57433 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Storable versions before 3.41 for Perl have a signed integer overflow when deserializing a |
| 4 | CRITICAL | CVE-2026-8376 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | CRITICAL | CVE-2026-12087 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Socket versions before 2.041 for Perl have an out-of-bounds heap read.  In Socket.xs, pack |
| 4 | CRITICAL | CVE-2026-13221 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.10 |
| 4 | CRITICAL | CVE-2026-42496 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract symlinks with attacker controlled targe |
| 4 | CRITICAL | CVE-2026-57433 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Storable versions before 3.41 for Perl have a signed integer overflow when deserializing a |
| 4 | CRITICAL | CVE-2026-8376 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | CRITICAL | CVE-2026-10536 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A use-after-free vulnerability exists in libcurl when an application configures an HTTP/2  |
| 4 | CRITICAL | CVE-2026-11856 | curl | 7.88.1-10+deb12u14 | kein Fix | – | Successfully using libcurl to do a transfer to a specific HTTP origin (`hostA`) with **Dig |
| 4 | CRITICAL | CVE-2026-18924 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A flaw in libcurl's handling of HTTP/2 Server Push streams, when the parent handle is set  |
| 4 | CRITICAL | CVE-2026-19931 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A flaw in libcurl makes it wrongly reuse an HTTP connection setup for a given hostname usi |
| 4 | CRITICAL | CVE-2026-86414 | curl | 7.88.1-10+deb12u14 | kein Fix | – | An HTTP proxy can trick libcurl into sending the origin's credentials (Basic password, or  |
| 4 | CRITICAL | CVE-2026-8924 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A flaw in curl’s cookie parsing logic allows a malicious HTTP server to set "super cookies |
| 4 | CRITICAL | CVE-2026-8927 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When reusing a libcurl handle for sequential transfers driven by environment-variable prox |
| 4 | CRITICAL | CVE-2026-92388 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When an FTP wildcard `LIST` operation fails, libcurl omits the restoration path meant for  |
| 4 | CRITICAL | CVE-2026-5450 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C L |
| 4 | CRITICAL | CVE-2026-5450 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C L |
| 4 | HIGH | CVE-2026-109518 | apt | 2.6.1 | 2.6.2 | – | On Debian, Ubuntu, and derivative Linux distributions, an on-path attacker who can manipul |
| 4 | HIGH | CVE-2026-5773 | curl | 7.88.1-10+deb12u14 | 7.88.1-10+deb12u15 | – | libcurl might in some circumstances reuse the wrong connection for SMB(S) transfers.  libc |
| 4 | HIGH | CVE-2025-6297 | dpkg | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb does not properly sanitize directory permissions when extr |
| 4 | HIGH | CVE-2026-2219 | dpkg | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb (a component of dpkg, the Debian package management system |
| 4 | HIGH | CVE-2025-6297 | dpkg-dev | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb does not properly sanitize directory permissions when extr |
| 4 | HIGH | CVE-2026-2219 | dpkg-dev | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb (a component of dpkg, the Debian package management system |
| 4 | HIGH | CVE-2026-109518 | libapt-pkg6.0 | 2.6.1 | 2.6.2 | – | On Debian, Ubuntu, and derivative Linux distributions, an on-path attacker who can manipul |
| 4 | HIGH | CVE-2025-15281 | libc-dev-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling wordexp with WRDE_REUSE in conjunction with WRDE_APPEND in the GNU C Library versi |
| 4 | HIGH | CVE-2026-0861 | libc-dev-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Passing too large an alignment to the memalign suite of functions (memalign, posix_memalig |
| 4 | HIGH | CVE-2026-0915 | libc-dev-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the  |
| 4 | HIGH | CVE-2026-4046 | libc-dev-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an as |
| 4 | HIGH | CVE-2026-4437 | libc-dev-bin | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 4 | HIGH | CVE-2025-15281 | libc6-dev | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling wordexp with WRDE_REUSE in conjunction with WRDE_APPEND in the GNU C Library versi |
| 4 | HIGH | CVE-2026-0861 | libc6-dev | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Passing too large an alignment to the memalign suite of functions (memalign, posix_memalig |
| 4 | HIGH | CVE-2026-0915 | libc6-dev | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the  |
| 4 | HIGH | CVE-2026-4046 | libc6-dev | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | The iconv() function in the GNU C Library versions 2.43 and earlier may crash due to an as |
| 4 | HIGH | CVE-2026-4437 | libc6-dev | 2.36-9+deb12u13 | 2.36-9+deb12u14 | – | Calling gethostbyaddr or gethostbyaddr_r with a configured nsswitch.conf that specifies th |
| 4 | HIGH | CVE-2026-4878 | libcap2 | 1:2.66-4+deb12u2+b2 | 1:2.66-4+deb12u3 | – | A flaw was found in libcap. A local unprivileged user can exploit a Time-of-check-to-time- |
| 4 | HIGH | CVE-2025-6297 | libdpkg-perl | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb does not properly sanitize directory permissions when extr |
| 4 | HIGH | CVE-2026-2219 | libdpkg-perl | 1.21.22 | 1.21.23 | – | It was discovered that dpkg-deb (a component of dpkg, the Debian package management system |
| 4 | HIGH | CVE-2026-103111 | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u2 | – | PCRE2 before 10.49, when there is an attacker-controlled regular expression and certain JI |
| 4 | HIGH | CVE-2026-86145 | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u1 | – | PCRE2 before 10.48 allows a pcre2_dfa_match out-of-bounds write because reuse of a cached  |
| 4 | HIGH | CVE-2026-89157 | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u1 | – | PCRE2 before 10.48, on 32-bit platforms, has a pcre2_pattern_convert out-of-bounds write w |
| 4 | HIGH | CVE-2026-89161 | libpcre2-8-0 | 10.42-1 | 10.42-1+deb12u1 | – | In PCRE2 before 10.48, pcre2_jit_match mishandles a previously copied subject being passed |
| 4 | HIGH | CVE-2026-42497 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract hardlinks to attacker controlled paths  |
| 4 | HIGH | CVE-2026-48959 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Uncompress::Unzip versions before 2.220 for Perl allow CPU exhaustion via per-byte rea |
| 4 | HIGH | CVE-2026-48962 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Compress versions before 2.220 for Perl can execute arbitrary code in File::GlobMapper |
| 4 | HIGH | CVE-2026-57432 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | HIGH | CVE-2026-7017 | libperl5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | HTTP::Tiny versions before 0.095 for Perl forward credential headers to cross-origin redir |
| 4 | HIGH | CVE-2026-107161 | libsasl2-modules-db | 2.1.28+dfsg-10 | 2.1.28+dfsg-10+deb12u1 | – | A heap-based buffer overflow flaw was found in Cyrus SASL. The add_to_challenge() function |
| 4 | HIGH | CVE-2026-34180 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue summary: Parsing a crafted DER-encoded ASN.1 structure with a primitive element whos |
| 4 | HIGH | CVE-2026-45445 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue summary: When an application drives an AES-OCB context through the public EVP_Cipher |
| 4 | HIGH | CVE-2026-45447 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue summary: A specially crafted PKCS#7 or S/MIME signed message could trigger a use-aft |
| 4 | HIGH | CVE-2026-54874 | openssl | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | – | Issue summary: Receiving a DTLS record for a future epoch while a handshake is in progress |
| 4 | HIGH | CVE-2026-63072 | openssl | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | – | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based on querying |
| 4 | HIGH | CVE-2026-63076 | openssl | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u1 | – | Issue summary: OpenSSL CMP password based protection verification only checks whether the  |
| 4 | HIGH | CVE-2026-7383 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue summary: A signed integer overflow when sizing the destination buffer for Unicode ou |
| 4 | HIGH | CVE-2026-84782 | openssl | 3.0.19-1~deb12u2 | 3.0.22-1~deb12u2 | – | Issue summary: The DTLS retransmission logic does not correctly handle a handshake message |
| 4 | HIGH | CVE-2026-9076 | openssl | 3.0.19-1~deb12u2 | 3.0.20-1~deb12u2 | – | Issue summary: When CMS password-based decryption (RFC 3211 / PWRI key unwrap) processes a |
| 4 | HIGH | CVE-2026-42497 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract hardlinks to attacker controlled paths  |
| 4 | HIGH | CVE-2026-48959 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Uncompress::Unzip versions before 2.220 for Perl allow CPU exhaustion via per-byte rea |
| 4 | HIGH | CVE-2026-48962 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Compress versions before 2.220 for Perl can execute arbitrary code in File::GlobMapper |
| 4 | HIGH | CVE-2026-57432 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | HIGH | CVE-2026-7017 | perl | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | HTTP::Tiny versions before 0.095 for Perl forward credential headers to cross-origin redir |
| 4 | HIGH | CVE-2026-42497 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract hardlinks to attacker controlled paths  |
| 4 | HIGH | CVE-2026-48959 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Uncompress::Unzip versions before 2.220 for Perl allow CPU exhaustion via per-byte rea |
| 4 | HIGH | CVE-2026-48962 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Compress versions before 2.220 for Perl can execute arbitrary code in File::GlobMapper |
| 4 | HIGH | CVE-2026-57432 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | HIGH | CVE-2026-7017 | perl-base | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | HTTP::Tiny versions before 0.095 for Perl forward credential headers to cross-origin redir |
| 4 | HIGH | CVE-2026-42497 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Archive::Tar versions before 3.08 for Perl extract hardlinks to attacker controlled paths  |
| 4 | HIGH | CVE-2026-48959 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Uncompress::Unzip versions before 2.220 for Perl allow CPU exhaustion via per-byte rea |
| 4 | HIGH | CVE-2026-48962 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | IO::Compress versions before 2.220 for Perl can execute arbitrary code in File::GlobMapper |
| 4 | HIGH | CVE-2026-57432 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.11 |
| 4 | HIGH | CVE-2026-7017 | perl-modules-5.36 | 5.36.0-7+deb12u3 | 5.36.0-7+deb12u4 | – | HTTP::Tiny versions before 0.095 for Perl forward credential headers to cross-origin redir |
| 4 | HIGH | CVE-2026-53613 | bsdutils | 1:2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | bsdutils | 1:2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | bsdutils | 1:2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2026-102010 | cpp-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | cpp-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-107928 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When curl is built with GnuTLS, a malicious WebSocket server can make curl send memory pas |
| 4 | HIGH | CVE-2026-12064 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When a user invokes curl using a schemeless URL combined with `--proto-default` sftp (or s |
| 4 | HIGH | CVE-2026-13608 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A flaw in the libcurl SASL negotiation for LDAP authentication allows an incomplete handsh |
| 4 | HIGH | CVE-2026-6276 | curl | 7.88.1-10+deb12u14 | kein Fix | – | Using libcurl, when a custom `Host:` header is first set for an HTTP request and a second  |
| 4 | HIGH | CVE-2026-80230 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When `CURLOPT_PINNEDPUBLICKEY` is configured alongside options that disable standard peer  |
| 4 | HIGH | CVE-2026-82209 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When libpsl support is enabled, libcurl fails to enforce the Public Suffix List boundary c |
| 4 | HIGH | CVE-2026-8286 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A vulnerability exists where a new transfer that uses STARTTLS to upgrade the connection m |
| 4 | HIGH | CVE-2026-86409 | curl | 7.88.1-10+deb12u14 | kein Fix | – | Setting `CURLOPT_AWS_SIGV4` to NULL but does not disable SigV4 authentication, contrary to |
| 4 | HIGH | CVE-2026-86410 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A flaw in the curl command line tool's logic makes it only set SSH host verification optio |
| 4 | HIGH | CVE-2026-87864 | curl | 7.88.1-10+deb12u14 | kein Fix | – | Enabling `CURLOPT_CRLF` causes curl to advertise the raw input byte count in the `IMAP APP |
| 4 | HIGH | CVE-2026-87865 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When libcurl uses libssh2 with a hashed `known_hosts` file, an unrelated initial entry can |
| 4 | HIGH | CVE-2026-8932 | curl | 7.88.1-10+deb12u14 | kein Fix | – | libcurl would reuse a previously created connection even when some mTLS config related opt |
| 4 | HIGH | CVE-2026-92389 | curl | 7.88.1-10+deb12u14 | kein Fix | – | libcurl's TFTP state machine fails to validate state transitions against the requested tra |
| 4 | HIGH | CVE-2026-92390 | curl | 7.88.1-10+deb12u14 | kein Fix | – | When invoked with `--remote-header-name` (`-J`), curl fails to preserve its documented ant |
| 4 | HIGH | CVE-2026-92391 | curl | 7.88.1-10+deb12u14 | kein Fix | – | A deeply nested multipart MIME structure constructed via the public API causes a stack ove |
| 4 | HIGH | CVE-2026-94266 | curl | 7.88.1-10+deb12u14 | kein Fix | – | libcurl could accidentally return a URL for `curl_easy_getinfo()`'s `CURLINFO_EFFECTIVE_UR |
| 4 | HIGH | CVE-2026-102010 | g++-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | g++-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | gcc-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | gcc-12 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | gcc-12-base | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | gcc-12-base | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-41992 | gzip | 1.12-1 | kein Fix | – | GNU gzip contains a global buffer overflow vulnerability in the LZH decompression logic ca |
| 4 | HIGH | CVE-2026-54369 | libacl1 | 2.3.1-3 | kein Fix | – | acl before version 2.4.0 contains a symlink traversal vulnerability in the libacl pathname |
| 4 | HIGH | CVE-2026-54370 | libacl1 | 2.3.1-3 | kein Fix | – | acl before version 2.4.0 contains a time-of-check to time-of-use (TOCTOU) race condition v |
| 4 | HIGH | CVE-2026-102010 | libasan8 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libasan8 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libatomic1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libatomic1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-54371 | libattr1 | 1:2.5.1-4 | kein Fix | – | attr before version 2.6.0 contains a symlink traversal vulnerability in the getfattr and s |
| 4 | HIGH | CVE-2026-53613 | libblkid1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | libblkid1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | libblkid1 | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2026-19499 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the |
| 4 | HIGH | CVE-2026-5435 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 4 | HIGH | CVE-2026-5928 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | Calling the ungetwc function on a FILE stream with wide characters encoded in a character  |
| 4 | HIGH | CVE-2026-6791 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | When expanding paths that begin with a tilde (~) followed by a username, the internal pars |
| 4 | HIGH | CVE-2026-84243 | libc-dev-bin | 2.36-9+deb12u13 | kein Fix | – | The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE |
| 4 | HIGH | CVE-2026-19499 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the |
| 4 | HIGH | CVE-2026-5435 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library versio |
| 4 | HIGH | CVE-2026-5928 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | Calling the ungetwc function on a FILE stream with wide characters encoded in a character  |
| 4 | HIGH | CVE-2026-6791 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | When expanding paths that begin with a tilde (~) followed by a username, the internal pars |
| 4 | HIGH | CVE-2026-84243 | libc6-dev | 2.36-9+deb12u13 | kein Fix | – | The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE |
| 4 | HIGH | CVE-2026-102010 | libcc1-0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libcc1-0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libgcc-12-dev | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libgcc-12-dev | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libgomp1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libgomp1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libitm1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libitm1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | liblsan0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | liblsan0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-53613 | libmount1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | libmount1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | libmount1 | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2025-8941 | libpam-modules | 1.5.2-6+deb12u2 | kein Fix | – | A flaw was found in linux-pam. The pam_namespace module may improperly handle user-control |
| 4 | HIGH | CVE-2026-54411 | libpam-modules | 1.5.2-6+deb12u2 | kein Fix | – | Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_use |
| 4 | HIGH | CVE-2025-8941 | libpam-modules-bin | 1.5.2-6+deb12u2 | kein Fix | – | A flaw was found in linux-pam. The pam_namespace module may improperly handle user-control |
| 4 | HIGH | CVE-2026-54411 | libpam-modules-bin | 1.5.2-6+deb12u2 | kein Fix | – | Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_use |
| 4 | HIGH | CVE-2025-8941 | libpam-runtime | 1.5.2-6+deb12u2 | kein Fix | – | A flaw was found in linux-pam. The pam_namespace module may improperly handle user-control |
| 4 | HIGH | CVE-2026-54411 | libpam-runtime | 1.5.2-6+deb12u2 | kein Fix | – | Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_use |
| 4 | HIGH | CVE-2025-8941 | libpam0g | 1.5.2-6+deb12u2 | kein Fix | – | A flaw was found in linux-pam. The pam_namespace module may improperly handle user-control |
| 4 | HIGH | CVE-2026-54411 | libpam0g | 1.5.2-6+deb12u2 | kein Fix | – | Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_use |
| 4 | HIGH | CVE-2026-82560 | libperl5.36 | 5.36.0-7+deb12u3 | kein Fix | – | Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD  |
| 4 | HIGH | CVE-2026-9538 | libperl5.36 | 5.36.0-7+deb12u3 | kein Fix | – | Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled |
| 4 | HIGH | CVE-2026-102010 | libquadmath0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libquadmath0 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-53613 | libsmartcols1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | libsmartcols1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | libsmartcols1 | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2026-102010 | libstdc++-12-dev | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libstdc++-12-dev | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libtsan2 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libtsan2 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-102010 | libubsan1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in GCC. When an application calls the erase_if function on a binary heap  |
| 4 | HIGH | CVE-2026-95619 | libubsan1 | 12.2.0-14+deb12u1 | kein Fix | – | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs  |
| 4 | HIGH | CVE-2026-53613 | libuuid1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | libuuid1 | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | libuuid1 | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2026-53613 | mount | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | mount | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | mount | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2025-69720 | ncurses-base | 6.4-4 | kein Fix | – | The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer over |
| 4 | HIGH | CVE-2025-69720 | ncurses-bin | 6.4-4 | kein Fix | – | The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer over |
| 4 | HIGH | CVE-2026-82560 | perl | 5.36.0-7+deb12u3 | kein Fix | – | Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD  |
| 4 | HIGH | CVE-2026-9538 | perl | 5.36.0-7+deb12u3 | kein Fix | – | Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled |
| 4 | HIGH | CVE-2026-82560 | perl-base | 5.36.0-7+deb12u3 | kein Fix | – | Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD  |
| 4 | HIGH | CVE-2026-9538 | perl-base | 5.36.0-7+deb12u3 | kein Fix | – | Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled |
| 4 | HIGH | CVE-2026-82560 | perl-modules-5.36 | 5.36.0-7+deb12u3 | kein Fix | – | Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD  |
| 4 | HIGH | CVE-2026-9538 | perl-modules-5.36 | 5.36.0-7+deb12u3 | kein Fix | – | Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled |
| 4 | HIGH | CVE-2026-53613 | util-linux | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | util-linux | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | util-linux | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | HIGH | CVE-2026-53613 | util-linux-extra | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 an |
| 4 | HIGH | CVE-2026-53615 | util-linux-extra | 2.38.1-5+deb12u3 | kein Fix | – | util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos |
| 4 | HIGH | CVE-2026-78410 | util-linux-extra | 2.38.1-5+deb12u3 | kein Fix | – | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but |
| 4 | MEDIUM KEV | CVE-2020-11023 | jquery | 1.12.4 | 3.5.0 (anderer Versionszweig: Upgrade nötig) | – | Potential XSS vulnerability in jQuery |

KEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).

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
| composer | 2 | 2 | 0 |
| host | 5 | 0 | 0 |
| js-lib | 1 | 0 | 0 |
| os-paket | 173 | 39 | 0 |
| runtime | 2 | 2 | 0 |
| runtime-lib | 7 | 7 | 0 |

### Container

```
ID:        59306a882f80eec1f285893ab71f1d8a8123ae778dc616fc081b0d8098560a71
Gestartet: 2026-11-07T21:15:09.035135089Z
Kommando:  ["docker-php-entrypoint"] ["php-fpm"]
Mounts:    /home/user/container-security-scan/beispiele/umgebung/php->/srv/app
Host:      Kernel 6.18.44-fc-v310
```

### Laufende Prozesse

```
PID                 USER                COMMAND
2150                root                php-fpm: master process (/usr/local/etc/php-fpm.conf)
2191                www-data            php-fpm: pool www
2194                www-data            php-fpm: pool www
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

Keine gefunden.
