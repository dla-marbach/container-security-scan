# Host-Scan: web01.example.com

- Host: web01.example.com, Kernel 6.18.44-fc-v445  
- OS: SUSE Linux Enterprise Server 15 SP7  
- Zeitpunkt: 2026-11-13 22:58  
- Scanner: container-security-scan 0.4.0  
- Datenbank: OSV, Stand 2026-11-13 03:23 UTC (/daten)  
- Erfassung: OS-Pakete rpm (Host); Dateien find/tar auf dem Host (/); Prozesse über /proc des Hosts (16 Prozesse außerhalb von Containern); 4 Sprach-Komponenten aus OS-Paketen (über das OS-Paket geprüft)
- Firewall: firewalld aktiv (Runtime), Standardzone public; Zone docker: docker0

## Ergebnis

**Warnung:** Supportende: jquery 1.12.4 (jquery 1, Datum unbekannt; /srv/www/app/public/js/jquery-1.12.4.min.js, /srv/www/htdocs/js/jquery-1.12.4.min.js)  
**8 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2022-29248** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.3 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2022-31042** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.4 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2022-31043** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.4 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2022-31090** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.5 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2022-31091** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.5 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2026-69246** (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.15.2 – genutzt von php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2)
- **CVE-2020-11023** (MEDIUM KEV) in jquery 1.12.4 – behoben in 3.5.0 (anderer Versionszweig: Upgrade nötig) – genutzt von php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 – Webadressen: http://www.example.org/app/, http://example.org/app/, https://www.example.org/app/ (+2) – **aktiv ausgenutzt** (KEV seit 2025-01-23)
- **CVE-2020-11023** (MEDIUM KEV) in jquery 1.12.4 – behoben in 3.5.0 (anderer Versionszweig: Upgrade nötig) – genutzt von php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 – Webadressen: http://localhost/, http://www.example.org/, http://example.org/ (+2) – **aktiv ausgenutzt** (KEV seit 2025-01-23)

**4 Einstellungen der Webserver** (erreichbar; Kennung für die Ausnahmeliste, Paket = Name der Website)

- **WEB-STATUS**: Apache: server-status unter /server-status nur für localhost freigegeben (Require local; Deny from all; Allow from localhost) – davor leitet ein Proxy Anfragen von dieser Maschine weiter (http://www.example.org/app/, http://example.org/app/ (+3)), damit greift die Beschränkung nicht – Webadressen: http://www.example.org/app/server-status, http://example.org/app/server-status, https://www.example.org/app/server-status (+3)
- **WEB-STATUS**: nginx: stub_status in location /nginx_status ohne Zugriffsbeschränkung (deny all, auth_basic, internal) – Webadressen: http://www.example.org/nginx_status, http://example.org/nginx_status, https://www.example.org/nginx_status (+1)
- **WEB-AUTOINDEX**: nginx: autoindex on (Verzeichnisliste) in location / – Webadressen: http://intranet.example.local/
- **WEB-TLS-ALT**: nginx:80,8443,443 nimmt TLS 1.0 und TLS 1.1 an (veraltet, ohne Sicherheitsupdates; ssl_protocols bzw. SSLProtocol auf TLSv1.2 TLSv1.3 setzen) – geprüft an 127.0.0.1:8443 – Webadressen: https://partner.example.org:8443/

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| php-fpm:9000 | php-fpm 8.3.36 | Port 9000/tcp (localhost) lauscht nur auf Loopback – von außen nicht erreichbar; hinter httpd-prefork:8080, nginx:80,8443,443 (gleicher Host) |
| httpd-prefork:8080 | httpd-prefork 2.4.71 | Port 8080/tcp (localhost) lauscht nur auf Loopback – von außen nicht erreichbar; hinter nginx:80,8443,443 (gleicher Host); Anwendung: /etc/apache2/httpd.conf; Konfiguration: VirtualHost 127.0.0.1:8080 ServerName app.example.org DocumentRoot /srv/www/app/public; Backend fcgi://127.0.0.1:9000 (Host) |
| nginx:80,8443,443 | nginx 1.21.5 | Port 80/tcp (alle) an allen Adressen, firewalld lässt durch: eth0: Zone public, Dienst http; Port 8443/tcp (alle) an allen Adressen, firewalld lässt durch: eth0: Zone public, Port 8443/tcp freigegeben; Port 443/tcp (alle) an allen Adressen, firewalld lässt durch: eth0: Zone public, Dienst https; Konfiguration: listen 80 server_name localhost root /srv/www/htdocs/,/srv/www/htdocs/ / listen 80,443 server_name www.example.org example.org root /srv/www/htdocs / listen 8443 server_name partner.example.org / listen 80 server_name intranet.example.local root /srv/www/intranet; Backend http://127.0.0.1:8080/ (Host) |
| python3.6:8000 | python3.6 3.6.15 | Port 8000/tcp (alle) an allen Adressen, aber von firewalld gesperrt (Zone public); Anwendung: http.server; Arbeitsverzeichnis: /srv/www/intranet |

## Webadressen

Aus der Konfiguration der Webserver (server_name, ServerName/ServerAlias, listen bzw. vHost, TLS); Pfade, die ein Proxy auf demselben Host weiterleitet, beim Ziel. „Erreichbar“ wie der Port, über den die Anfrage hereinkommt.

| Webadresse | Erreichbar | Dienst | Weg | Website | Docroot / Ziel |
|---|---|---|---|---|---|
| http://www.example.org/app/ (\.php$) | ja | php-fpm:9000 | nginx:80,8443,443 → httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| http://example.org/app/ (\.php$) | ja | php-fpm:9000 | nginx:80,8443,443 → httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| https://www.example.org/app/ (\.php$) | ja | php-fpm:9000 | nginx:80,8443,443 → httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| https://example.org/app/ (\.php$) | ja | php-fpm:9000 | nginx:80,8443,443 → httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| https://partner.example.org:8443/ (\.php$) | ja | php-fpm:9000 | nginx:80,8443,443 → httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| http://app.example.org:8080/ (\.php$) | nein | php-fpm:9000 | httpd-prefork:8080 → php-fpm:9000 | (weitergeleitet) | – |
| http://www.example.org/app/ | ja | httpd-prefork:8080 | nginx:80,8443,443 → httpd-prefork:8080 | (weitergeleitet) | – |
| http://example.org/app/ | ja | httpd-prefork:8080 | nginx:80,8443,443 → httpd-prefork:8080 | (weitergeleitet) | – |
| https://www.example.org/app/ | ja | httpd-prefork:8080 | nginx:80,8443,443 → httpd-prefork:8080 | (weitergeleitet) | – |
| https://example.org/app/ | ja | httpd-prefork:8080 | nginx:80,8443,443 → httpd-prefork:8080 | (weitergeleitet) | – |
| https://partner.example.org:8443/ | ja | httpd-prefork:8080 | nginx:80,8443,443 → httpd-prefork:8080 | (weitergeleitet) | – |
| http://app.example.org:8080/ | nein | httpd-prefork:8080 | httpd-prefork:8080 | /etc/apache2/vhosts.d/app.conf:2 | /srv/www/app/public |
| http://localhost/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/nginx.conf | /srv/www/htdocs/ |
| http://www.example.org/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | /srv/www/htdocs |
| http://example.org/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | /srv/www/htdocs |
| https://www.example.org/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | /srv/www/htdocs |
| https://example.org/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | /srv/www/htdocs |
| https://partner.example.org:8443/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | / → http://127.0.0.1:8080/ |
| http://intranet.example.local/ | ja | nginx:80,8443,443 | nginx:80,8443,443 | /etc/nginx/vhosts.d/www.conf | /srv/www/intranet |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 0 | 6 | 22 | 0 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 0 | 0 | 0 | 0 | 0 |

## Befunde (28 von 28; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Webadressen | Titel |
|---|---|---|---|---|---|---|---|---|
| 1 | HIGH | CVE-2022-29248 | guzzlehttp/guzzle | 7.4.0 | 7.4.3 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Cross-domain cookie leakage in Guzzle |
| 1 | HIGH | CVE-2022-31042 | guzzlehttp/guzzle | 7.4.0 | 7.4.4 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Failure to strip the Cookie header on change in host or HTTP downgrade |
| 1 | HIGH | CVE-2022-31043 | guzzlehttp/guzzle | 7.4.0 | 7.4.4 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Failure to strip the Cookie header on change in host or HTTP downgrade |
| 1 | HIGH | CVE-2022-31090 | guzzlehttp/guzzle | 7.4.0 | 7.4.5 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | CURLOPT_HTTPAUTH option not cleared on change of origin |
| 1 | HIGH | CVE-2022-31091 | guzzlehttp/guzzle | 7.4.0 | 7.4.5 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Change in port should be considered a change in origin |
| 1 | HIGH | CVE-2026-69246 | guzzlehttp/guzzle | 7.4.0 | 7.15.2 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Noncanonical host can bypass host-based checks |
| 1 | MEDIUM | CVE-2026-55568 | guzzlehttp/guzzle | 7.4.0 | 7.12.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/guzzle: Silent HTTPS-Proxy Downgrade to Cleartext |
| 1 | MEDIUM | CVE-2026-55767 | guzzlehttp/guzzle | 7.4.0 | 7.12.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/guzzle: Dot-Only Cookie Domains Match All Hosts |
| 1 | MEDIUM | CVE-2026-59883 | guzzlehttp/guzzle | 7.4.0 | 7.12.3 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Cookie Disclosure and Injection via IP-Address Domains |
| 1 | MEDIUM | CVE-2026-67339 | guzzlehttp/guzzle | 7.4.0 | 7.14.2 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Proxy-Authorization headers can be sent to origin servers |
| 1 | MEDIUM | CVE-2026-67353 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Unbounded response cookies risk denial of service |
| 1 | MEDIUM | CVE-2026-67354 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: URI fragments disclosed in redirect Referer headers |
| 1 | MEDIUM | CVE-2026-67355 | guzzlehttp/guzzle | 7.4.0 | 7.15.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Host-only cookie scope is not preserved |
| 1 | MEDIUM | CVE-2026-69245 | guzzlehttp/guzzle | 7.4.0 | 7.15.2 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Guzzle: Noncanonical cookie domain keeps subdomain scope |
| 1 | MEDIUM | CVE-2022-24775 | guzzlehttp/psr7 | 2.1.0 | 2.1.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Improper Input Validation in guzzlehttp/psr7 |
| 1 | MEDIUM | CVE-2023-29197 | guzzlehttp/psr7 | 2.1.0 | 2.4.5 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | Improper header name validation in guzzlehttp/psr7 |
| 1 | MEDIUM | CVE-2026-48998 | guzzlehttp/psr7 | 2.1.0 | 2.10.2 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/psr7 has Host Confusion via Authority Reinterpretation |
| 1 | MEDIUM | CVE-2026-49214 | guzzlehttp/psr7 | 2.1.0 | 2.10.2 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/psr7 has CRLF Injection via URI Host Component |
| 1 | MEDIUM | CVE-2026-55766 | guzzlehttp/psr7 | 2.1.0 | 2.12.1 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/psr7: CRLF Injection in HTTP Start-Line Serialization |
| 1 | MEDIUM | CVE-2026-59882 | guzzlehttp/psr7 | 2.1.0 | 2.12.3 | php-fpm:9000, nginx:80,8443,443 (über php-fpm), httpd-prefork:8080 | http://www.example.org/app/, http://example.org/app/ (+3) | guzzlehttp/psr7: Host Confusion via Weak URI Host Validation |
| 1 | MEDIUM | CVE-2015-9251 | jquery | 1.12.4 | 3.0.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://www.example.org/app/, http://example.org/app/ (+3) | Cross-Site Scripting (XSS) in jquery |
| 1 | MEDIUM | CVE-2015-9251 | jquery | 1.12.4 | 3.0.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://localhost/, http://www.example.org/ (+3) | Cross-Site Scripting (XSS) in jquery |
| 1 | MEDIUM | CVE-2019-11358 | jquery | 1.12.4 | 3.4.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://www.example.org/app/, http://example.org/app/ (+3) | XSS in jQuery as used in Drupal, Backdrop CMS, and other products |
| 1 | MEDIUM | CVE-2019-11358 | jquery | 1.12.4 | 3.4.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://localhost/, http://www.example.org/ (+3) | XSS in jQuery as used in Drupal, Backdrop CMS, and other products |
| 1 | MEDIUM | CVE-2020-11022 | jquery | 1.12.4 | 3.5.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://www.example.org/app/, http://example.org/app/ (+3) | Potential XSS vulnerability in jQuery |
| 1 | MEDIUM | CVE-2020-11022 | jquery | 1.12.4 | 3.5.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://localhost/, http://www.example.org/ (+3) | Potential XSS vulnerability in jQuery |
| 1 | MEDIUM KEV | CVE-2020-11023 | jquery | 1.12.4 | 3.5.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://www.example.org/app/, http://example.org/app/ (+3) | Potential XSS vulnerability in jQuery |
| 1 | MEDIUM KEV | CVE-2020-11023 | jquery | 1.12.4 | 3.5.0 (anderer Versionszweig: Upgrade nötig) | php-fpm:9000, httpd-prefork:8080, nginx:80,8443,443 | http://localhost/, http://www.example.org/ (+3) | Potential XSS vulnerability in jQuery |

KEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).

## Anhang

### Komponenten (gesamt / von Diensten mit offenem Port genutzt)

| Typ | gesamt | genutzt | dev |
|---|---|---|---|
| composer | 2 | 2 | 0 |
| js-lib | 2 | 2 | 0 |
| os-paket | 220 | 29 | 0 |
| runtime | 2 | 2 | 0 |
| runtime-lib | 4 | 4 | 0 |
| server | 2 | 2 | 0 |

### Host

```
Name:      web01.example.com
Kernel:    6.18.44-fc-v445
Adressen:  lo=127.0.0.1 eth0=172.17.0.2
```

### Laufende Prozesse (außerhalb von Containern)

```
PID     USER       COMMAND
1       0          sleep infinity
8       498        dbus-daemon --system --fork
9       0          /usr/bin/python3 /usr/sbin/firewalld --nofork --nopid
50      0          php-fpm: master process (/etc/php8/fpm/php-fpm.conf)
51      0          /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
67      499        php-fpm: pool www
68      499        php-fpm: pool www
69      0          nginx: master process nginx
70      497        nginx: worker process
71      0          /bin/sh /usr/local/sbin/start.sh
73      0          python3 -m http.server 8000
74      499        /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
75      499        /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
76      499        /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
77      499        /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
78      499        /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Includ
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

- PID 70 (/usr/sbin/nginx): /[aio] (deleted)

ACHTUNG: Diese Prozesse nutzen noch alte Dateiversionen – Dienst neu starten.

### Webserver-Konfiguration (Auszug)

```
--- /usr/sbin/httpd-prefork -DSYSCONFIG -C PidFile /run/httpd.pid -C Include /etc/apache2/sysconfig.d//loadmodule.conf -C Include /etc/apache2/sysconfig.d//global.conf -f /etc/apache2/httpd.conf -c Include /etc/apache2/sysconfig.d//include.conf -DFOREGROUND -S
VirtualHost configuration:
127.0.0.1:8080         app.example.org (/etc/apache2/vhosts.d/app.conf:2)
ServerRoot: "/srv/www"
Main DocumentRoot: "/srv/www/htdocs"
Main ErrorLog: "/var/log/apache2/error_log"
Mutex ssl-stapling-refresh: using_defaults
Mutex ssl-stapling: using_defaults
Mutex proxy: using_defaults
Mutex ssl-cache: using_defaults
Mutex default: dir="/run/" mechanism=default 
Mutex mpm-accept: using_defaults
PidFile: "/run/httpd.pid"
Define: SYSCONFIG
Define: FOREGROUND
Define: DUMP_VHOSTS
Define: DUMP_RUN_CFG
User: name="wwwrun" id=499
Group: name="www" id=486
--- /usr/sbin/httpd-prefork -M
Loaded Modules:
 core_module (static)
 so_module (static)
 http_module (static)
 mpm_prefork_module (static)
 unixd_module (static)
 systemd_module (static)
 actions_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_host_module (shared)
 authz_groupfile_module (shared)
 authz_core_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 cgi_module (shared)
 dir_module (shared)
 env_module (shared)
 expires_module (shared)
 include_module (shared)
 log_config_module (shared)
 mime_module (shared)
 negotiation_module (shared)
 setenvif_module (shared)
 ssl_module (shared)
 socache_shmcb_module (shared)
 userdir_module (shared)
 reqtimeout_module (shared)
 proxy_module (shared)
 proxy_fcgi_module (shared)
 status_module (shared)

--- /usr/sbin/nginx -T (Auszug)
# configuration file /etc/nginx/nginx.conf:
    server {
        listen       80;
        server_name  localhost;
        location / {
            root   /srv/www/htdocs/;
        location = /50x.html {
            root   /srv/www/htdocs/;
# configuration file /etc/nginx/mime.types:
# configuration file /etc/nginx/vhosts.d/www.conf:
server {
    listen 80;
    listen 443 ssl;
    server_name www.example.org example.org;
    root /srv/www/htdocs;
    location /app/ {
        proxy_pass http://127.0.0.1:8080/;
    location /nginx_status { stub_status; }     # ohne allow/deny: WEB-STATUS
server {
    listen 8443 ssl;
    server_name partner.example.org;
    location / { proxy_pass http://127.0.0.1:8080/; }
server {
    listen 80;
    server_name intranet.example.local;
    root /srv/www/intranet;
```
