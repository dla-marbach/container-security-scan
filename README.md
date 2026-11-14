# container-security-scan

Schwachstellen-Scan für **laufende Docker-Container** und die **Dienste direkt auf dem Server** (z. B. nginx,
Apache und php-fpm unter SLES 15). Gemeldet wird vor allem, was ein von außen erreichbarer Dienst tatsächlich
nutzt. Eine Python-Datei, nur Standardbibliothek, ab Python 3.6, rein lesend; Paketlisten verlassen den Server
nie.

Was Image-Scanner wie Trivy oder Grype nicht sehen:

- Anwendungen in **Volumes** (z. B. PHP samt `vendor/`), **eingebettete JavaScript-Bibliotheken** (jQuery 1.x)
- **Laufzeiten aus offiziellen Images** (PHP, Node.js, Python aus dem Quellcode gebaut, ohne OS-Paket)
- welcher Dienst eine Komponente lädt und ob er **erreichbar** ist – auch hinter Reverse Proxys
  (nginx → Apache → php-fpm), im Nachbarcontainer oder hinter firewalld auf dem Host

## So sieht ein Lauf aus

```bash
sudo /usr/local/sbin/container-security-scan-lauf
```

Ausschnitt aus dem Lauf über die [Testumgebung](beispiele/umgebung/compose.yml) (nginx vor PHP-FPM und Node.js,
Traefik mit Docker-Socket; vollständig: [Konsolenausgabe](beispiele/ausgabe.txt)):

```
app-php: RELEVANTE SCHWACHSTELLEN – 1384 Befunde, davon 65 relevant (65 neu, 4 aktiv ausgenutzt), … öffentlich: php-fpm:9000 – Bericht: …/scan_app-php.md
app-php:   Webadressen php-fpm:9000: erreichbar: http://shop.example.org:8080/ (\.php$)
app-php:   CVE-2026-109618 (CRITICAL KEV) in php 8.3.30 – behoben in 8.3.36 – genutzt von php-fpm:9000 – Webadressen: http://shop.example.org:8080/ (\.php$) – aktiv ausgenutzt (KEV seit 2026-10-26)
app-php:   CVE-2022-29248 (HIGH) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.3 – genutzt von php-fpm:9000 (Docroot unbekannt)
…
app-traefik:   CONF-SOCKET: /var/run/docker.sock eingebunden als /var/run/docker.sock: Zugriff auf die Container-Laufzeit = root auf dem Host (auch schreibgeschützt)
…
ERGEBNIS: FUNDE (Rückgabewert 1) – <rechner>
```

- Von 1384 Befunden sind 65 **relevant**: php-fpm ist über nginx erreichbar (Priorität P1), die Lücken sind
  schwer bzw. aktiv ausgenutzt (`KEV`), und es gibt einen Fix.
- `Webadressen` zeigt, über welche Adresse die Komponente erreichbar ist.
- `CONF-SOCKET` ist eine [gefährliche Einstellung](#gefährliche-einstellungen-des-containers): Wer Traefik
  übernimmt, ist root auf dem Host.
- Der Bericht je Container ([Beispiel](beispiele/scan_app-php.md)) enthält alle Befunde, Dienste und Ports.

Weitere Beispiele: SLES-15-Server mit nginx → Apache → php-fpm und firewalld ([Bericht](beispiele/host_web01.md),
[Konsolenausgabe](beispiele/ausgabe-host.txt)), Einzelscan eines Containers
([Konsolenausgabe](beispiele/ausgabe-einzeln.txt)), SBOM ([CycloneDX](beispiele/scan_app-node.cdx.json)).

## Installation und Betrieb

Der Scan läuft als root, deshalb sind Code und Daten getrennt. Den **Code** installiert root von Hand aus einem
Release (Git-Tag). Die **Daten** holt der Benutzer `csscan` ohne Rechte bei jedem Lauf per `git pull` aus dem
Branch [`daten`](https://github.com/dla-marbach/container-security-scan/tree/daten).

```
/opt/container-security-scan/                  Code (container-security-scan.py)
/var/lib/container-security-scan/daten/        Daten (Branch daten, Benutzer csscan)
/usr/local/sbin/container-security-scan-lauf   Wrapper: Daten aktualisieren, dann scannen
/etc/container-security-scan/ausnahmen.txt     Ausnahmeliste
/var/log/container-security-scan/              Logs; Berichte unter berichte/
```

### Einrichten

Voraussetzungen: Linux, Python ≥ 3.6, `git`, `curl`; für Container Docker; für den Host `rpm` bzw. `dpkg`, `ip`,
optional firewalld.

Das [Installscript](installation/installieren.sh) aus dem
[aktuellen Release](https://github.com/dla-marbach/container-security-scan/releases/latest) holen, lesen und
ausführen:

```bash
V=vX.Y.Z      # Version des Releases
curl -fsSO https://raw.githubusercontent.com/dla-marbach/container-security-scan/$V/installation/installieren.sh
less installieren.sh
sudo bash installieren.sh $V
# mit Proxy (gilt auch für das git pull der Daten): sudo env https_proxy=http://proxy:3128 bash installieren.sh $V
```

Es bricht ab, bevor es etwas ändert, wenn `$V` kein Tag ist oder nicht zur Version im Code passt. Code und
[Wrapper](installation/container-security-scan-lauf) ersetzt es jedes Mal; Benutzer, Daten und
[Ausnahmeliste](installation/ausnahmen.txt) legt es nur an, wenn sie fehlen.

Optional mit geprüfter Signatur des Tags (Schutz gegen eine Übernahme des GitHub-Kontos). Das Installscript
bricht ab, wenn der Tag nicht auf den angegebenen Commit zeigt:

```bash
# Schlüssel des Maintainers vorher importieren: https://github.com/felixlohmeier.gpg
git clone -q https://github.com/dla-marbach/container-security-scan.git /tmp/css && cd /tmp/css \
  && git verify-tag $V && git checkout -q $V \
  && sudo bash installation/installieren.sh $V "$(git rev-parse HEAD)"
```

### Scannen

```bash
sudo /usr/local/sbin/container-security-scan-lauf            # Host und alle laufenden Container
sudo /usr/local/sbin/container-security-scan-lauf app-php    # nur dieser Container
```

Ohne Docker prüft der Wrapper nur den Host. Ein einzelner Container wird ohne den Host geprüft und ohne die
Proxys in anderen Containern: Ist er nur über einen solchen erreichbar, erscheinen seine Dienste als P2 statt P1.

### Täglich per cron oder Rundeck

Die Daten werden täglich um 03:17 UTC aktualisiert (oft bis zu einer Stunde später); den Scan danach ansetzen.

cron (`/etc/cron.d/container-security-scan`, Mail an root nur bei Rückgabewert 1 oder 2):

```cron
MAILTO=""
23 7 * * * root /usr/local/sbin/container-security-scan-lauf --mail >/dev/null 2>&1
```

Rundeck darf per sudo nur den Wrapper ohne Argumente starten (`""` verbietet Argumente):

```bash
echo 'rundeck ALL=(root) NOPASSWD: /usr/local/sbin/container-security-scan-lauf ""' > /etc/sudoers.d/rundeck-container-scan
chmod 440 /etc/sudoers.d/rundeck-container-scan && visudo -c
```

- Job-Schritt „Command“ (nicht „Script“): `sudo -n /usr/local/sbin/container-security-scan-lauf`; bei
  `requiretty` zusätzlich `Defaults:rundeck !requiretty`.
- Zeitlimit großzügig (bis zu 30 Minuten je Container); Server auf demselben Host nacheinander.
- 1 und 2 sind in Rundeck beide rot; die letzte Zeile `ERGEBNIS: FUNDE` bzw. `ERGEBNIS: UNVOLLSTAENDIG`
  unterscheidet sie.
- Optional den SSH-Schlüssel auf den Befehl festlegen (`~rundeck/.ssh/authorized_keys`):
  `command="sudo -n /usr/local/sbin/container-security-scan-lauf",from="<IP>",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA…`

### Auf das Ergebnis reagieren

| Rückgabewert | `ERGEBNIS:` | Bedeutung | Zu tun |
|---|---|---|---|
| `0` | `OK` | nichts Relevantes gefunden | nichts |
| `1` | `FUNDE` | relevante Schwachstellen, [gefährliche Einstellungen](#gefährliche-einstellungen-des-containers) oder auf dem Host erreichbare [Einstellungen der Webserver](#einstellungen-der-webserver) | Funde ansehen (neue sind markiert), Images bzw. Pakete aktualisieren (SLES: `zypper patch`), Einstellungen beheben; Fehlalarme und akzeptierte Risiken in die [Ausnahmeliste](#ausnahmen) |
| `2` | `UNVOLLSTAENDIG` | **Prüfung unvollständig – nie als „sauber“ werten** | Meldung lesen und Ursache beheben |

Gründe für `2` sind z. B.: Docker nicht erreichbar, Daten fehlen oder sind älter als 3 Tage, Dateien, Prozesse
oder Webserver-Konfiguration nicht vollständig lesbar, Distribution ohne Sicherheitsupdates (Supportende),
Ausnahmeliste fehlerhaft, Host-Scan nicht als root.

[Warnungen](#warnungen) (Supportende, Dienst als root, Neustart für neuen Kernel …) ändern den Rückgabewert nicht.

### Aktualisieren

1. Änderungen ansehen: Hinweise im Release und `…/compare/vA.B.C...vX.Y.Z`. Die installierte Version nennen jedes
   Log und `python3 /opt/container-security-scan/container-security-scan.py --version`.
2. Das Installscript des neuen Releases wie unter [Einrichten](#einrichten) ausführen. Daten, Ausnahmeliste und
   Berichte bleiben; eigene Änderungen am Wrapper werden ersetzt.

Ein automatisches Update des Codes gibt es bewusst nicht.

### Ohne Zugriff auf GitHub

Soll GitHub nicht die Datenquelle sein, lädt `csscan` die Daten direkt von den Quellen (OSV, endoflife.date,
CISA, SUSE). Dafür ohne Branch `daten` installieren:

```bash
sudo env DATEN= bash installieren.sh $V
```

Erreicht der Server `github.com` gar nicht, den Tag auf einem anderen Rechner als Bundle verpacken:

```bash
git clone -q https://github.com/dla-marbach/container-security-scan.git css && git -C css bundle create ../css.bundle $V
git -C css show $V:installation/installieren.sh > installieren.sh     # beides auf den Server kopieren, dort:
sudo env REPO=$PWD/css.bundle DATEN= bash installieren.sh $V
```

Nach jeder Installation im Wrapper die Zeilen mit `git pull` und `ARGS=` ersetzen:

```bash
  runuser -u csscan -- python3 -I "$CODE" --db "$D/osv-db" --db-aktualisieren \
      || { echo "FEHLER: Daten nicht aktualisiert (direkt von OSV)"; exit 2; }
ARGS=(--db "$D/osv-db")
```

Der erste Lauf lädt ca. 1,25 GB, danach meist 30–40 MB pro Tag; bei vielen Änderungen lädt er den Gesamtexport
eines Ökosystems neu (Ubuntu ca. 800 MB, etwa ein- bis zweimal pro Woche). Die Ergebnisse sind gleich, das
Einlesen dauert länger (Ubuntu ca. 30 statt 5 s je Container).

## Ergebnis verstehen

### Priorität und Relevanz

| | Komponente genutzt von … |
|---|---|
| **P1** | einem erreichbaren Dienst (siehe [Erreichbarkeit](#erreichbarkeit)) |
| **P2** | einem Dienst mit nur internem Port; auf dem Host auch der laufende Kernel |
| **P3** | einem Prozess ohne offenen Port |
| **P4** | keinem erkannten Prozess, oder Entwicklungsabhängigkeit |

**Relevant** (Rückgabewert 1) sind P1 CRITICAL/HIGH und P2 CRITICAL (`RELEVANT` im Skript) sowie jede **aktiv
ausgenutzte Lücke** aus dem [KEV-Katalog der CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
auch als P4 – Programme wie ImageMagick oder ffmpeg laufen nur bei Bedarf. Der Wrapper zählt nur Funde mit Fix
(`--nur-behebbare`). Nicht relevant sind Funde aus der Ausnahmeliste, Funde ohne Schweregrad (eigens
ausgewiesen) und Lücken, die laut Titel nur Windows betreffen.

„Genutzt von“ ermittelt der Scan aus `/proc` (Programm, geladene Bibliotheken, offene Dateien und Ports) und für
npm/Composer/PyPI über das Projektverzeichnis (Arbeitsverzeichnis, Skriptpfad, venv, Docroot des Webservers).

Schweregrad: Einstufung der Distribution (SUSE: SUSEs eigene CVSS-Bewertung), sonst der Quelle, sonst CVSS.
Fehlt er, gilt die Bewertung derselben CVE aus den Bitnami- bzw. Alpine-Daten, markiert mit `*` (`CRITICAL*`).
Kernel-Pakete werden in Containern nicht geprüft (sie nutzen den Kernel des Hosts).

### Erreichbarkeit

„Öffentlich“ heißt: von außerhalb des Servers erreichbar. Internet und Intranet sind auf dem Server nicht zu
unterscheiden und zählen gleich; eine Testumgebung mit derselben Konfiguration liefert dieselben Funde.
Grundsatz: **im Zweifel erreichbar.** Erkannt werden:

- veröffentlichte Ports (auch an `127.0.0.1`), Host-Netzwerk, eigene Adresse im LAN (macvlan, ipvlan, geroutet),
  gemeinsamer Netzwerk-Namespace (`network_mode: container:…`)
- Backends eines erreichbaren nginx oder Apache – im Container oder direkt auf dem Host, auch über mehrere Stufen
  (`proxy_pass`, `fastcgi_pass`, `upstream`, `ProxyPass`, `SetHandler proxy:`, Variablen aus `set`/`map`), Ziel
  per Container-Name, IP oder `127.0.0.1`
- Ziele aus Traefik- und caddy-docker-proxy-Labels
- Container, die eine erreichbare Anwendung aufruft (Ziel-URLs in Umgebung oder Kommandozeile, offene
  Verbindungen); Datenbanken und Caches als Ziel zählen nicht
- Tunnel-Agenten (cloudflared, frpc, ngrok, chisel)
- **möglicherweise erreichbar** (mit Warnung): Container im Docker-Netz eines Proxys, dessen Ziele nicht
  vollständig bekannt sind (Traefik, Caddy, HAProxy, Envoy, Varnish; nginx mit nicht auflösbarer Variable)

Ein Dienst, der nur auf Loopback lauscht, ist nur über einen Proxy mit demselben Loopback erreichbar.

**Auf dem Host** ist ein Port erreichbar, wenn er nicht nur auf Loopback oder an einem Container-Netz lauscht und
**firewalld** ihn durchlässt (Runtime-Konfiguration: Zonen, Dienste, Ports, Rich Rules, Policies; eine Freigabe
nur für bestimmte Quellen zählt). Ohne firewalld gilt jeder Port als erreichbar. Ports von `docker-proxy` sind
immer erreichbar, da Docker an firewalld vorbei weiterleitet.

### Webadressen

Aus `server_name`/`listen` (nginx) und den vHosts (Apache) bildet der Scan die Webadressen je Dienst, z. B.
`https://www.example.org/`. Leitet ein Webserver einen Pfad weiter, erscheint die Adresse beim Ziel:
`https://www.example.org/app/ (\.php$)` bei php-fpm hinter Apache hinter nginx. Jeder Fund nennt die Adressen
der Dienste, die die Komponente nutzen. Die Adressen stammen aus der Konfiguration, nicht aus dem DNS.

### Gefährliche Einstellungen des Containers

Einstellungen, mit denen aus einer Lücke im Container root auf dem Host wird. Sie sind **immer relevant**, auch
mit `--nur-behebbare`:

| Kennung | Befund |
|---|---|
| `CONF-PRIVILEGED` | `--privileged` |
| `CONF-SOCKET` | `docker.sock`, `containerd.sock` oder `podman.sock` eingebunden, auch über ein Verzeichnis wie `/run` oder `/` und auch mit `:ro` |
| `CONF-PID-HOST` | `pid=host` |
| `CONF-CAP-…` | Capability `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH` oder `BPF` (z. B. `CONF-CAP-SYS-ADMIN`) |
| `CONF-SECCOMP-UNCONFINED`, `CONF-APPARMOR-UNCONFINED` | Schutzprofil abgeschaltet |
| `CONF-HOST-PFAD` | Systempfad des Hosts beschreibbar eingebunden: `/etc` (oder Teile wie `shadow`, `sudoers`, `cron*`), `/root`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/usr`, `/proc`, `/sys`, `/dev`, `/home` bzw. `~/.ssh`, `/var/lib/docker` |

Typischer Fall ist Traefik mit `docker.sock`: besser einen Socket-Proxy mit Lesezugriff vorschalten (z. B.
`tecnativa/docker-socket-proxy`), sonst eine [Ausnahme](#ausnahmen) mit dem Containernamen.

### Einstellungen der Webserver

Einstellungen von nginx und Apache, die Informationen preisgeben. Auf dem Host sind sie relevant, wenn der
Webserver erreichbar ist; im Container vorerst nur eine Warnung.

| Kennung | Befund |
|---|---|
| `WEB-STATUS` | Statusseite ohne Zugriffsbeschränkung (nginx `stub_status`, Apache `server-status`/`server-info`); auch „nur localhost“, wenn ein Proxy auf derselben Maschine davor steht |
| `WEB-AUTOINDEX` | Verzeichnisliste (nginx `autoindex on`, Apache `Options Indexes`) |
| `WEB-TLS-ALT` | nur Host: ein erreichbarer TLS-Port nimmt TLS 1.0 oder 1.1 an (per Verbindungsaufbau geprüft) |

### Warnungen

Ohne Einfluss auf den Rückgabewert, im Bericht und auf der Konsole:

- **Öffentlicher Dienst als root**, z. B. Node oder Python (nginx, Apache und php-fpm mit unprivilegierten
  Workern nicht; entfällt mit userns-remap oder rootless Docker).
- **Datenbank, Cache oder Message Broker direkt erreichbar** (z. B. `ports: ["5432:5432"]`): `ports:` entfernen
  oder an `127.0.0.1` binden.
- **Supportende** bzw. Supportende in den nächsten 90 Tagen (Daten von [endoflife.date](https://endoflife.date))
  für Bibliotheken und Frameworks (Laravel, Symfony, Django, jQuery, Spring, Log4j …) und für Laufzeiten und
  Server, die nicht aus einem OS-Paket stammen. Bei OS-Paketen zählt der Support der Distribution.
- **Kernel** (Host): neuerer Kernel installiert (Neustart nötig) oder Live-Patches vorhanden.
- Proxy nicht vollständig auswertbar, Einstellungen der Webserver im Container, veraltete EOL-, KEV- oder
  SUSE-Daten.

### Ausnahmen

Für Fehlalarme und bewusst akzeptierte Risiken. Datei `/etc/container-security-scan/ausnahmen.txt` (root, nur
für root beschreibbar; anfangs nur auskommentierte [Beispiele](installation/ausnahmen.txt)):

```
# Kennung       Paket oder *  gültig bis  Begründung
CVE-2024-8926   php           2027-06-30  betrifft nur PHP-CGI unter Windows (geprüft 2026-11-05)
CONF-SOCKET     traefik       2027-03-31  liest nur Labels, Umstieg auf Socket-Proxy geplant
WEB-AUTOINDEX   downloads.example.org  2027-06-30  Verzeichnisliste gewollt, nur öffentliche Dateien
```

- Paket wie in der Spalte „Paket“ des Berichts; bei `CONF-…` der Containername, bei `WEB-…` der erste Name der
  Website.
- Nach dem Ablaufdatum zählt der Fund wieder (mit Warnung). Ausgenommene Funde stehen im Bericht unter „Nicht
  gezählt“.
- Eine fehlerhafte Zeile ergibt Rückgabewert 2, statt still etwas auszublenden.

### Berichte

Je Container bzw. Host im Ausgabeverzeichnis, nur für den Aufrufer lesbar (sie enthalten Kommandozeilen der
Prozesse, oft mit Passwörtern):

| Datei | Inhalt |
|---|---|
| `scan_<container>_<zeit>.md`, `host_<rechner>_<zeit>.md` | Bericht: relevante Funde und Warnungen, Dienste mit Ports und Webadressen, alle Befunde nach Priorität, Prozesse, Webserver-Konfiguration; beim Host auch Firewall |
| `….cdx.json` | SBOM (CycloneDX 1.5), auch mit Trivy, Grype oder Dependency-Track nutzbar |
| `….sha256` | Prüfsummen |
| `bekannt_<container>.json`, `bekannt-host.json` | relevante Funde des letzten Laufs, für die Markierung „neu“ |

## Aufruf ohne Wrapper

Für Sonderfälle; nutzt die vorhandenen Daten, ohne sie zu aktualisieren:

```bash
C=/opt/container-security-scan/container-security-scan.py; DB=/var/lib/container-security-scan/daten
sudo python3 -I $C --db $DB --host --alle-container --nur-behebbare <ausgabeverzeichnis>   # wie der Wrapper
sudo python3 -I $C --db $DB --host <ausgabeverzeichnis>                                    # nur der Host
sudo python3 -I $C --db $DB --alle <container> <ausgabeverzeichnis>                        # ein Container, alle Befunde
```

| Option | Bedeutung |
|---|---|
| `--alle-container` | alle laufenden Container, zuerst die erreichbaren und die Backends ihrer Proxys |
| `--oeffentliche` | nur die erreichbaren Container und deren Backends |
| `--host` | den Server selbst prüfen (vor den Containern); nur als root vollständig |
| `--nur-behebbare` | nur Funde mit Fix zählen – empfohlen, sonst melden ungepatchte Lücken dauerhaft `1` |
| `--alle` | alle Befunde in die Tabelle (sonst P3/P4 nur CRITICAL/HIGH/KEV) |
| `--ausnahmen DATEI` | [Ausnahmeliste](#ausnahmen) |
| `--db DIR` | Datenverzeichnis; mehrfach möglich, je Ökosystem gilt das erste, das es enthält. Standard: `daten/` und `osv-db/` neben dem Skript |
| `--db-aktualisieren` | Daten holen (nie als root, nie den Code): im Git-Checkout den Branch `daten` nach `daten/`; mit `--db DIR` alle Daten direkt von den Quellen; `--oekosysteme A,B` lädt weitere Ökosysteme (z. B. openSUSE) nach `osv-db/`, `--voll` alles neu |
| `--user` | Benutzer für `docker exec` (Standard `0`); ein anderer kann meist nicht alles lesen (dann `2`) |
| `--version` | Version anzeigen |

## Was geprüft wird

| Bereich | Quelle | Abgleich |
|---|---|---|
| OS-Pakete | dpkg, apk, rpm (über das Quellpaket) | Debian, Ubuntu, Alpine, SUSE (SLES 15 und 16; optional openSUSE) |
| npm | `package.json` | npm |
| Composer | `vendor/composer/installed.json` | Packagist |
| PyPI | `*.dist-info`, `*.egg-info` (auch venvs) | PyPI |
| Java | JAR/WAR/EAR, auch verschachtelt | Maven |
| Go | Build-Info in Go-Programmen | Go |
| JavaScript | eingebettete Bibliotheken (jQuery, Bootstrap, Moment, Vue …) | npm |
| Laufzeiten, Server | Version von node, php, php-fpm, python, java, nginx, apache, mariadb, postgresql | Distribution, sonst (offizielle Images, nginx.org, NodeSource, Sury, mariadb.org) OSV Bitnami |

Mit `--host` gilt das auch für den Server selbst: Prozesse außerhalb von Containern, OS-Pakete samt laufendem
Kernel und Anwendungen unter `/`, `/srv`, `/opt`, `/var/www`, `/usr/local`, den Docroots und Arbeitsverzeichnissen
der Dienste (nicht `/var/lib/docker`, `/.snapshots`, `/tmp`, `/var/log` u. a.).

**Daten** (Branch [`daten`](https://github.com/dla-marbach/container-security-scan/tree/daten), täglich von
[`daten.yml`](.github/workflows/daten.yml) erzeugt, ca. 380 MB): ein Auszug aus den OSV-Exporten mit nur den
Feldern und Einträgen, die der Abgleich liest (Ergebnisse identisch mit den vollständigen Exporten), dazu Supportende
(endoflife.date), KEV-Katalog (CISA) und SUSEs Schweregrade. Quellen und Lizenzen:
[`QUELLEN.md`](https://github.com/dla-marbach/container-security-scan/blob/daten/QUELLEN.md).

## Rein lesend

- Im Container laufen nur `find`/`tar`, ein sh-Skript, das `/proc` liest, und Versionsabfragen (`node -e`,
  `php -r` …) mit Zeitlimit – **nie mit mehr Rechten als der jeweilige Prozess**, Befehle über einen festen
  Suchpfad statt den `PATH` des Images. `docker diff` zeigt vor und nach dem Scan keine Änderung.
- `nginx -T` bzw. `apache2 -S` laufen mit dem Benutzer des Webservers, nicht als root.
- Ohne Shell im Container wird passiv gelesen (`docker export`, `docker cp`, `/proc` des Hosts); nichts wird auf
  dem Host entpackt.
- Auf dem Host: `firewall-cmd` und `ip` nur abfragend; die TLS-Prüfung ist ein Verbindungsaufbau zum eigenen
  Dienst (im Log des Webservers ggf. als abgebrochener Handshake).
- Es werden nur Daten heruntergeladen; Paketlisten verlassen den Server nie.

## Abgrenzung und Grenzen

Das Werkzeug beantwortet eine Frage: **Welche laufenden Dienste sind erreichbar, und welche verwundbaren
Komponenten nutzen sie?** Nicht vorgesehen sind allgemeine Härtung (CIS-Benchmarks, HTTP-Header, Cipher-Listen,
no-new-privileges …), weitere Paketfilter neben firewalld und Prüfungen der Konfiguration weiterer Dienste.
Dafür gibt es z. B. [Trivy](https://trivy.dev), [Grype](https://github.com/anchore/grype),
[Vuls](https://github.com/future-architect/vuls) oder [Kubescape](https://kubescape.io).

Bekannte Grenzen:

- Nicht erkannt: Rust, Ruby, .NET, Programme ohne Versionskennung, JavaScript-Bundles ohne Kopfkommentar,
  Fremdpaketquellen außer den genannten.
- Welche Pakete eine Anwendung tatsächlich importiert, ist von außen nicht sichtbar.
- Nur nginx und Apache werden als Proxy ausgewertet; andere machen ihre Nachbarn „möglicherweise“ erreichbar
  (eher zu viel). Ziele, die nur in Konfigurationsdateien einer Anwendung stehen (z. B. Spring
  `application.yml`), fehlen, wenn gerade keine Verbindung besteht.
- Webadressen über mehrere Proxy-Stufen sind nur richtig, wenn jedes Ziel mit Pfad `/` weiterleitet.
- Host: nur firewalld zur Laufzeit (nicht nftables/iptables direkt, dann im Zweifel erreichbar); Kernel-Live-Patches
  werden nicht berücksichtigt; `.htaccess` wird nicht ausgewertet; TLS 1.0/1.1 nur auf dem Host geprüft.
- Supportende nur für Produkte mit Paketkennung und die genannten Laufzeiten, nicht für einzelne OS-Pakete,
  Java-Laufzeiten oder Anwendungen wie WordPress.

## Entwicklung und Tests

Nur auf einem eigenen Testrechner, nicht auf Servern:

```bash
git clone https://github.com/dla-marbach/container-security-scan.git && cd container-security-scan
./container-security-scan.py --db-aktualisieren                              # Daten nach daten/ (nicht als root)
sudo ./container-security-scan.py --host --alle-container --nur-behebbare berichte/

python3 -m unittest discover -s tests                                        # Unit-Tests, ohne Docker
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit Docker und daten/
sudo bash beispiele/erzeugen.sh                                              # Beispiele neu erzeugen
```

- Was welche Testdatei prüft: [`tests/README.md`](tests/README.md). Die Action
  [`tests.yml`](.github/workflows/tests.yml) führt die Unit-Tests mit Python 3.6, 3.11, 3.13 und 3.14 aus, den Docker-Test
  bei Pull Requests und auf `main`.
- [Beispiele](beispiele/) im selben Pull Request neu erzeugen, wenn sich `VERSION` oder das Format der Berichte
  ändert (ein Test prüft die Version). Das Skript startet [`beispiele/umgebung/`](beispiele/umgebung/) und baut
  den SLES-Server aus [`beispiele/umgebung/host/`](beispiele/umgebung/host/); Optionen für `docker build` (z. B.
  Proxy) in `CSS_DOCKER_BUILD_ARGS`.
- Änderungen unter `installation/` aus einem Tag des committeten Stands ausprobieren (in einem temporären
  Klon, die eigenen Tags bleiben unberührt):

  ```bash
  V=v$(./container-security-scan.py --version | cut -d" " -f2) && rm -rf /tmp/css && git clone -q . /tmp/css
  git -C /tmp/css tag -f $V && git -C /tmp/css bundle create /tmp/css.bundle $V
  sudo env REPO=/tmp/css.bundle bash installation/installieren.sh $V && sudo /usr/local/sbin/container-security-scan-lauf
  ```

### Releases

Server installieren nur Git-Tags `vX.Y.Z` auf `main`. Die Version steht nur in `VERSION` in
`container-security-scan.py`. Jeder Pull Request, der den Code oder `installation/` ändert, erhöht sie: `Z` bei
Korrekturen ohne Einfluss auf Ergebnisse, `Y` bei neuen Funktionen oder anderer Bewertung, `X` bei inkompatiblen
Änderungen (Rückgabewerte, `ERGEBNIS: …`, Optionen, Schritte für Admins).

1. Im Pull Request: `VERSION` erhöhen, Beispiele neu erzeugen.
2. Nach dem Merge den Merge-Commit taggen und pushen: `git tag -s v0.2.0 -m v0.2.0 <commit> && git push origin v0.2.0`
   (die Action prüft, dass der Tag zu `VERSION` passt).
3. Auf GitHub ein Release anlegen und darin nennen, was Admins wissen müssen (Voraussetzungen, Rückgabewerte,
   Wrapper).

### Repository auf GitHub (Rulesets)

Damit das Token des Workflows nur die Daten ändern kann:

| Ruleset bzw. Einstellung | Regeln |
|---|---|
| Branch `main` | *Restrict deletions*, *Block force pushes*, *Require a pull request before merging*; optional *Require status checks* und *Require signed commits*; keine *Bypass list* für GitHub Actions |
| Branch `daten` | *Restrict deletions*, *Block force pushes* (die Action committet direkt) |
| Tags `v*` | *Restrict creations* (nur *Repository admin*), *Restrict updates*, *Restrict deletions* |
| *Actions → General → Workflow permissions* | *Allow GitHub Actions to create and approve pull requests* aus |

Gegen eine Übernahme des Kontos hilft das nicht, sondern nur der Blick auf die Änderungen vor jedem Update und die
Signatur des Tags.
