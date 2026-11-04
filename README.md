# container-security-scan

Schwachstellen-Scan für **laufende Docker-Container** – mit Fokus auf das, was tatsächlich läuft und
von außen erreichbar ist. Ein einzelnes Python-Skript, nur Standardbibliothek, ab Python 3.6
(SLES 15), rein lesend. Die Schwachstellendaten (gekürzter Auszug aus [OSV](https://osv.dev)) liegen
in diesem Repository und werden täglich per GitHub Action aktualisiert – auf dem Server genügt `git pull`,
Paketlisten verlassen den Server nie.

```bash
git clone https://github.com/felixlohmeier/container-security-scan.git
cd container-security-scan
./container-security-scan.py --oeffentliche berichte/ --nur-behebbare
echo $?        # 0 = ok, 1 = relevante Schwachstellen, 2 = Fehler/unvollständig
```

## Warum?

Übliche Scanner (Trivy, Grype, OSV-Scanner) prüfen **Images** oder Lockfiles. Für den Betrieb zählt,
was im **laufenden** Container steckt und ob es von außen erreichbar ist:

- Inhalte von **Volumes** (z. B. eine PHP-Anwendung samt `vendor/` im Volume) sieht ein Image-Scan nicht.
- **Laufzeiten aus offiziellen Images** (PHP, Node.js, Python sind dort aus dem Quellcode gebaut) haben
  kein OS-Paket – ein reiner Paket-Scan übersieht Lücken in der Laufzeit selbst (Beispiele aus 2026:
  PHP2Shell in PHP, Node2Shell in Node.js).
- **Eingebettete JavaScript-Bibliotheken** (z. B. jQuery 1.x unter `Resources/Public/…`) erkennt Trivy nicht.
- Von Tausenden Funden zählen die, die ein **öffentlich erreichbarer Dienst** tatsächlich lädt – auch
  hinter einem Reverse Proxy (nginx → php-fpm oder Node im Nachbarcontainer).

## Voraussetzungen

- Linux-Host mit Docker; Aufruf als root (empfohlen) oder Mitglied der Gruppe `docker`
- Python ≥ 3.6 (SLES 15: `python3`) und `git`
- optional `rpm` auf dem Host (nur für RPM-Container ohne eigenes `rpm`)

## Nutzung

```bash
# alle öffentlich erreichbaren Container (veröffentlichte Ports, Host-Netzwerk) und deren Backends hinter Proxys
./container-security-scan.py --oeffentliche [ausgabeverzeichnis]

# einen einzelnen Container
./container-security-scan.py <container> [ausgabeverzeichnis]

# Skript und Daten aktualisieren (= git pull)
./container-security-scan.py --db-aktualisieren

# zusätzliche Ökosysteme direkt von OSV laden (nach osv-db/), z. B. für Ubuntu-basierte Images
# wie mariadb, solr oder elasticsearch (ca. 800 MB)
./container-security-scan.py --db-aktualisieren --oekosysteme Ubuntu
```

| Option | Bedeutung |
|---|---|
| `--oeffentliche` | alle öffentlich erreichbaren Container; Backends hinter einem öffentlichen Proxy (auch in anderen Containern) werden mitgeprüft und zählen als öffentlich |
| `--nur-behebbare` | für den Rückgabewert nur Funde zählen, für die es einen Fix gibt – **empfohlen** für die Alarmierung, sonst melden Container mit offenen, noch unbehobenen CVEs dauerhaft `1` |
| `--alle` | alle Befunde in die Tabelle (sonst P3/P4 nur CRITICAL/HIGH) |
| `--db-aktualisieren` | im Git-Checkout `git pull`; mit `--oekosysteme A,B` zusätzlich direkt von OSV laden (inkrementell, `--voll` lädt alles neu) |
| `--db DIR` | anderes Datenverzeichnis (Standard: `osv-daten/` und `osv-db/` neben dem Skript) |
| `--user` | Benutzer für `docker exec` (Standard `0`) |

### Rückgabewert

| Wert | Bedeutung |
|---|---|
| `0` | keine relevanten Schwachstellen |
| `1` | relevante Schwachstellen gefunden |
| `2` | Fehler oder **Prüfung unvollständig** – nie als „sauber“ werten. Z. B.: docker nicht erreichbar, Container läuft nicht, Daten fehlen für ein benötigtes Ökosystem oder sind älter als 3 Tage, keine Paketdatenbank im Container, Dateien nicht vollständig lesbar, nginx-Konfiguration nicht lesbar, Distribution ohne aktuelle Sicherheitsdaten (EOL). |

**Relevant** ist P1 CRITICAL/HIGH und P2 CRITICAL (anpassbar über `RELEVANT` am Anfang des Skripts).

### Priorität

| | Bedeutung |
|---|---|
| **P1** | genutzt von einem öffentlich erreichbaren Dienst: Port veröffentlicht, Host-Netzwerk oder hinter einem öffentlichen Reverse Proxy |
| **P2** | genutzt von einem Dienst mit internem Port |
| **P3** | genutzt nur von einem Prozess ohne offenen Port |
| **P4** | installiert, aber nicht in Benutzung erkannt; oder Entwicklungsabhängigkeit (dev) |

„Genutzt von“ wird über `/proc` ermittelt: Programm und geladene Bibliotheken, geöffnete Dateien (JARs),
offene TCP/UDP-Ports; für npm/Composer/PyPI über das Projektverzeichnis (Arbeitsverzeichnis, Skriptpfad,
venv, Docroot aus der nginx-/Apache-Konfiguration). Welche Pakete eine Anwendung tatsächlich importiert,
ist von außen nicht sichtbar. Lässt sich ein veröffentlichter Port keinem Prozess zuordnen, werden
vorsichtshalber alle Komponenten des Containers als öffentlich genutzt gewertet (mit Warnung).

## Täglicher Betrieb

Neue Schwachstellen erscheinen in den OSV-Daten typischerweise 1–2 Tage nach Veröffentlichung; die
GitHub Action übernimmt sie täglich um 03:17 UTC in `osv-daten/`. Ein täglicher Lauf erkennt sie für
die bereits laufenden Versionen, ohne dass dafür etwas angepasst werden muss.

`/etc/cron.d/container-security-scan` (Mail nur bei Rückgabewert ≠ 0):

```cron
MAILTO=""
23 5 * * * root /opt/container-security-scan/taeglich.sh
```

`/opt/container-security-scan/taeglich.sh`:

```bash
#!/bin/bash
cd /opt/container-security-scan || exit 2
LOG=/var/log/container-security-scan/$(date +%F).txt
mkdir -p /var/log/container-security-scan/berichte
{ ./container-security-scan.py --db-aktualisieren &&
  ./container-security-scan.py --oeffentliche /var/log/container-security-scan/berichte --nur-behebbare; } > "$LOG" 2>&1
rc=$?
[ $rc -ne 0 ] && mail -s "container-security-scan $(hostname): Rückgabewert $rc" root < "$LOG"
exit $rc
```

- **1** → Funde prüfen und Images aktualisieren. Der Bericht markiert Funde, die seit dem letzten Lauf **neu** sind.
- **2** → Ursache beheben (Daten, Ökosystem ergänzen, Container), sonst ist die Überwachung blind.
- Warnungen zum Supportende sind keine OSV-Schwachstellen und ändern den Rückgabewert nicht.
- Der Host selbst (SLES) ist nicht Teil des Scans: dafür `zypper list-patches --category security`.

### Mit Rundeck

Rundeck übernimmt Zeitplan, Übersicht und Benachrichtigung; Skript und Daten bleiben auf jedem Server
(`git pull` dort). Rundeck darf per sudo nur genau dieses eine Skript starten – keine allgemeinen
root-Rechte, kein `docker`, kein `python3` mit beliebigen Argumenten. Wer Rundeck übernimmt, kann so
Scans auslösen, aber nicht root auf den Servern werden.

`/opt/container-security-scan/rundeck.sh` (statt `taeglich.sh` und cron):

```bash
#!/bin/bash
# Aufruf durch Rundeck: sudo -n /opt/container-security-scan/rundeck.sh
# Ausgabe ins Rundeck-Log, letzte Zeile "ERGEBNIS: ...", Rückgabewert wie beim Skript (0/1/2).
DIR=/opt/container-security-scan
LOGDIR=/var/log/container-security-scan
umask 077                                  # Berichte enthalten u. a. Prozess-Kommandozeilen
exec 9>/run/container-security-scan.lock
if ! flock -n 9; then
    echo "ERGEBNIS: UNVOLLSTAENDIG (Rückgabewert 2, Scan läuft bereits) – $(hostname)"
    exit 2
fi
mkdir -p "$LOGDIR/berichte"
LOG=$LOGDIR/$(date +%F_%H%M%S).txt
# mit Ubuntu-basierten Images: --db-aktualisieren --oekosysteme Ubuntu
{ cd "$DIR" &&
  ./container-security-scan.py --db-aktualisieren &&
  ./container-security-scan.py --oeffentliche "$LOGDIR/berichte" --nur-behebbare; } 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
case $rc in
    0) ergebnis=OK ;;
    1) ergebnis=FUNDE ;;
    *) ergebnis=UNVOLLSTAENDIG; rc=2 ;;
esac
echo "ERGEBNIS: $ergebnis (Rückgabewert $rc) – $(hostname)" | tee -a "$LOG"
exit $rc
```

Einrichtung auf jedem Server (als root):

```bash
chown -R root:root /opt/container-security-scan
chmod 755 /opt/container-security-scan/rundeck.sh
chmod -R go-w /opt/container-security-scan     # sonst könnte der Rundeck-Benutzer das Skript ändern

cat > /etc/sudoers.d/rundeck-container-scan <<'EOF'
rundeck ALL=(root) NOPASSWD: /opt/container-security-scan/rundeck.sh ""
EOF
chmod 440 /etc/sudoers.d/rundeck-container-scan
visudo -c
```

`""` am Ende verbietet zusätzliche Argumente. Den Benutzernamen an Ihren Rundeck-Benutzer anpassen; ist
`requiretty` gesetzt, zusätzlich `Defaults:rundeck !requiretty`. Optional lässt sich auch der SSH-Schlüssel
auf diesen Befehl festlegen (`~rundeck/.ssh/authorized_keys` auf dem Server; dann eigener Schlüssel nur
für diesen Job):

```
command="sudo -n /opt/container-security-scan/rundeck.sh",from="<IP des Rundeck-Servers>",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA… rundeck-container-scan
```

Rundeck-Job:

- Schritt „Command“: `sudo -n /opt/container-security-scan/rundeck.sh` – kein Schritt „Script“, der eine
  Datei auf den Server kopiert und ausführt (dafür bräuchte der Rundeck-Benutzer allgemeine root-Rechte).
- Zeitplan täglich mit Abstand zur Action (siehe oben), z. B. 07:23.
- Zeitlimit großzügig (mehrere Stunden): ein Container kann bis zu 30 Minuten dauern.
- Teilen sich Server Ressourcen (VMs auf demselben Host, gemeinsamer Speicher), die Server nacheinander
  oder in kleinen Gruppen abarbeiten statt alle parallel.
- Benachrichtigung bei Fehlschlag. Rundeck kennt nur Erfolg oder Fehlschlag: Rückgabewert 1 und 2 sind
  beide rot, die Zeile `ERGEBNIS: FUNDE` bzw. `ERGEBNIS: UNVOLLSTAENDIG` am Ende des Logs unterscheidet sie.

Die Berichte und `bekannt_*.json` (Markierung „neu“) bleiben auf dem jeweiligen Server unter
`/var/log/container-security-scan/`; die Konsolenausgabe steht zusätzlich im Rundeck-Log.

## Ausgabe

Je Container im Ausgabeverzeichnis:

- `scan_<name>_<zeit>.md` – Bericht: Ergebnis (relevante Funde, neue zuerst, Warnungen), laufende Dienste
  mit Ports, Proxy-Backends und vHosts, Übersicht nach Priorität, Befundtabelle, nicht automatisch prüfbare
  Komponenten, Anhang (Prozesse, veraltete Bibliotheken im Speicher, Webserver-Konfiguration)
- `scan_<name>_<zeit>.cdx.json` – SBOM im Format CycloneDX 1.5 als Beleg (auch mit Trivy, Grype oder
  Dependency-Track nutzbar)
- `scan_<name>_<zeit>.sha256` – Prüfsummen
- `bekannt_<name>.json` – relevante Funde des letzten Laufs (für die Markierung „neu“)

Beispiele: [`beispiele/`](beispiele/) – ein Lauf `--oeffentliche --nur-behebbare` über eine Testumgebung
([Konsolenausgabe](beispiele/ausgabe_oeffentliche.txt)): nginx als öffentlicher Reverse Proxy vor Node,
Python und PHP-FPM in Nachbarcontainern, PHP 8.3.30 mit Apache (PHP2Shell), Node 22.22.0 nur über den Proxy
erreichbar (Node2Shell), ein PHP-Container mit eingebettetem jQuery 1.10.2 und Java-Bibliotheken, Solr
(Ubuntu-basiert, ohne Ubuntu-Daten → Rückgabewert 2).

## Was erfasst wird

| Bereich | Quelle im Container | Abgleich |
|---|---|---|
| OS-Pakete | dpkg (`status`, `status.d`), apk, rpm – inkl. Quellpaket | Debian, Alpine (optional Ubuntu, SUSE, openSUSE) |
| npm | jede `package.json` mit Name und Version | npm |
| Composer | `vendor/composer/installed.json` | Packagist |
| PyPI | `*.dist-info/METADATA`, `*.egg-info` (alle site-packages, auch venvs) | PyPI |
| Java | JAR/WAR/EAR inkl. verschachtelter Archive: `pom.properties`, Tomcat-Version, sonst Manifest/Dateiname (als unsicher markiert) | Maven |
| Go | Build-Info in Go-Programmen (Go-Version und Module) | Go |
| JavaScript | eingebettete Bibliotheken (jQuery, jQuery UI, Chart.js, Bootstrap, Moment, Vue, …) über Kopfkommentar/Dateiname | npm |
| Laufzeiten/Server | Version am Programm: node, php, php-fpm, python, java, nginx, apache, mariadb, postgresql | aus Distributionspaket: über die Distribution; sonst (offizielle Images, Herstellerquellen wie nginx.org, NodeSource, Sury, mariadb.org) über OSV Bitnami |
| Dienste | offene Ports, veröffentlichte Ports, nginx-/Apache-Konfiguration (vHosts, Docroot, Backends → Container) | Priorisierung |

Dateien, die zu einem OS-Paket gehören (z. B. `gosu` aus dem Ubuntu-Paket), werden wie bei Trivy nur
über das OS-Paket geprüft.

## Daten

`osv-daten/` enthält einen gekürzten Auszug aus den OSV-Exporten für Debian, Alpine, npm, PyPI, Packagist,
Maven, Go und Bitnami (ca. 170 MB, in Git komprimiert ca. 15 MB). Gekürzt heißt: nur die für den Abgleich
nötigen Felder; die Ergebnisse sind mit den vollständigen Exporten identisch (geprüft). Die GitHub Action
[`.github/workflows/osv-daten.yml`](.github/workflows/osv-daten.yml) erzeugt die Daten täglich neu; die
Ausgabe ist deterministisch, Commits enthalten nur echte Änderungen. Quellen und Lizenzen:
[`osv-daten/QUELLEN.md`](osv-daten/QUELLEN.md).

Ohne Git-Checkout (oder für weitere Ökosysteme) lädt `--db-aktualisieren --oekosysteme …` direkt von OSV
nach `osv-db/` – erst der Gesamtexport, danach nur Änderungen.

Für Ubuntu-basierte Varianten von MariaDB, Solr und Elasticsearch ist einmalig
`./container-security-scan.py --db-aktualisieren --oekosysteme Ubuntu` erforderlich. Der große Export
liegt nur lokal in `osv-db/`, nicht im Repository; bei späteren Aktualisierungen denselben Befehl
erneut ausführen. Maßgeblich ist die Distribution des jeweiligen Images, nicht der Imagename.
Fehlen die Ubuntu-Daten, bleibt das Ergebnis ausdrücklich unvollständig (Rückgabewert 2).

### Supportende (EOL)

`eol-daten.json` enthält einen Auszug aus [endoflife.date](https://endoflife.date) (MIT-Lizenz, siehe
[`EOL-LIZENZ.txt`](EOL-LIZENZ.txt)), den die Action täglich aus dem vollständigen API-Export
(`/api/v1/products/full/`) erzeugt. Geprüft werden:

- **Pakete** mit npm-, Composer-, PyPI- oder Maven-Kennung bei endoflife.date (z. B. Laravel, Vue,
  Angular, jQuery, Bootstrap, Django, Drupal, TYPO3, Spring, Log4j) sowie ergänzend Symfony, CakePHP,
  Twig, Shopware, Craft CMS, Contao, Electron und Tomcat (`EOL_ZUSATZ` im Skript);
- **Laufzeiten und Server**, die nicht aus einem OS-Paket stammen (offizielle Images, Herstellerquellen):
  PHP/PHP-FPM, Node.js, Python, nginx, Apache httpd, MariaDB, MySQL, PostgreSQL. Stammen sie aus einem
  OS-Paket, zählt der Support der Distribution (Debian portiert Sicherheitskorrekturen zurück); deren
  Supportende wird über die Sicherheitsdaten erkannt (Rückgabewert 2).

Verglichen werden nur numerische Versionszweige (`2.7.16` → Zweig `2.7`, sonst `2`). Ein abgelaufener
Zweig erscheint als **Warnung** „Supportende“, ein Zweig mit Supportende in den nächsten 90 Tagen als
„Supportende bald“ – im Bericht und auf der Konsole, **nicht** als CVE und ohne Einfluss auf den
Rückgabewert. Fehlende oder mindestens 30 Tage alte EOL-Daten werden ebenfalls als Warnung gemeldet.
Maßgeblich ist das reguläre Supportende, nicht kommerzieller Zusatzsupport (z. B. für PHP oder Node.js).
Ohne Git-Checkout lädt `--db-aktualisieren` die EOL-Daten direkt nach `osv-db/eol-daten.json`.

## Rein lesend und ohne Datenabfluss

- Im Container laufen nur: `find`/`tar` (Metadaten-Dateien lesen; Container-Dateisystem und Volumes,
  nicht eingebundene Host-Verzeichnisse wie `/var/lib/docker`), ein POSIX-sh-Skript, das `/proc` liest –
  je Prozess-Benutzer, da Docker auch root im Container keinen Zugriff auf fremde Prozesse gibt –, und
  Versionsabfragen der gefundenen Programme (`node -e`, `php -r`, `python -I -S -c`, `nginx -T`,
  `java -version` …) mit Zeitlimit, im Verzeichnis `/` und **nie mit mehr Rechten als der laufende Prozess**.
- Ohne Shell oder Werkzeuge im Container wird passiv gelesen (`docker export`, `docker cp`, `/proc` des Hosts).
- Der tar-Strom aus dem Container wird im Speicher gelesen; nichts wird auf dem Host entpackt.
- Getestet: `docker diff` zeigt vor und nach dem Scan keine Änderung im Container.
- Es werden nur Daten **heruntergeladen** (GitHub bzw. OSV und endoflife.date); Paketlisten verlassen den Server nicht.

## Grenzen

- Schweregrad: Einstufung der Distribution (Debian, Ubuntu), sonst Angabe der Quelle, sonst CVSS 3 bzw.
  eine Näherung für CVSS 4 (eher zu hoch). Als Schadsoftware gemeldete Pakete (`MAL-…`) gelten als CRITICAL.
  Einträge ganz ohne Bewertung („UNKNOWN“) zählen nicht als relevant, werden aber eigens ausgewiesen.
- Nicht erfasst: Rust, Ruby, .NET, Tcl, Programme ohne Versionskennung, Bundles ohne Kopfkommentar,
  Programme direkt auf dem Host, UDP-Dienste nur bei offenem Socket, Proxys außer nginx/Apache
  (Traefik, Caddy, HAProxy: Backends dann einzeln scannen).
- EOL-Abgleich nur für Produkte mit Paketkennung bzw. die genannten Laufzeiten/Server und nur für
  numerische Versionszweige; einzelne OS-Pakete, Java-Laufzeiten (herstellerabhängig) und Anwendungen
  ohne Paketkennung (z. B. WordPress, Nextcloud) werden nicht auf Supportende geprüft.
- Herstellerpaketquellen werden über typische Versionskennungen und Paketbetreuer erkannt
  (nginx.org, NodeSource, Sury, mariadb.org, PostgreSQL); andere Fremdquellen können unerkannt bleiben.
- Ohne `--oeffentliche` kennt ein Einzelscan keine Proxys in *anderen* Containern; Backends erscheinen dann als P2.
- nginx-Konfiguration: `nginx -T` wird mit `-p`/`-c` des laufenden Masterprozesses aufgerufen. Schlägt
  die Abfrage fehl, ist die Prüfung unvollständig (Rückgabewert 2), da Proxy-Backends fehlen könnten.

## Validierung

Getestet mit Python 3.6 und 3.13 (auch `LANG=C`) an Debian-, Ubuntu-, Alpine-, openSUSE- und
distroless-Containern (PHP/Apache, PHP-FPM, Node, Python, nginx, Solr, MariaDB), dazu eine unabhängige
Code-Prüfung mit gezielten Fehlerfällen (fehlende Werkzeuge im Container, Benutzerwechsel, venv über PATH,
`${APACHE_DOCUMENT_ROOT}`, nginx.org-Pakete, präparierte Module im Arbeitsverzeichnis, docker nicht
erreichbar). Abgleich mit Trivy (Image-Scan derselben Images, gleiche Datenstände):

- Paketerkennung: gleich (außer `gpg-pubkey`-Einträgen bei RPM, die keine Software sind).
- Schwachstellen: Trivy fand nichts, was das Skript nicht fand – bis auf Debians vorläufige
  `TEMP-…`-Kennungen ohne CVE und einzelne tzdata-Meldungen. Mehr Funde vor allem bei eingebetteten
  JavaScript-Bibliotheken, bei Laufzeiten aus offiziellen Images und bei offenen Ubuntu-CVEs ohne Fix.

### Tests

```bash
python3 -m unittest discover -s tests                                   # Unit-Tests, ohne Docker (ca. 1 s)
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit echten Containern
```

| Datei | Prüft |
|---|---|
| `test_versionen.py` | Versionsvergleiche (dpkg, rpm, apk, SemVer, PEP 440, Maven, PHP) und OSV-Versionsbereiche |
| `test_schweregrad.py` | CVSS 3/4, Vorrang von Quellen-Einstufung, Debian-Dringlichkeit, Ubuntu-Priorität, `MAL-…` |
| `test_inventar.py` | dpkg (auch distroless), apk, rpm, npm/Composer/PyPI, JS-Bibliotheken, JARs, Go-Build-Info, tar-Strom |
| `test_prozesse.py` | Prozesse, Ports und Dateien aus `/proc` (je Prozess-Benutzer bzw. über den Host), Volumes |
| `test_webserver.py` | nginx-/Apache-Konfiguration, `nginx -T` mit `-p`/`-c`, veröffentlichte Ports, Backends |
| `test_nutzung.py` | Zuordnung Komponente → Dienst, Erreichbarkeit, Priorität P1–P4 |
| `test_osv.py` | Abgleich je Ökosystem, Quellpakete, Fremdquellen über Bitnami, Datenformat, inkrementelle Aktualisierung |
| `test_eol.py` | EOL-Daten erzeugen, Supportende und Vorwarnung |
| `test_ausgabe.py` | Bericht, CycloneDX-SBOM, Gesamtlauf mit Rückgabewerten 0/1/2 und bekannten Funden |
| `test_kommandozeile.py` | Aufruf als Programm: Optionen, docker nicht erreichbar, unerwartete Fehler → 2 |
| `test_docker.py` | nginx (`-c`) als Proxy vor Node: Proxy-Erkennung, EOL-Warnungen, Berichte, `docker diff` unverändert |

Die GitHub Action [`tests.yml`](.github/workflows/tests.yml) führt die Unit-Tests mit Python 3.6, 3.11 und 3.13
sowie den Docker-Test aus.

## Verwandte Werkzeuge

- [Trivy](https://trivy.dev), [Grype](https://github.com/anchore/grype),
  [OSV-Scanner](https://github.com/google/osv-scanner): Images, Dateisysteme, SBOMs; ohne Laufzeitkontext.
- [Vuls](https://github.com/future-architect/vuls): agentloser Scanner für Server, kann betroffene Prozesse zeigen.
- [Kubescape](https://kubescape.io) „Relevancy“: priorisiert nach tatsächlich geladenen Paketen (eBPF, Kubernetes).
