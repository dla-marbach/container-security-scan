# container-security-scan

Schwachstellen-Scan für **laufende Docker-Container** – mit Fokus auf das, was tatsächlich läuft und
von außen erreichbar ist. Ein einzelnes Python-Skript, nur Standardbibliothek, ab Python 3.6 (SLES 15),
rein lesend. Die Schwachstellendaten (gekürzter Auszug aus [OSV](https://osv.dev), dazu Supportende und
aktiv ausgenutzte Lücken) liegen im Branch [`daten`](https://github.com/felixlohmeier/container-security-scan/tree/daten) und werden täglich per GitHub
Action aktualisiert; Paketlisten verlassen den Server nie.

Nach der [Einrichtung](#installation-und-betrieb) (einmalig, wenige Minuten):

```bash
sudo /usr/local/sbin/container-security-scan-lauf
# 0 = ok, 1 = relevante Schwachstellen oder gefährliche Einstellungen, 2 = Fehler/unvollständig
# Berichte unter /var/log/container-security-scan/
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

## Installation und Betrieb

Das Skript läuft als root, deshalb sind Code und Daten getrennt: Der **Code** ist eine Datei aus einem
Release (Git-Tag) und wird nur von Hand aktualisiert. Die **Daten** (Branch `daten`, nur JSON) holt
der Benutzer `csscan` ohne Rechte per `git pull`. Der Wrapper `container-security-scan-lauf` aktualisiert
die Daten und scannt dann als root – von Hand, per cron oder per Rundeck.

```
/opt/container-security-scan/                  Code (nur container-security-scan.py): root
/var/lib/container-security-scan/daten/        Daten (Branch daten): csscan, git pull bei jedem Lauf
/usr/local/sbin/container-security-scan-lauf   Wrapper: root
/etc/container-security-scan/ausnahmen.txt     Ausnahmeliste: root, anfangs nur auskommentierte Beispiele
/var/log/container-security-scan/              Berichte und Logs
```

### 1. Einrichten

Voraussetzungen: Linux mit Docker, Python ≥ 3.6 (SLES 15: `python3`), `git`, `curl`; optional `rpm` (nur für
RPM-Container ohne eigenes `rpm`).

Das Installscript [`installation/installieren.sh`](installation/installieren.sh) (zum Einrichten und
Aktualisieren) aus dem [aktuellen Release](https://github.com/felixlohmeier/container-security-scan/releases/latest)
holen, lesen und mit dessen Version ausführen:

```bash
V=vX.Y.Z      # Version des Releases
curl -fsSO https://raw.githubusercontent.com/felixlohmeier/container-security-scan/$V/installation/installieren.sh
less installieren.sh
sudo bash installieren.sh $V
```

Es holt den Tag per `git clone` und bricht ab, bevor etwas verändert ist, wenn es kein Tag ist oder die
Version im Skript nicht passt. Code und [Wrapper](installation/container-security-scan-lauf) ersetzt es jedes
Mal; Benutzer, Daten und Ausnahmeliste legt es nur an, wenn sie fehlen. Mit Proxy (gilt auch für das
tägliche `git pull` der Daten): `sudo env https_proxy=http://proxy:3128 bash installieren.sh $V`.

Den Code legt der Tag fest; Tags lassen sich nicht verschieben ([Rulesets](#repository-auf-github-rulesets)).
Gegen eine Übernahme des GitHub-Kontos hilft keine Angabe aus demselben Repository, sondern nur der Blick auf
die Änderungen vor jedem Update ([Schritt 5](#5-code-aktualisieren)) und die Signatur des Tags. Wer sie
prüft, gibt den Commit mit; das Installscript bricht ab, wenn der Tag auf einen anderen zeigt:

```bash
# Schlüssel des Maintainers vorher importieren: https://github.com/felixlohmeier.gpg
git clone -q https://github.com/felixlohmeier/container-security-scan.git /tmp/css && cd /tmp/css \
  && git verify-tag $V && git checkout -q $V \
  && sudo bash installation/installieren.sh $V "$(git rev-parse HEAD)"
```

Die [Ausnahmeliste](#ausnahmen) `/etc/container-security-scan/ausnahmen.txt` enthält anfangs nur
auskommentierte [Beispiele](installation/ausnahmen.txt). Sie muss root gehören und nur für root beschreibbar sein.

### 2. Bei Bedarf von Hand prüfen

```bash
sudo /usr/local/sbin/container-security-scan-lauf
```

Geprüft werden alle laufenden Container, zuerst die [erreichbaren](#erreichbarkeit) samt den Backends
hinter ihren Reverse Proxys. Nur ein Container (dann ohne Erreichbarkeit über Proxys in anderen Containern):

```bash
sudo /usr/local/sbin/container-security-scan-lauf <container>
```

### 3. Täglich: cron oder Rundeck

Die Daten werden täglich um 03:17 UTC aktualisiert (oft bis zu einer Stunde später); den Scan mit Abstand
ansetzen, z. B. 07:23 Ortszeit.

**cron** – `/etc/cron.d/container-security-scan` (Mail an root nur bei Rückgabewert 1 oder 2):

```cron
MAILTO=""
23 7 * * * root /usr/local/sbin/container-security-scan-lauf --mail >/dev/null 2>&1
```

**Rundeck** – statt cron. Rundeck darf per sudo nur den Wrapper ohne Argumente starten:

```bash
cat > /etc/sudoers.d/rundeck-container-scan <<'EOF'
rundeck ALL=(root) NOPASSWD: /usr/local/sbin/container-security-scan-lauf ""
EOF
chmod 440 /etc/sudoers.d/rundeck-container-scan && visudo -c
```

- `""` verbietet Argumente (kein `*`). `rundeck` an den eigenen Benutzer anpassen; bei `requiretty`
  zusätzlich `Defaults:rundeck !requiretty`.
- Job mit dem Schritt „Command“ (nicht „Script“): `sudo -n /usr/local/sbin/container-security-scan-lauf`.
- Zeitlimit großzügig (bis zu 30 Minuten je Container); Server, die sich einen Host teilen, nacheinander.
- Rückgabewert 1 und 2 sind beide rot; die letzte Zeile `ERGEBNIS: FUNDE` bzw. `ERGEBNIS: UNVOLLSTAENDIG`
  unterscheidet sie. Das Rundeck-Log enthält je Container die Zusammenfassung und jeden relevanten Fund;
  der vollständige Bericht liegt auf dem Server.
- Optional den SSH-Schlüssel auf diesen Befehl festlegen (`~rundeck/.ssh/authorized_keys`):

  ```
  command="sudo -n /usr/local/sbin/container-security-scan-lauf",from="<IP des Rundeck-Servers>",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA… rundeck-container-scan
  ```

### 4. Auf das Ergebnis reagieren

- **0** – nichts zu tun.
- **1** – Funde im Bericht prüfen (neue sind markiert), Images aktualisieren bzw.
  [gefährliche Einstellungen](#gefährliche-einstellungen-des-containers) beseitigen; Fehlalarme und
  akzeptierte Risiken in die [Ausnahmeliste](#ausnahmen).
- **2** – Ursache beheben (siehe [Rückgabewert](#rückgabewert)).

Warnungen (Supportende, öffentlicher Dienst als root …) ändern den Rückgabewert nicht. Der Host selbst ist
nicht Teil des Scans.

### 5. Code aktualisieren

1. Änderungen ansehen, z. B. `…/compare/v0.1.0...v0.2.0` und die Hinweise im Release. Die installierte
   Version nennen jedes Log und jeder Bericht, ebenso
   `python3 /opt/container-security-scan/container-security-scan.py --version`.
2. Das Installscript des neuen Releases wie in [Schritt 1](#1-einrichten) holen und ausführen (ggf. mit
   Proxy). Daten, Ausnahmeliste und Berichte bleiben; eigene Änderungen am Wrapper sind danach ersetzt.

## Ergebnis verstehen

### Rückgabewert

| Wert | Bedeutung |
|---|---|
| `0` | keine relevanten Schwachstellen |
| `1` | relevante Schwachstellen oder [gefährliche Einstellungen](#gefährliche-einstellungen-des-containers) gefunden |
| `2` | Fehler oder **Prüfung unvollständig** – nie als „sauber“ werten. Z. B.: docker nicht erreichbar, Container läuft nicht, Daten fehlen für ein benötigtes Ökosystem oder sind älter als 3 Tage, keine Paketdatenbank im Container, Dateien nicht vollständig lesbar (z. B. unlesbare Verzeichnisse; während der Prüfung gelöschte oder geänderte Dateien zählen nicht), nginx- bzw. Apache-Konfiguration nicht lesbar (im Container oder eines Proxys auf dem Host), Distribution ohne aktuelle Sicherheitsdaten (EOL), Ausnahmeliste fehlerhaft. |

**Relevant** ist P1 CRITICAL/HIGH und P2 CRITICAL (anpassbar über `RELEVANT` am Anfang des Skripts), dazu
**jede aktiv ausgenutzte Lücke** aus dem [KEV-Katalog der CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
unabhängig von Priorität und Schweregrad. Mit `--nur-behebbare` (so im Wrapper) gilt für alle, auch für
KEV-Funde: nur mit verfügbarem Fix. Grund für KEV: „Genutzt von“ ist eine Momentaufnahme. Programme, die eine
Anwendung nur bei Bedarf startet (ImageMagick, Ghostscript, ffmpeg beim Hochladen), erscheinen als P4; ist
eine solche Lücke aktiv ausgenutzt, soll sie trotzdem melden. Nicht relevant sind Funde aus der
Ausnahmeliste und Funde, die laut Titel nur Windows betreffen (siehe [Bewertung](#bewertung-der-funde)).

### Priorität

| | Bedeutung |
|---|---|
| **P1** | genutzt von einem erreichbaren Dienst (Intranet oder Internet, siehe [Erreichbarkeit](#erreichbarkeit)) |
| **P2** | genutzt von einem Dienst mit internem Port |
| **P3** | genutzt nur von einem Prozess ohne offenen Port |
| **P4** | installiert, aber nicht in Benutzung erkannt; oder Entwicklungsabhängigkeit (dev) |

„Genutzt von“ wird über `/proc` ermittelt: Programm und geladene Bibliotheken, geöffnete Dateien (JARs),
offene TCP/UDP-Ports; für npm/Composer/PyPI über das Projektverzeichnis (Arbeitsverzeichnis, Skriptpfad,
venv, Docroot aus der nginx-/Apache-Konfiguration). Welche Pakete eine Anwendung tatsächlich importiert,
ist von außen nicht sichtbar. Lässt sich ein veröffentlichter Port keinem Prozess zuordnen, werden
vorsichtshalber alle Komponenten des Containers als öffentlich genutzt gewertet (mit Warnung).

### Erreichbarkeit

„Öffentlich“ heißt im Bericht: von außerhalb des Docker-Hosts erreichbar. Ob aus dem Internet oder nur aus
dem Intranet, ist auf dem Server nicht erkennbar (Firewall, NAT, vorgelagerte Load Balancer) und wird gleich
gewertet. Das Ergebnis hängt nur von der Docker-Konfiguration ab, nicht vom Netz: Eine Testumgebung im
internen Netz mit derselben Konfiguration findet dieselben relevanten Funde wie die Produktion.

Grundsatz: **im Zweifel erreichbar.** Als intern gilt ein Dienst nur, wenn der Weg dorthin vollständig
bekannt ist. Ein Dienst, der nur auf Loopback lauscht (127.0.0.1, ::1), ist nie erreichbar. Sonst gilt er als
erreichbar, wenn eine der folgenden Bedingungen zutrifft:

| Weg | Erkennung |
|---|---|
| Port veröffentlicht | `docker inspect`, auch an `127.0.0.1` (dann meist hinter einem Reverse Proxy auf dem Host) |
| Host-Netzwerk | `network_mode: host` |
| eigene Adresse im LAN | Docker-Netz mit Treiber macvlan/ipvlan oder `gateway_mode_ipv4/6` `routed` bzw. `nat-unprotected` |
| gemeinsamer Netzwerk-Namespace | `network_mode: container:…`/`service:…` (z. B. VPN- oder Sidecar-Container): es gelten die Ports des Spenders; ein Ziel des Spenders wird an alle Container dieses Namespace weitergegeben |
| hinter einem erreichbaren nginx/Apache | Backends aus `nginx -T` bzw. der Apache-Konfiguration (`proxy_pass`, `fastcgi_pass`, `upstream`, `ProxyPass`, `SetHandler proxy:`), auch über mehrere Proxys und Variablen aus `set`/`map`; Ziele per Container-Name, Alias, Compose-Dienst oder IP |
| hinter einem erreichbaren Traefik bzw. caddy-docker-proxy | Ziele aus Docker-Labels (`traefik.*.services.*.loadbalancer.server.port`, `caddy.reverse_proxy: {{upstreams …}}`) |
| hinter einem Reverse Proxy **direkt auf dem Host** | nginx/Apache außerhalb von Docker (Programm mit dem Wurzelverzeichnis des Hosts, nicht in der cgroup eines Containers), das nicht nur auf Loopback lauscht: Konfiguration wie oben, Ziele über die Container-IP (z. B. `proxy_pass http://172.18.0.5:3000`). Ergebnis auf der Konsole als `Host: …`; gilt auch für den Einzelscan |
| aufgerufen von einer erreichbaren Anwendung | z. B. API-Gateway oder php-fpm hinter nginx im selben Container: Ziel-URLs (`http(s)://`, `ws(s)://`, `grpc(s)://`) auf andere Container in Umgebung oder Kommandozeile sowie beim Scan offene TCP-Verbindungen. Datenbanken, Caches und Message Broker als Ziel zählen nicht. Im Bericht als `Aufruf: Container …, Port … (Quelle)`, ohne Werte der Umgebung |
| hinter einem Tunnel-Agenten | cloudflared, frpc, ngrok, chisel – im Container oder auf dem Host: leiten Verkehr von außen weiter, ohne zu lauschen; gelten immer als erreichbar und nicht auswertbar (siehe nächste Zeile). Container mit einem solchen Image bzw. Befehl werden vorgezogen |
| **möglicherweise** erreichbar | Container im selben Docker-Netz wie ein erreichbarer Dienst, dessen Weiterleitungen nicht vollständig bekannt sind: Traefik, Caddy, HAProxy, Envoy, Varnish u. a. (Konfiguration wird nicht ausgewertet; Labels geben nur einen Teil der Ziele an), nginx-Ziel mit nicht auflösbarer Variable (`proxy_pass http://$host`), nicht lesbare nginx-Konfiguration, veröffentlichter Port ohne erkennbaren Prozess. Bei einem solchen Dienst auf dem Host oder im Host-Netzwerk: alle Container mit einem Docker-Netz (der Host erreicht sie über ihre IP). Mit Warnung je Dienst |

Die Prozesse auf dem Host liest das Skript nur als root vollständig; sonst warnt es (`Host: WARNUNG: Prozesse
auf dem Host nicht vollständig lesbar`), da ein Proxy auf dem Host unerkannt bleiben könnte. Ist die
Konfiguration eines Proxys auf dem Host nicht lesbar, ist die Prüfung unvollständig (Rückgabewert 2).

### Bewertung der Funde

- **Schweregrad:** Einstufung der Distribution (Debian, Ubuntu), sonst Angabe der Quelle, sonst CVSS. Hat
  der zutreffende Eintrag keinen (z. B. Go-Daten, Debian „not yet assigned“), wird die Bewertung derselben
  CVE aus den Bitnami- bzw. Alpine-Daten (CVSS der NVD) übernommen, bei mehreren die höchste. Solche Werte
  sind im Bericht mit `*` markiert. CVSS 4 wird angenähert (eher zu hoch), als Schadsoftware gemeldete
  Pakete (`MAL-…`) gelten als CRITICAL. Ohne jede Bewertung („UNKNOWN“) zählt ein Fund nicht als relevant
  (außer KEV), wird aber eigens ausgewiesen.
- **KEV:** aktiv ausgenutzte Lücken sind im Bericht mit `KEV` markiert und immer relevant (siehe oben).
- **Nur Windows:** Daten außerhalb der Distributionen (GitHub, Bitnami) führen auch Lücken, die nur unter
  Windows auftreten (z. B. „On Windows a directory returned by tempfile.mkdtemp() …“). Nennt der Titel das
  eindeutig, steht der Fund mit „nicht gezählt: betrifft laut Titel nur Windows“ in der Tabelle, zählt aber
  nicht als relevant. Die Erkennung ist bewusst vorsichtig (Titel mit „Linux“, „macOS“, „Windows and …“
  bleiben relevant); was sie nicht erkennt, gehört in die Ausnahmeliste.
- **Kernel-Pakete** (`linux-libc-dev`, `linux-headers`, `linux-image-*`, `kernel-*`) werden nicht geprüft:
  Container nutzen den Kernel des Hosts, und Debian/Ubuntu führen alle Kernel-CVEs am Quellpaket `linux` –
  ohne diese Regel sind in einem Debian-Image oft über 90 % der Funde Kernel-CVEs in den Headern.
- **Versionsbereiche der Distribution:** OSV ergänzt Alpine-Daten teils um eine erste betroffene Version
  aus einem anderen Versionszweig („betroffen ab 3.4.0, behoben in 3.3.7-r1“). Liegt der Fix der
  Distribution vor dieser Version, hat sie ihn zurückportiert, ihr Zweig war also betroffen: Solche
  Bereiche gelten ab Version 0. Gültige Angaben bleiben wirksam (curl 8.12.1 ist von einer Lücke ab 8.13.0
  nicht betroffen).

### Gefährliche Einstellungen des Containers

Einstellungen, mit denen aus einer Lücke im Container root auf dem Host wird. Sie sind **immer relevant**
(Rückgabewert 1), unabhängig von Schwachstellen und von `--nur-behebbare`, denn beheben lassen sie sich
immer. Geprüft wird nur, was ein Dienst praktisch nie braucht, aus `docker inspect`:

| Kennung | Befund |
|---|---|
| `CONF-PRIVILEGED` | `--privileged` |
| `CONF-SOCKET` | Socket der Container-Laufzeit eingebunden (`docker.sock`, `containerd.sock`, `podman.sock`) oder ein Verzeichnis, das ihn enthält (`/run`, `/var/run`, `/run/docker`, `/run/containerd`, `/run/podman`, die Host-Wurzel `/`) – auch schreibgeschützt, denn `:ro` verhindert den Zugriff auf einen Socket nicht |
| `CONF-PID-HOST` | `pid=host` |
| `CONF-CAP-…` | zusätzliche Capability, die den Ausbruch erlaubt: `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH`, `BPF` (z. B. `CONF-CAP-SYS-ADMIN`) |
| `CONF-SECCOMP-UNCONFINED`, `CONF-APPARMOR-UNCONFINED` | Schutzprofil ausdrücklich abgeschaltet |
| `CONF-HOST-PFAD` | Host-Pfad beschreibbar eingebunden: `/etc` (ganz oder `passwd`, `shadow`, `sudoers`, `cron*`, `systemd`, `ssh`, `docker`), `/root`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/usr` und `/usr/local` (ganz oder Programme, Bibliotheken), `/proc`, `/sys`, `/dev`, `/home` (ganz oder `~/.ssh`), `/var/lib/docker` (auch das Verzeichnis aller Volumes; einzelne Volumes nicht) |

Mit `--privileged` entfallen die Befunde zu Capabilities und Schutzprofilen (darin enthalten). Typischer
begründeter Fall ist ein Reverse Proxy wie Traefik mit `docker.sock`: besser einen Socket-Proxy mit
Lesezugriff vorschalten (z. B. `tecnativa/docker-socket-proxy`), sonst Ausnahme mit Begründung und
Ablaufdatum (Paket = Containername):

```
CONF-SOCKET       traefik       2027-03-31  liest nur Labels, Umstieg auf Socket-Proxy geplant
```

**Öffentlicher Dienst als root:** Laufen alle Prozesse an einem öffentlichen Port (im Sinne der
[Erreichbarkeit](#erreichbarkeit), auch „möglicherweise“) als root (je Port geprüft), erscheint eine **Warnung** (kein Rückgabewert), z. B. Node oder Python als root. nginx, Apache
und php-fpm (Master root, Worker unprivilegiert am selben Port) zählen nicht. Mit userns-remap oder rootless Docker ist root im
Container nicht root auf dem Host; dann entfällt die Warnung (außer bei `--userns=host`).

Nicht geprüft werden allgemeine Härtung (no-new-privileges, `cap_drop: ALL`, read-only, Limits, Ports nur
an bestimmte IPs) und der Docker-Daemon. Geprüft werden die gescannten (laufenden) Container, mit
`--alle-container` (so im Wrapper) also alle, mit `--oeffentliche` nur die erreichbaren und deren Ziele.

### Ausnahmen

Für Fehlalarme und bewusst akzeptierte Risiken, die die automatische Bewertung nicht erkennt, z. B.
CVE-2024-8926: Der Titel nennt nur „PHP CGI Parameter Injection“, die Lücke betrifft aber nur PHP-CGI unter
Windows. Die Liste liegt auf dem Server, nicht im Repository (einrichten: [Schritt 1](#1-einrichten)):

```
# /etc/container-security-scan/ausnahmen.txt
# Kennung         Paket oder *  gültig bis  Begründung
CVE-2024-8926     php           2027-06-30  betrifft nur PHP-CGI unter Windows (geprüft 2026-11-05)
CVE-2026-107814   mariadb       2027-03-31  betrifft nur die RPM-Pakete von MariaDB, hier Ubuntu-Image
```

- Kennung wie im Bericht (CVE, Kennung der Quelle oder `CONF-…`), Paket wie in der Spalte „Paket“ (bei
  `CONF-…` der Containername) oder `*` für alle.
- Jede Ausnahme braucht ein Ablaufdatum und eine Begründung: Danach zählt der Fund wieder, mit Warnung im
  Bericht. So bleibt keine Ausnahme unbemerkt für immer.
- Ausgenommene Funde stehen im Bericht unter „Nicht gezählt“ und in der Tabelle mit Begründung.
- Eine fehlerhafte Zeile bricht den Scan ab (Rückgabewert 2) statt still etwas auszublenden.

## Aufruf und Optionen

Für den Betrieb genügt der Wrapper. Direkter Aufruf für Spezialfälle (verwendet den vorhandenen
Datenstand, ohne ihn zu aktualisieren):

```bash
C=/opt/container-security-scan/container-security-scan.py
DB=/var/lib/container-security-scan/daten
sudo python3 -I $C --db $DB --alle-container <ausgabeverzeichnis>    # wie der Wrapper, ohne Datenaktualisierung
sudo python3 -I $C --db $DB <container> <ausgabeverzeichnis>         # einzelner Container, ohne Datenaktualisierung
sudo python3 -I $C --db $DB --alle <container> <ausgabeverzeichnis>  # alle Befunde in die Tabelle
```

| Option | Bedeutung |
|---|---|
| `--alle-container` | alle laufenden Container: zuerst die erreichbaren und die Backends hinter ihren Proxys (zählen als öffentlich, siehe [Erreichbarkeit](#erreichbarkeit)), dann alle übrigen – **empfohlen**, so im Wrapper. Ein Container, der zwischen Auflistung und Scan entfernt wurde (z. B. `docker run --rm`), wird übersprungen |
| `--oeffentliche` | wie `--alle-container`, aber ohne die übrigen Container |
| `--nur-behebbare` | für den Rückgabewert nur Funde zählen, für die es einen Fix gibt – **empfohlen** für die Alarmierung, sonst melden Container mit offenen, noch unbehobenen CVEs dauerhaft `1` |
| `--alle` | alle Befunde in die Tabelle (sonst P3/P4 nur CRITICAL/HIGH/KEV) |
| `--ausnahmen DATEI` | Ausnahmeliste: passende Funde zählen nicht als relevant, jede Ausnahme mit Begründung und Ablaufdatum (siehe [Ausnahmen](#ausnahmen)) |
| `--db-aktualisieren` | als root abgelehnt (Rückgabewert 2): nie Daten aus dem Netz als root schreiben. Im Git-Checkout den Branch `daten` nach `daten/` holen bzw. dort `git pull` – **nie den Code**; mit `--oekosysteme A,B` zusätzlich diese Ökosysteme direkt von OSV nach `osv-db/` (inkrementell, `--voll` lädt alles neu). Ohne Git-Checkout oder mit `--db`: alle Ökosysteme, die EOL- und die KEV-Daten direkt |
| `--db DIR` | nur diese Datenverzeichnisse verwenden; mehrfach möglich, je Ökosystem gilt das erste, das es enthält. Mit `--db-aktualisieren` genau eines (Ziel). Standard: `daten/` (Clone des Branches `daten`) und `osv-db/` neben dem Skript |
| `--user` | Benutzer für `docker exec` (Standard `0`). Ein anderer Benutzer kann meist nicht alle Verzeichnisse lesen: Die Prüfung gilt dann als unvollständig (`2`), die Meldung nennt die ersten unlesbaren Pfade |

## Ausgabe

Auf der Konsole (beim Wrapper auch im Log, in der Mail und im Rundeck-Log) zuerst Reverse Proxys direkt auf
dem Host mit ihren Zielen (`Host: nginx:443 auf dem Host – erreichbar; Ziele in Containern: app (3000)`), dann
je Container Warnungen, eine Zusammenfassung mit dem Pfad des Berichts und darunter alle relevanten Funde,
neue zuerst:

```
app-php: RELEVANTE SCHWACHSTELLEN – 1295 Befunde, davon 65 relevant (2 neu, 4 aktiv ausgenutzt); öffentlich: php-fpm:9000 – Bericht: …
app-php:   NEU: CVE-2026-111497 (CRITICAL KEV) in libbrotli1 1.0.9-2+b6 – behoben in 1.0.9-2+deb12u1 – genutzt von php-fpm:9000 – aktiv ausgenutzt (KEV seit 2026-10-27)
app-php:   CVE-2025-14179 (CRITICAL) in php 8.3.30 – behoben in 8.3.31 – genutzt von php-fpm:9000
…
```

Je Container im Ausgabeverzeichnis:

- `scan_<name>_<zeit>.md` – Bericht: Ergebnis (relevante Funde, neue zuerst, Warnungen), laufende Dienste
  mit Ports, Proxy-Backends und vHosts, Übersicht nach Priorität, Befundtabelle, nicht automatisch prüfbare
  Komponenten, Anhang (Prozesse, veraltete Bibliotheken im Speicher, Webserver-Konfiguration)
- `scan_<name>_<zeit>.cdx.json` – SBOM im Format CycloneDX 1.5 als Beleg (auch mit Trivy, Grype oder
  Dependency-Track nutzbar)
- `scan_<name>_<zeit>.sha256` – Prüfsummen
- `bekannt_<name>.json` – relevante Funde des letzten Laufs (für die Markierung „neu“)

Beispiele: [`beispiele/`](beispiele/) – ein Lauf `--alle-container --nur-behebbare` über die Testumgebung
[`beispiele/umgebung/compose.yml`](beispiele/umgebung/compose.yml) ([Konsolenausgabe](beispiele/ausgabe.txt)):
nginx als öffentlicher Reverse Proxy vor Node.js 22.22.0 (Node2Shell) und PHP 8.3.30 als PHP-FPM
(PHP2Shell) mit Anwendung, `vendor/` und eingebettetem jQuery 1.12.4 im Volume; Traefik mit Docker-Socket
(gefährliche Einstellung) und Ziel per Label.

## Was erfasst wird

| Bereich | Quelle im Container | Abgleich |
|---|---|---|
| OS-Pakete | dpkg (`status`, `status.d`), apk, rpm – inkl. Quellpaket | Debian, Ubuntu, Alpine (optional SUSE, openSUSE) |
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

Der Branch [`daten`](https://github.com/felixlohmeier/container-security-scan/tree/daten) enthält einen gekürzten Auszug aus den OSV-Exporten für Debian, Ubuntu, Alpine, npm, PyPI,
Packagist, Maven, Go und Bitnami (ca. 360 MB, in Git komprimiert ca. 25 MB). Gekürzt heißt: nur die für den
Abgleich nötigen Felder und Einträge; die Ergebnisse sind mit den vollständigen Exporten identisch
(geprüft). Die GitHub Action [`.github/workflows/daten.yml`](.github/workflows/daten.yml) erzeugt die
Daten täglich neu; die Ausgabe ist deterministisch, Commits enthalten nur echte Änderungen. Dazu kommen `eol-daten.json`
([Supportende](#supportende-eol)) und `kev.json` ([aktiv ausgenutzte Lücken](#aktiv-ausgenutzte-lücken-kev)).
Quellen und Lizenzen: [`QUELLEN.md` im Branch `daten`](https://github.com/felixlohmeier/container-security-scan/blob/daten/QUELLEN.md).

Ubuntu ist am stärksten gekürzt: Der Export ist entpackt rund 8 GB groß (als ZIP ca. 800 MB), der
Auszug ca. 190 MB. Weggelassen wird nur, was der Abgleich nie liest: die Listen der Binärpakete (abgeglichen
wird über das Quellpaket), Einträge für Ubuntu Pro, FIPS und Realtime (nicht in Container-Images), Kernel-
Quellpakete (siehe [Bewertung](#bewertung-der-funde)) und die USN-Sammelmeldungen (je CVE gibt es genauere
Einträge). Geprüft (11/2026): Solr und MariaDB (Ubuntu 22.04/24.04) mit identischen Berichten, Abgleich
ca. 5 statt 30 s; dazu je ca. 4000 Paketversionen für Ubuntu 14.04, 16.04 und 18.04 mit über 550 000
identischen Funden.

Ökosysteme, die nicht im Repository liegen (SUSE, openSUSE), lädt `--db-aktualisieren --oekosysteme …`
direkt von OSV nach `osv-db/`. Für Ökosysteme, die es im Branch `daten` schon gibt, ist das wirkungslos:
Je Ökosystem gilt das erste Verzeichnis, das es enthält, und `daten/` (bzw. das erste `--db`) kommt vor
`osv-db/`.

### Sonderfall: Daten direkt von OSV statt über GitHub

Für Server, die `github.com` nicht erreichen dürfen oder GitHub nicht als Datenquelle nutzen sollen. Dann lädt `csscan` alle Ökosysteme direkt von OSV (`storage.googleapis.com`),
die EOL-Daten von endoflife.date und den KEV-Katalog der CISA. Dafür das Installscript mit `DATEN=` aufrufen
(es holt dann den Branch `daten` nicht: `sudo env DATEN= bash installieren.sh $V`) und nach jeder
Installation im Wrapper `/usr/local/sbin/container-security-scan-lauf` die Zeilen mit `git pull` und `ARGS=`
ersetzen:

```bash
  runuser -u csscan -- python3 -I "$CODE" --db "$D/osv-db" --db-aktualisieren \
      || { echo "FEHLER: Daten nicht aktualisiert (direkt von OSV)"; exit 2; }
ARGS=(--db "$D/osv-db")
```

Darf der Server `github.com` gar nicht erreichen, auf einem anderen Rechner den Tag als Bundle verpacken,
übertragen und das Installscript daraus installieren lassen:

```bash
git clone -q https://github.com/felixlohmeier/container-security-scan.git css && git -C css bundle create ../css.bundle $V
git -C css show $V:installation/installieren.sh > installieren.sh     # beides auf den Server kopieren, dort:
sudo env REPO=$PWD/css.bundle DATEN= bash installieren.sh $V
```

- **Erster Lauf:** die Gesamtexporte, zusammen ca. 1,2 GB (Stand 11/2026: Ubuntu 800 MB, npm 220 MB,
  Debian 81 MB, PyPI 38 MB, die übrigen je ca. 10 MB; endoflife.date 3 MB, KEV-Katalog 2 MB).
- **Danach inkrementell:** Das Skript liest die Änderungsliste `modified_id.csv` bis zum letzten
  bekannten Stand und lädt nur die geänderten Einträge einzeln. Den Gesamtexport eines Ökosystems lädt
  es neu, wenn seit dem letzten Lauf mehr als 2000 Einträge geändert wurden oder sich mehr als 10 000
  Einzeldateien angesammelt haben. Debian und Ubuntu ändern oft Tausende Einträge an einem Tag; dann
  wird der Gesamtexport neu geladen, bei Ubuntu jeweils ca. 800 MB (Stand 11/2026 ein- bis zweimal pro
  Woche), sonst ca. 30–40 MB pro Tag.
- **Auf der Platte** liegen die ungekürzten Exporte (`<Ökosystem>.zip`, ca. 1,2 GB) und geänderte
  Einträge (`<Ökosystem>.neu/`), nicht der gekürzte Auszug aus dem Repository. Die Ergebnisse sind
  gleich; das Einlesen dauert länger (Debian: ca. 3,5 s statt 1,9 s, Ubuntu: ca. 30 s statt 5 s je
  Container).

### Supportende (EOL)

`eol-daten.json` im Branch `daten` enthält einen Auszug aus [endoflife.date](https://endoflife.date) (MIT-Lizenz, siehe
[`EOL-LIZENZ.txt`](https://github.com/felixlohmeier/container-security-scan/blob/daten/EOL-LIZENZ.txt)), den die Action täglich aus dem vollständigen API-Export
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
Ohne Git-Checkout oder mit `--db DIR` lädt `--db-aktualisieren` die EOL-Daten direkt nach
`osv-db/eol-daten.json` bzw. `DIR/eol-daten.json`.

### Aktiv ausgenutzte Lücken (KEV)

`kev.json` im Branch `daten` enthält aus dem [Katalog der CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(Known Exploited Vulnerabilities, CC0) je CVE das Datum der Aufnahme; die Action lädt ihn täglich. Funde mit
einer dieser CVEs sind im Bericht mit `KEV` markiert, stehen auch als P3/P4 in der Tabelle und sind
**immer relevant** (Rückgabewert 1), unabhängig von Priorität und Schweregrad; `--nur-behebbare` gilt
auch für sie. Fehlende oder mindestens 7 Tage alte KEV-Daten sind eine Warnung, kein Rückgabewert 2:
Die Bewertung nach Priorität und Schweregrad bleibt vollständig. Ohne Git-Checkout oder mit `--db DIR`
lädt `--db-aktualisieren` den Katalog direkt nach `DIR/kev.json`.

Ein Beispiel aus dem [PHP-Bericht](beispiele/scan_app-php.md): das eingebettete jQuery 1.12.4 mit
CVE-2020-11023 (MEDIUM, keinem Prozess zugeordnet, also P4). Ohne KEV nie gemeldet; laut CISA wird die
Lücke aktiv ausgenutzt.

## Rein lesend und ohne Datenabfluss

- Im Container laufen nur: `find`/`tar` (Metadaten-Dateien lesen; Container-Dateisystem und Volumes,
  nicht eingebundene Host-Verzeichnisse wie `/var/lib/docker`), ein POSIX-sh-Skript, das `/proc` liest –
  je Prozess-Benutzer, da Docker auch root im Container keinen Zugriff auf fremde Prozesse gibt –, und
  Versionsabfragen der gefundenen Programme (`node -e`, `php -r`, `python -I -S -c`, `java -version` …)
  mit Zeitlimit, im Verzeichnis `/` und **nie mit mehr Rechten als der laufende Prozess**.
- Die Konfiguration der Webserver (`nginx -T`, `apache2 -S/-M/-t`) wird mit dem Benutzer des jeweiligen
  Hauptprozesses abgefragt, nicht als root: Programm, Optionen und Konfiguration bestimmt der Container,
  und `load_module`/`LoadModule` würde dabei Code laden. Für einen Proxy direkt auf dem Host ebenso
  (`setpriv` mit Benutzer und Gruppe des Hauptprozesses, leere Umgebung, fester Suchpfad). `nginx -T` kann wie `nginx -t` fehlende Log- oder
  Temp-Verzeichnisse anlegen, die der Hauptprozess ohnehin anlegt.
- Befehle im Container (`sh`, `find`, `tar`, `awk`, `rpm` …) werden über einen festen Suchpfad
  (`/usr/sbin:/usr/bin:/sbin:/bin`) gesucht, nicht über den `PATH` des Images – liegt dort ein Verzeichnis,
  in das die Anwendung schreiben darf (z. B. ein venv), könnte sie sonst ein `sh` unterschieben, das der
  Scan als root startet. Nur `node`, `php`, `python3` … ohne Pfad werden über den `PATH` des Images
  gesucht, dann aber als `nobody` abgefragt.
- Ohne Shell oder Werkzeuge im Container wird passiv gelesen (`docker export`, `docker cp`, `/proc` des Hosts).
- Der tar-Strom aus dem Container wird im Speicher gelesen; nichts wird auf dem Host entpackt.
- Getestet: `docker diff` zeigt vor und nach dem Scan keine Änderung im Container.
- Es werden nur Daten **heruntergeladen** (GitHub bzw. OSV, endoflife.date und CISA); Paketlisten verlassen den Server nicht.
- Berichte und SBOM enthalten Kommandozeilen der Prozesse (oft mit Passwörtern) und Konfigurationsauszüge;
  das Skript legt sie daher nur für den aufrufenden Benutzer lesbar an (`umask 077`).

## Grenzen

- Nicht erfasst: Rust, Ruby, .NET, Tcl, Programme ohne Versionskennung, Bundles ohne Kopfkommentar,
  Programme direkt auf dem Host, UDP-Dienste nur bei offenem Socket.
- Erreichbarkeit: Konfigurationen werden nur von nginx und Apache ausgewertet; andere Proxys machen alle
  Container in ihren Docker-Netzen „möglicherweise“ erreichbar (eher zu viel), auf dem Host alle Container.
  Ziele einer Anwendung, die selbst weiterleitet (API-Gateway), werden nur über Ziel-URLs in Umgebung bzw.
  Kommandozeile und über beim Scan offene Verbindungen erkannt – nicht über URLs, die nur in
  Konfigurationsdateien stehen (z. B. Spring `application.yml`), wenn gerade keine Verbindung besteht.
  Umgekehrt zählt auch ein interner HTTP-Dienst, den eine erreichbare App nur aufruft (eher zu viel).
- EOL-Abgleich nur für Produkte mit Paketkennung bzw. die genannten Laufzeiten/Server und nur für
  numerische Versionszweige; einzelne OS-Pakete, Java-Laufzeiten (herstellerabhängig) und Anwendungen
  ohne Paketkennung (z. B. WordPress, Nextcloud) werden nicht auf Supportende geprüft.
- Herstellerpaketquellen werden über typische Versionskennungen und Paketbetreuer erkannt
  (nginx.org, NodeSource, Sury, mariadb.org, PostgreSQL); andere Fremdquellen können unerkannt bleiben.
- Ein Einzelscan (ohne `--alle-container`/`--oeffentliche`) kennt keine Proxys in *anderen* Containern;
  Backends erscheinen dann als P2.
- nginx-Konfiguration: `nginx -T` wird mit `-p`/`-c` des laufenden Masterprozesses aufgerufen. Schlägt
  die Abfrage fehl (ebenso `apache2 -S` bzw. `-t -D DUMP_INCLUDES`), ist die Prüfung unvollständig
  (Rückgabewert 2), da Proxy-Backends fehlen könnten.

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

Abgleich mit Grype 0.121 und Trivy 0.76 (11/2026, 8 laufende Container: nginx als Proxy vor Node, Python
und PHP-FPM, PHP 8.3 mit Code im Volume, Node auf distroless, Solr, MariaDB; Funde je Container auf
CVE und Paket abgeglichen, Abweichungen einzeln geprüft):

| Befund | Skript | Grype | Trivy |
|---|---|---|---|
| nginx von nginx.org, MariaDB von mariadb.org (Herstellerquellen), Java-Laufzeit | ✓ | – | – |
| Laufzeiten aus offiziellen Images (Node, PHP, Python) | ✓ | ✓ | – |
| Composer/npm im Volume | ✓ | nur über Syft mit Image-Katalogen | ✓ |
| eingebettetes jQuery | ✓ | – | – |
| Go-Standardbibliothek in `gosu` | ✓ (Schweregrad über die CVE) | teilweise | ✓ |
| Alpine curl 8.12.1: Lücken erst ab 8.13.0 | richtig nicht gemeldet | Fehlalarm | Fehlalarm |
| Alpine openssl/libxml2 mit zurückportiertem Fix | ✓ (seit [Versionsbereiche](#bewertung-der-funde)) | ✓ | ✓ |
| Kernel-Header `linux-libc-dev` | nicht geprüft | nicht geprüft | über 90 % der Funde |
| aktiv ausgenutzt (KEV) | ✓ | ✓ | – |

Grype eignet sich als unabhängige Zweitmeinung: andere Datenquellen (NVD, GitHub, Hersteller) als OSV.

## Entwicklung und Tests

Zum Ausprobieren und Entwickeln, **nur auf einem eigenen Testrechner** – auf Servern gilt
[Installation und Betrieb](#installation-und-betrieb):

```bash
git clone https://github.com/felixlohmeier/container-security-scan.git && cd container-security-scan
./container-security-scan.py --db-aktualisieren        # Branch daten nach daten/ holen (nicht als root)
sudo ./container-security-scan.py --alle-container berichte/ --nur-behebbare
```

```bash
python3 -m unittest discover -s tests                                   # Unit-Tests, ohne Docker (ca. 1 s)
./container-security-scan.py --db-aktualisieren                       # Daten (Branch daten) für den Docker-Test
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit echten Containern
```

Was welche Testdatei prüft: [`tests/README.md`](tests/README.md). Die GitHub Action
[`tests.yml`](.github/workflows/tests.yml) führt die Unit-Tests mit Python 3.6, 3.11, 3.13 und 3.14 (Python des
Runners, mit dem auch die Daten erzeugt werden) aus, den Docker-Test nur bei Pull Requests und auf `main`.

[Beispiele](beispiele/) neu erzeugen – nötig, wenn sich `VERSION` oder das Format der Berichte ändert, im
selben Pull Request (ein Unit-Test prüft die Version). Startet die Testumgebung
[`beispiele/umgebung/compose.yml`](beispiele/umgebung/compose.yml) (Ports 8080 und 8081) und scannt sie:

```bash
sudo bash beispiele/erzeugen.sh
```

Änderungen unter `installation/` auf einem Testrechner (oder in einer VM) ausprobieren: aus einem Tag des
committeten Stands, angelegt in einem temporären Klon (die eigenen Tags bleiben unberührt):

```bash
V=v$(./container-security-scan.py --version | cut -d" " -f2) && rm -rf /tmp/css && git clone -q . /tmp/css
git -C /tmp/css tag -f $V && git -C /tmp/css bundle create /tmp/css.bundle $V
sudo env REPO=/tmp/css.bundle bash installation/installieren.sh $V && sudo /usr/local/sbin/container-security-scan-lauf
```

### Releases

Server installieren nur Releases: Git-Tags `vX.Y.Z` auf `main`. Die Version steht nur in `VERSION` am Anfang
von `container-security-scan.py`; Installscript, Wrapper und README nennen sie nicht. Ein Release:

1. Per Pull Request nach `main`: `VERSION` erhöhen und die [Beispiele neu erzeugen](#entwicklung-und-tests).
2. Nach dem Merge den Merge-Commit taggen (signiert, wenn möglich) und den Tag pushen:

   ```bash
   git tag -s v0.2.0 -m v0.2.0 <commit>
   ```

   ```bash
   git push origin v0.2.0
   ```

3. Auf GitHub ein Release zum Tag anlegen und darin die Änderungen nennen, vor allem alles, was Admins
   wissen müssen (neue Voraussetzungen, geänderte Rückgabewerte, Änderungen am Wrapper).

Beim Push eines Tags prüft die Action, dass er `v` + `VERSION` entspricht; das Installscript bricht ebenso ab,
wenn die Version im Skript nicht zum Tag passt.

### Repository auf GitHub (Rulesets)

Damit das Token des Workflows nur die Daten ändern kann, in den Einstellungen des Repositorys unter
*Settings → Rules → Rulesets* (bzw. *Settings → Actions*) einrichten:

| Ruleset bzw. Einstellung | Regeln | Wirkung |
|---|---|---|
| Branch `main` (Default branch) | *Restrict deletions*, *Block force pushes*, *Require a pull request before merging*, optional *Require status checks to pass* (Unit-Tests) und *Require signed commits*; keine Ausnahme (*Bypass list*) für GitHub Actions | Code ändert sich nur über einen Pull Request; das Token des Workflows kann `main` nicht beschreiben. |
| Branch `daten` | *Restrict deletions*, *Block force pushes* | Die Action committet weiter direkt; die Historie der Daten lässt sich nicht umschreiben. |
| Tags `v*` | *Restrict creations* (Ausnahme nur *Repository admin*), *Restrict updates*, *Restrict deletions* | Releases legt nur der Admin an; ein Tag lässt sich nicht verschieben oder löschen. Ein verschobener Tag fiele mit Commit beim Installscript auf. |
| *Actions → General → Workflow permissions* | *Allow GitHub Actions to create and approve pull requests* aus (Standard) | Der Workflow kann sich nicht über einen eigenen Pull Request nach `main` schreiben. |

Gegen eine Übernahme des Kontos schützen Rulesets nicht; dagegen hilft nur der Blick auf die Änderungen vor
jedem Update und die Signatur des Tags ([Schritt 1](#1-einrichten)).

## Verwandte Werkzeuge

- [Trivy](https://trivy.dev), [Grype](https://github.com/anchore/grype),
  [OSV-Scanner](https://github.com/google/osv-scanner): Images, Dateisysteme, SBOMs; ohne Laufzeitkontext.
- [Vuls](https://github.com/future-architect/vuls): agentloser Scanner für Server, kann betroffene Prozesse zeigen.
- [Kubescape](https://kubescape.io) „Relevancy“: priorisiert nach tatsächlich geladenen Paketen (eBPF, Kubernetes).
