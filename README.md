# container-security-scan

Schwachstellen-Scan für **laufende Docker-Container** – mit Fokus auf das, was tatsächlich läuft und
von außen erreichbar ist. Ein einzelnes Python-Skript, nur Standardbibliothek, ab Python 3.6
(SLES 15), rein lesend. Die Schwachstellendaten (gekürzter Auszug aus [OSV](https://osv.dev)) liegen
im Branch [`daten`](https://github.com/felixlohmeier/container-security-scan/tree/daten) dieses Repositorys, getrennt vom Code im Branch `main`, und werden
täglich per GitHub Action aktualisiert – auf dem Server genügt `git pull` im Daten-Clone (siehe
[Code und Daten trennen](#code-und-daten-trennen)). Paketlisten verlassen den Server nie.

```bash
git clone https://github.com/felixlohmeier/container-security-scan.git
cd container-security-scan
./container-security-scan.py --db-aktualisieren          # holt den Branch daten nach daten/ (nicht als root)
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

- Linux-Host mit Docker; Aufruf als root (empfohlen) oder Mitglied der Gruppe `docker` – beides gleichwertig:
  Wer docker steuern darf, ist faktisch root. Für den Code gilt daher in beiden Fällen
  [Code und Daten trennen](#code-und-daten-trennen).
- Python ≥ 3.6 (SLES 15: `python3`) und `git`
- optional `rpm` auf dem Host (nur für RPM-Container ohne eigenes `rpm`)

## Nutzung

```bash
# alle öffentlich erreichbaren Container (veröffentlichte Ports, Host-Netzwerk) und deren Backends hinter Proxys
./container-security-scan.py --oeffentliche [ausgabeverzeichnis]

# einen einzelnen Container
./container-security-scan.py <container> [ausgabeverzeichnis]

# Daten aktualisieren: Branch daten nach daten/ holen bzw. dort git pull – nie den Code; nicht als root
./container-security-scan.py --db-aktualisieren

# als root: festgehaltener Code, Daten aus einem eigenen Clone des Branches daten (siehe „Code und Daten trennen“)
/opt/container-security-scan/container-security-scan.py --db /var/lib/container-security-scan/daten --oeffentliche [ausgabeverzeichnis]

# zusätzliche Ökosysteme direkt von OSV laden (nach osv-db/), z. B. für Ubuntu-basierte Images
# wie mariadb, solr oder elasticsearch (ca. 800 MB)
./container-security-scan.py --db-aktualisieren --oekosysteme Ubuntu

# alle Daten direkt von OSV und endoflife.date statt über GitHub (siehe „Daten“): laden als csscan, scannen als root
runuser -u csscan -- ./container-security-scan.py --db /var/lib/container-security-scan/osv-db --db-aktualisieren
./container-security-scan.py --db /var/lib/container-security-scan/osv-db --oeffentliche [ausgabeverzeichnis]
```

| Option | Bedeutung |
|---|---|
| `--oeffentliche` | alle öffentlich erreichbaren Container; Backends hinter einem öffentlichen Proxy (auch in anderen Containern) werden mitgeprüft und zählen als öffentlich |
| `--nur-behebbare` | für den Rückgabewert nur Funde zählen, für die es einen Fix gibt – **empfohlen** für die Alarmierung, sonst melden Container mit offenen, noch unbehobenen CVEs dauerhaft `1` |
| `--alle` | alle Befunde in die Tabelle (sonst P3/P4 nur CRITICAL/HIGH/KEV) |
| `--ausnahmen DATEI` | Ausnahmeliste: passende Funde zählen nicht als relevant, jede Ausnahme mit Begründung und Ablaufdatum (siehe [Ausnahmen](#ausnahmen)) |
| `--db-aktualisieren` | als root abgelehnt (Rückgabewert 2): nie Daten aus dem Netz als root schreiben. Im Git-Checkout den Branch `daten` nach `daten/` holen bzw. dort `git pull` – **nie den Code**; mit `--oekosysteme A,B` zusätzlich diese Ökosysteme direkt von OSV nach `osv-db/` (inkrementell, `--voll` lädt alles neu). Ohne Git-Checkout oder mit `--db`: alle Ökosysteme, die EOL- und die KEV-Daten direkt |
| `--db DIR` | nur diese Datenverzeichnisse verwenden; mehrfach möglich, je Ökosystem gilt das erste, das es enthält. Mit `--db-aktualisieren` genau eines (Ziel). Standard: `daten/` (Clone des Branches `daten`) und `osv-db/` neben dem Skript |
| `--user` | Benutzer für `docker exec` (Standard `0`) |

### Rückgabewert

| Wert | Bedeutung |
|---|---|
| `0` | keine relevanten Schwachstellen |
| `1` | relevante Schwachstellen gefunden |
| `2` | Fehler oder **Prüfung unvollständig** – nie als „sauber“ werten. Z. B.: docker nicht erreichbar, Container läuft nicht, Daten fehlen für ein benötigtes Ökosystem oder sind älter als 3 Tage, keine Paketdatenbank im Container, Dateien nicht vollständig lesbar, nginx-Konfiguration nicht lesbar, Distribution ohne aktuelle Sicherheitsdaten (EOL), Ausnahmeliste fehlerhaft. |

**Relevant** ist P1 CRITICAL/HIGH und P2 CRITICAL (anpassbar über `RELEVANT` am Anfang des Skripts), dazu
**jede aktiv ausgenutzte Lücke** aus dem [KEV-Katalog der CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
unabhängig von Priorität und Schweregrad. Grund: „Genutzt von“ ist eine Momentaufnahme. Programme, die eine
Anwendung nur bei Bedarf startet (ImageMagick, Ghostscript, ffmpeg beim Hochladen), erscheinen als P4; ist
eine solche Lücke aktiv ausgenutzt, soll sie trotzdem melden. Nicht relevant sind Funde aus der
Ausnahmeliste und Funde, die laut Titel nur Windows betreffen (siehe [Bewertung](#bewertung-der-funde)).

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

### Bewertung der Funde

- **Schweregrad:** Einstufung der Distribution (Debian, Ubuntu), sonst Angabe der Quelle, sonst CVSS. Hat
  der zutreffende Eintrag keinen (z. B. Go-Daten, Debian „not yet assigned“), wird die Bewertung derselben
  CVE aus den Bitnami- bzw. Alpine-Daten (CVSS der NVD) übernommen, bei mehreren die höchste. Solche Werte
  sind im Bericht mit `*` markiert.
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

### Ausnahmen

Für Fehlalarme und bewusst akzeptierte Risiken, die die automatische Bewertung nicht erkennt, z. B.
CVE-2024-8926: Der Titel nennt nur „PHP CGI Parameter Injection“, die Lücke betrifft aber nur PHP-CGI unter
Windows. Die Liste liegt auf dem Server, root-eigen und nur für root beschreibbar (sonst Rückgabewert 2),
nicht im Repository:

```
# /etc/container-security-scan/ausnahmen.txt
# Kennung         Paket oder *  gültig bis  Begründung
CVE-2024-8926     php           2027-06-30  betrifft nur PHP-CGI unter Windows (geprüft 2026-11-05)
CVE-2026-107814   mariadb       2027-03-31  betrifft nur die RPM-Pakete von MariaDB, hier Ubuntu-Image
```

- Kennung wie im Bericht (CVE oder Kennung der Quelle), Paket wie in der Spalte „Paket“ oder `*` für alle.
- Jede Ausnahme braucht ein Ablaufdatum und eine Begründung: Danach zählt der Fund wieder, mit Warnung im
  Bericht. So bleibt keine Ausnahme unbemerkt für immer.
- Ausgenommene Funde stehen im Bericht unter „Nicht gezählt“ und in der Tabelle mit Begründung.
- Eine fehlerhafte Zeile bricht den Scan ab (Rückgabewert 2) statt still etwas auszublenden.

## Code und Daten trennen

Das Skript läuft als root. Käme sein Code automatisch aus GitHub, hätte jeder, der das Repository
übernimmt, mit dem nächsten Lauf root auf allen Servern – auch ohne das Skript selbst zu ändern, z. B.
über eine zusätzliche `json.py` neben dem Skript, die Python beim `import json` zuerst lädt. Deshalb:

- **Zwei Branches:** `main` enthält nur Code, [`daten`](https://github.com/felixlohmeier/container-security-scan/tree/daten) nur Daten (JSON, keine
  Programme). Die GitHub Action läuft mit dem Code aus `main` und schreibt nur nach `daten`.
- **Code** liegt root-eigen unter `/opt/container-security-scan` (Branch `main`), auf einem geprüften Stand
  festgehalten, und wird nur von Hand nach Prüfung aktualisiert.
- **Daten** holt ein Benutzer ohne Rechte (`csscan`) täglich in einen Clone nur des Branches `daten`. Darin
  liegt kein Code, der versehentlich als root gestartet werden könnte. Der Scan als root liest daraus nur
  JSON-Dateien (`--db`).
- `--db-aktualisieren` holt nur den Branch `daten`, nie den Code, und lehnt jeden Aufruf als root ab
  (Rückgabewert 2): Daten aus dem Netz soll root nicht in ein Verzeichnis schreiben, das einem anderen
  Benutzer gehört (symbolische Links).
- Gleiches gilt für Mitglieder der Gruppe `docker`: Ein Checkout, den jemand anders (oder `git pull`)
  aktualisiert, darf nicht mit root- oder docker-Rechten laufen – sonst hat, wer ihn ändern kann, root.

```
/opt/container-security-scan/              Code (Branch main): root, festgehalten
/var/lib/container-security-scan/daten/    Daten (nur Branch daten): csscan, täglich git pull
/var/lib/container-security-scan/osv-db/   optional, z. B. Ubuntu-Daten direkt von OSV: csscan
```

Einrichtung (als root):

```bash
# Code
git clone --single-branch --branch main https://github.com/felixlohmeier/container-security-scan.git \
    /opt/container-security-scan
chmod -R go-w /opt/container-security-scan

# Daten
useradd -r -U -m -d /var/lib/container-security-scan -s /sbin/nologin csscan
runuser -u csscan -- git clone --single-branch --branch daten \
    https://github.com/felixlohmeier/container-security-scan.git /var/lib/container-security-scan/daten
```

Braucht der Server einen Proxy, diesen für `csscan` in git eintragen
(`runuser -u csscan -- git config --global http.proxy http://proxy:3128`).

Damit hat eine Übernahme des Repositorys nur noch eine Folge: Die Daten können gefälscht sein, Funde
also unterdrückt oder erfunden werden. Code als root läuft dadurch nicht. Wer auch GitHub als Datenquelle
ausschließen will, lädt die Daten direkt von OSV ([siehe unten](#direkt-von-osv-statt-über-github)).

### Branches schützen (Rulesets)

In den Einstellungen des Repositorys unter *Settings → Rules → Rulesets* (bzw. *Settings → Actions*):

| Ruleset bzw. Einstellung | Regeln | Wirkung |
|---|---|---|
| Branch `main` (Default branch) | *Restrict deletions*, *Block force pushes*, *Require a pull request before merging*, optional *Require status checks to pass* (Unit-Tests) und *Require signed commits*; keine Ausnahme (*Bypass list*) für GitHub Actions | Code ändert sich nur über einen Pull Request; das Token des Workflows kann `main` nicht beschreiben. |
| Branch `daten` | *Restrict deletions*, *Block force pushes* | Die Action committet weiter direkt; die Historie der Daten lässt sich nicht umschreiben. |
| *Actions → General → Workflow permissions* | *Allow GitHub Actions to create and approve pull requests* aus (Standard) | Der Workflow kann sich nicht über einen eigenen Pull Request nach `main` schreiben. |

Rulesets schützen gegen Versehen und gegen ein missbrauchtes Token des Workflows, **nicht** gegen eine
Übernahme des Kontos: Wer Admin-Rechte hat, kann sie abschalten. Deshalb bleibt der Code auf dem Server
festgehalten und wird nur nach Prüfung aktualisiert (optional über signierte Tags, siehe unten).

### Code aktualisieren

Nur nach Prüfung, als root. `git fetch` führt nichts aus; da `main` nur Code enthält, ist jede Änderung zu
prüfen – jede neue `.py`-Datei neben dem Skript würde mitgeladen:

```bash
cd /opt/container-security-scan
git fetch origin main
git diff --stat HEAD origin/main     # was hat sich geändert?
git diff HEAD origin/main            # ansehen
git checkout --detach origin/main    # bzw. den geprüften Commit
```

Optional mit **signierten Tags**: Geprüfte Stände werden mit einem Schlüssel signiert, der nicht bei
GitHub liegt (z. B. auf einem Hardware-Token). Der Server übernimmt nur so signierte Tags; wer das
Repository übernimmt, kann keine gültigen erzeugen. Die Liste der erlaubten Schlüssel wird auf dem
Server gepflegt, nicht aus dem Repository geholt:

```bash
# /etc/container-security-scan/allowed_signers: <name> ssh-ed25519 AAAA…
git fetch origin --tags
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/etc/container-security-scan/allowed_signers \
    verify-tag v1.2 && git checkout --detach v1.2
```

Ein von der GitHub Action signierter Daten-Commit hilft dagegen nicht: Der Schlüssel läge als Secret bei
GitHub, und wer das Repository übernimmt, kann den Workflow ändern.

## Täglicher Betrieb

Neue Schwachstellen erscheinen in den OSV-Daten typischerweise 1–2 Tage nach Veröffentlichung; die
GitHub Action übernimmt sie täglich um 03:17 UTC in den Branch `daten`. Ein täglicher Lauf erkennt sie für
die bereits laufenden Versionen, ohne dass dafür etwas angepasst werden muss.

Den Scan **nicht zu früh** nach der Action ansetzen: Geplante GitHub-Läufe starten oft mit Verzögerung
(bis etwa eine Stunde, selten mehr). Läuft der Scan vorher, prüft er mit dem Stand des Vortags. Bei
mitteleuropäischer Zeit wäre z. B. 05:23 im Sommer schon 03:23 UTC. 07:23 Ortszeit (05:23 bzw. 06:23 UTC)
lässt genug Abstand; die Daten sind beim Scan dann nur wenige Stunden alt. Welcher Stand verwendet wurde,
steht im Bericht unter „Datenbank“.

`/etc/cron.d/container-security-scan` (Mail nur bei Rückgabewert ≠ 0):

```cron
MAILTO=""
23 7 * * * root /usr/local/sbin/container-security-scan-taeglich
```

`/usr/local/sbin/container-security-scan-taeglich` (root-eigen, Modus 755; bewusst nicht im Git-Checkout):

```bash
#!/bin/bash
# Daten als csscan aktualisieren, dann als root mit festgehaltenem Code scannen (README: Code und Daten trennen)
PATH=/usr/sbin:/usr/bin:/sbin:/bin
D=/var/lib/container-security-scan
OUT=/var/log/container-security-scan
UBUNTU=nein                    # ja: Ubuntu-Daten (ca. 800 MB) nach $D/osv-db laden und verwenden
AUSNAHMEN=/etc/container-security-scan/ausnahmen.txt   # optional, siehe „Ausnahmen“
cd / && umask 077              # Berichte enthalten u. a. Prozess-Kommandozeilen
mkdir -p "$OUT/berichte"
LOG=$OUT/$(date +%F).txt
DB=(--db "$D/daten")
[ "$UBUNTU" = ja ] && DB+=(--db "$D/osv-db")
[ -f "$AUSNAHMEN" ] && DB+=(--ausnahmen "$AUSNAHMEN")
(
  if ! runuser -u csscan -- git -C "$D/daten" pull --ff-only --quiet; then
      echo "FEHLER: Daten nicht aktualisiert (git pull als csscan)"; exit 2
  fi
  if [ "$UBUNTU" = ja ] && ! runuser -u csscan -- /opt/container-security-scan/container-security-scan.py \
          --db "$D/osv-db" --db-aktualisieren --oekosysteme Ubuntu; then
      echo "FEHLER: Ubuntu-Daten nicht aktualisiert"; exit 2
  fi
  /opt/container-security-scan/container-security-scan.py "${DB[@]}" --oeffentliche "$OUT/berichte" --nur-behebbare
) > "$LOG" 2>&1
rc=$?
[ $rc -ne 0 ] && mail -s "container-security-scan $(hostname): Rückgabewert $rc" root < "$LOG"
exit $rc
```

Schlägt die Datenaktualisierung fehl, ist der Rückgabewert 2 (nicht der von git). Bleibt sie mehrere
Tage aus, meldet auch der Scan veraltete Daten (Rückgabewert 2).

- **1** → Funde prüfen und Images aktualisieren. Der Bericht markiert Funde, die seit dem letzten Lauf **neu** sind.
- **2** → Ursache beheben (Daten, Ökosystem ergänzen, Container), sonst ist die Überwachung blind.
- Warnungen zum Supportende sind keine OSV-Schwachstellen und ändern den Rückgabewert nicht.
- Fehlalarme nicht durch Abschalten der Alarmierung lösen, sondern mit Begründung und Ablaufdatum in die
  [Ausnahmeliste](#ausnahmen) eintragen.
- Der Host selbst (SLES) ist nicht Teil des Scans: dafür `zypper list-patches --category security`.

### Mit Rundeck

Rundeck übernimmt Zeitplan, Übersicht und Benachrichtigung; Code und Daten bleiben auf jedem Server,
getrennt wie oben. Rundeck darf per sudo nur genau dieses eine Skript starten – keine allgemeinen
root-Rechte, kein `docker`, kein `python3` mit beliebigen Argumenten. Wer Rundeck übernimmt, kann so
Scans auslösen, aber nicht root auf den Servern werden.

`/usr/local/sbin/container-security-scan-rundeck` (root-eigen, Modus 755; statt cron und
`container-security-scan-taeglich`):

```bash
#!/bin/bash
# Aufruf durch Rundeck: sudo -n /usr/local/sbin/container-security-scan-rundeck
# Ausgabe ins Rundeck-Log, letzte Zeile "ERGEBNIS: ...", Rückgabewert wie beim Skript (0/1/2).
PATH=/usr/sbin:/usr/bin:/sbin:/bin
D=/var/lib/container-security-scan
OUT=/var/log/container-security-scan
UBUNTU=nein                    # ja: Ubuntu-Daten (ca. 800 MB) nach $D/osv-db laden und verwenden
AUSNAHMEN=/etc/container-security-scan/ausnahmen.txt   # optional, siehe „Ausnahmen“
cd / && umask 077              # Berichte enthalten u. a. Prozess-Kommandozeilen
exec 9>/run/container-security-scan.lock
if ! flock -n 9; then
    echo "ERGEBNIS: UNVOLLSTAENDIG (Rückgabewert 2, Scan läuft bereits) – $(hostname)"
    exit 2
fi
mkdir -p "$OUT/berichte"
LOG=$OUT/$(date +%F_%H%M%S).txt
DB=(--db "$D/daten")
[ "$UBUNTU" = ja ] && DB+=(--db "$D/osv-db")
[ -f "$AUSNAHMEN" ] && DB+=(--ausnahmen "$AUSNAHMEN")
{
  if ! runuser -u csscan -- git -C "$D/daten" pull --ff-only --quiet; then
      echo "FEHLER: Daten nicht aktualisiert (git pull als csscan)"; exit 2
  fi
  if [ "$UBUNTU" = ja ] && ! runuser -u csscan -- /opt/container-security-scan/container-security-scan.py \
          --db "$D/osv-db" --db-aktualisieren --oekosysteme Ubuntu; then
      echo "FEHLER: Ubuntu-Daten nicht aktualisiert"; exit 2
  fi
  /opt/container-security-scan/container-security-scan.py "${DB[@]}" --oeffentliche "$OUT/berichte" --nur-behebbare
} 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
case $rc in
    0) ergebnis=OK ;;
    1) ergebnis=FUNDE ;;
    *) ergebnis=UNVOLLSTAENDIG; rc=2 ;;
esac
echo "ERGEBNIS: $ergebnis (Rückgabewert $rc) – $(hostname)" | tee -a "$LOG"
exit $rc
```

sudo-Regel (als root):

```bash
cat > /etc/sudoers.d/rundeck-container-scan <<'EOF'
rundeck ALL=(root) NOPASSWD: /usr/local/sbin/container-security-scan-rundeck ""
EOF
chmod 440 /etc/sudoers.d/rundeck-container-scan
visudo -c
```

`""` am Ende verbietet zusätzliche Argumente. Das Skript liegt bewusst außerhalb der Git-Checkouts, damit
git-Operationen es nicht berühren; wie alles, was sudo als root startet, darf es nur root ändern können. Den Benutzernamen an Ihren Rundeck-Benutzer anpassen;
ist `requiretty` gesetzt, zusätzlich `Defaults:rundeck !requiretty`. Optional lässt sich auch der
SSH-Schlüssel auf diesen Befehl festlegen (`~rundeck/.ssh/authorized_keys` auf dem Server; dann eigener
Schlüssel nur für diesen Job):

```
command="sudo -n /usr/local/sbin/container-security-scan-rundeck",from="<IP des Rundeck-Servers>",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA… rundeck-container-scan
```

Rundeck-Job:

- Schritt „Command“: `sudo -n /usr/local/sbin/container-security-scan-rundeck` – kein Schritt „Script“,
  der eine Datei auf den Server kopiert und ausführt (dafür bräuchte der Rundeck-Benutzer allgemeine
  root-Rechte).
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

Der Branch [`daten`](https://github.com/felixlohmeier/container-security-scan/tree/daten) enthält einen gekürzten Auszug aus den OSV-Exporten für Debian, Alpine, npm, PyPI, Packagist,
Maven, Go und Bitnami (ca. 170 MB, in Git komprimiert ca. 15 MB). Gekürzt heißt: nur die für den Abgleich
nötigen Felder; die Ergebnisse sind mit den vollständigen Exporten identisch (geprüft). Die GitHub Action
[`.github/workflows/daten.yml`](.github/workflows/daten.yml) erzeugt die Daten täglich neu; die
Ausgabe ist deterministisch, Commits enthalten nur echte Änderungen. Dazu kommen `eol-daten.json`
([Supportende](#supportende-eol)) und `kev.json` ([aktiv ausgenutzte Lücken](#aktiv-ausgenutzte-lücken-kev)).
Quellen und Lizenzen: [`QUELLEN.md` im Branch `daten`](https://github.com/felixlohmeier/container-security-scan/blob/daten/QUELLEN.md).

Ökosysteme, die nicht im Repository liegen, lädt `--db-aktualisieren --oekosysteme …` direkt von OSV
nach `osv-db/`. Für Ökosysteme, die es im Branch `daten` schon gibt, ist das wirkungslos: Je Ökosystem
gilt das erste Verzeichnis, das es enthält, und `daten/` (bzw. das erste `--db`) kommt vor `osv-db/`.

Für Ubuntu-basierte Varianten von MariaDB, Solr und Elasticsearch ist einmalig
`./container-security-scan.py --db-aktualisieren --oekosysteme Ubuntu` erforderlich. Der große Export
liegt nur lokal in `osv-db/`, nicht im Repository; bei späteren Aktualisierungen denselben Befehl
erneut ausführen. Bei getrennten Daten (Betrieb als root) lädt `csscan` sie in ein eigenes Verzeichnis,
das beim Scan als zweites `--db` angegeben wird (`UBUNTU=ja` in den Skripten unter „Täglicher Betrieb“). Maßgeblich ist die Distribution des jeweiligen Images, nicht der Imagename.
Fehlen die Ubuntu-Daten, bleibt das Ergebnis ausdrücklich unvollständig (Rückgabewert 2).

### Direkt von OSV statt über GitHub

Ohne Git-Checkout oder mit `--db DIR` lädt `--db-aktualisieren` alle Ökosysteme direkt von OSV
(`storage.googleapis.com`), die EOL-Daten von endoflife.date und den KEV-Katalog der CISA in dieses Verzeichnis. `--db DIR` dann
auch beim Scan angeben, sonst werden die Repository-Daten verwendet. Bei getrennten Daten ersetzt das den
Clone von `csscan`; GitHub ist dann gar nicht mehr beteiligt:

```bash
runuser -u csscan -- /opt/container-security-scan/container-security-scan.py \
    --db /var/lib/container-security-scan/osv-db --db-aktualisieren               # täglich, als csscan
/opt/container-security-scan/container-security-scan.py \
    --db /var/lib/container-security-scan/osv-db --oeffentliche … --nur-behebbare  # Scan als root
```

- **Erster Lauf:** die Gesamtexporte, zusammen ca. 390 MB (Stand 11/2026: npm 220 MB, Debian 81 MB,
  PyPI 38 MB, die übrigen je ca. 10 MB; endoflife.date 3 MB, KEV-Katalog 2 MB).
- **Danach inkrementell:** Das Skript liest die Änderungsliste `modified_id.csv` bis zum letzten
  bekannten Stand und lädt nur die geänderten Einträge einzeln. Den Gesamtexport eines Ökosystems lädt
  es neu, wenn seit dem letzten Lauf mehr als 2000 Einträge geändert wurden oder sich mehr als 10 000
  Einzeldateien angesammelt haben. Debian ändert oft Tausende Einträge an einem Tag; im Mittel sind
  daher ca. 30–40 MB pro Tag zu erwarten, gelegentlich mehr (npm neu: 220 MB).
- **Auf der Platte** liegen die ungekürzten Exporte (`<Ökosystem>.zip`, ca. 390 MB) und geänderte
  Einträge (`<Ökosystem>.neu/`), nicht der gekürzte Auszug aus dem Repository. Die Ergebnisse sind
  gleich; das Einlesen dauert etwas länger (Debian: ca. 3,5 s statt 1,9 s je Container).

| | über GitHub (Standard) | direkt (`--db DIR`) |
|---|---|---|
| Übertragung | erstmals ca. 15–25 MB, täglich nur die Änderungen | erstmals ca. 390 MB, täglich ca. 30–40 MB |
| Speicher | ca. 170 MB plus Git | ca. 390 MB |
| Freigabe im Proxy/Firewall | `github.com` | `osv-vulnerabilities.storage.googleapis.com`, `endoflife.date`, `www.cisa.gov` |
| Datenstand beim Scan | letzte Action (03:17 UTC) | Zeitpunkt der Aktualisierung |
| Nachvollziehbarkeit | Git-Historie der Daten | nur `stand.json` |
| Übernahme des GitHub-Repositorys | bei getrennten Daten: Daten fälschbar (falsche Ergebnisse), kein Code als root | ohne Folgen für die Daten |
| bei Ausfall | von GitHub/Action: Daten veralten (nach 3 Tagen Rückgabewert 2) | von OSV: Aktualisierung schlägt fehl |

Der Zeitgewinn beim direkten Abruf ist gering, wenn der Scan wie empfohlen einige Stunden nach der
Action läuft. Der direkte Weg lohnt sich vor allem, wenn der Server `github.com` nicht erreichen darf
oder GitHub auch als Datenquelle ausgeschlossen sein soll.

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

Ein Beispiel aus dem Test: freetype CVE-2025-27363 (MEDIUM laut Debian, Paket nicht geladen, also P4) in
einem Solr-Image. Ohne KEV nie gemeldet; laut CISA wird die Lücke aktiv ausgenutzt.

## Rein lesend und ohne Datenabfluss

- Im Container laufen nur: `find`/`tar` (Metadaten-Dateien lesen; Container-Dateisystem und Volumes,
  nicht eingebundene Host-Verzeichnisse wie `/var/lib/docker`), ein POSIX-sh-Skript, das `/proc` liest –
  je Prozess-Benutzer, da Docker auch root im Container keinen Zugriff auf fremde Prozesse gibt –, und
  Versionsabfragen der gefundenen Programme (`node -e`, `php -r`, `python -I -S -c`, `java -version` …)
  mit Zeitlimit, im Verzeichnis `/` und **nie mit mehr Rechten als der laufende Prozess**.
- Die Konfiguration der Webserver (`nginx -T`, `apache2 -S/-M/-t`) wird mit dem Benutzer des jeweiligen
  Hauptprozesses abgefragt, nicht als root: Programm, Optionen und Konfiguration bestimmt der Container,
  und `load_module`/`LoadModule` würde dabei Code laden. `nginx -T` kann wie `nginx -t` fehlende Log- oder
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

- Schweregrad: Einstufung der Distribution (Debian, Ubuntu), sonst Angabe der Quelle, sonst CVSS 3 bzw.
  eine Näherung für CVSS 4 (eher zu hoch), sonst die Bewertung derselben CVE aus Bitnami/Alpine (`*`). Als
  Schadsoftware gemeldete Pakete (`MAL-…`) gelten als CRITICAL. Einträge, für die es nirgends eine Bewertung
  gibt („UNKNOWN“), zählen nicht als relevant (außer KEV), werden aber eigens ausgewiesen.
- Lücken nur unter Windows werden nur erkannt, wenn der Titel es eindeutig sagt; sonst Ausnahmeliste.
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

### Tests

```bash
python3 -m unittest discover -s tests                                   # Unit-Tests, ohne Docker (ca. 1 s)
./container-security-scan.py --db-aktualisieren                       # Daten (Branch daten) für den Docker-Test
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit echten Containern
```

| Datei | Prüft |
|---|---|
| `test_versionen.py` | Versionsvergleiche (dpkg, rpm, apk, SemVer, PEP 440, Maven, PHP) und OSV-Versionsbereiche |
| `test_schweregrad.py` | CVSS 3/4, Vorrang von Quellen-Einstufung, Debian-Dringlichkeit, Ubuntu-Priorität, `MAL-…` |
| `test_inventar.py` | dpkg (auch distroless), apk, rpm, npm/Composer/PyPI, JS-Bibliotheken, JARs, Go-Build-Info, tar-Strom |
| `test_prozesse.py` | Prozesse, Ports und Dateien aus `/proc` (je Prozess-Benutzer bzw. über den Host, nie alle Host-Prozesse), Volumes, fester Suchpfad im Container, Benutzer der Versionsabfragen |
| `test_webserver.py` | nginx-/Apache-Konfiguration, `nginx -T` mit `-p`/`-c` und dem Benutzer des Hauptprozesses (nie root für fremde Programme/Optionen), veröffentlichte Ports, Backends |
| `test_nutzung.py` | Zuordnung Komponente → Dienst, Erreichbarkeit, Priorität P1–P4 |
| `test_osv.py` | Abgleich je Ökosystem, Quellpakete, Fremdquellen über Bitnami, Datenformat, inkrementelle Aktualisierung, ungültige Kennungen (kein Pfad) |
| `test_bewertung.py` | widersprüchliche Versionsbereiche der Distribution, Kernel-Pakete, Schweregrad über die CVE, KEV (Daten erzeugen, laden, markieren), Ausnahmeliste (Format, Rechte, Ablauf), nur Windows, Relevanz |
| `test_eol.py` | EOL-Daten erzeugen, Supportende und Vorwarnung |
| `test_ausgabe.py` | Bericht, CycloneDX-SBOM, Gesamtlauf mit Rückgabewerten 0/1/2 und bekannten Funden, KEV macht P4 relevant, Ausnahme, Kernel-Pakete |
| `test_kommandozeile.py` | Aufruf als Programm: Optionen (auch mehrfaches `--db`), `--db-aktualisieren` als root abgelehnt, holt bzw. aktualisiert nur den Branch `daten` (nie den Code), `daten/` ohne Git bricht ab, Berichte nur für den Aufrufer lesbar, docker nicht erreichbar, fehlerhafte Ausnahmeliste und unerwartete Fehler → 2 |
| `test_docker.py` | mit den Daten aus dem Branch `daten` unter `daten/`: nginx (`-c`) als Proxy vor Node: Proxy-Erkennung, EOL-Warnungen, Berichte, `docker diff` unverändert |

Die GitHub Action [`tests.yml`](.github/workflows/tests.yml) führt die Unit-Tests mit Python 3.6, 3.11 und 3.13
sowie den Docker-Test aus.

## Verwandte Werkzeuge

- [Trivy](https://trivy.dev), [Grype](https://github.com/anchore/grype),
  [OSV-Scanner](https://github.com/google/osv-scanner): Images, Dateisysteme, SBOMs; ohne Laufzeitkontext.
- [Vuls](https://github.com/future-architect/vuls): agentloser Scanner für Server, kann betroffene Prozesse zeigen.
- [Kubescape](https://kubescape.io) „Relevancy“: priorisiert nach tatsächlich geladenen Paketen (eBPF, Kubernetes).
