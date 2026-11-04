# Quellen und Lizenzen der Daten in `osv-daten/`

Die Dateien in diesem Verzeichnis sind **gekürzte Auszüge aus der [OSV-Datenbank](https://osv.dev)**
(Exporte unter `https://osv-vulnerabilities.storage.googleapis.com/<Ökosystem>/all.zip`). Sie werden
täglich von der GitHub Action `.github/workflows/osv-daten.yml` neu erzeugt.

**Bearbeitung:** Je Eintrag sind nur die Felder enthalten, die `container-security-scan.py` für den
Abgleich braucht (Kennung, Aliase, betroffene Pakete und Versionsbereiche, Schweregrad, Kurztitel,
Veröffentlichungsdatum). Ausführliche Beschreibungen, Referenzen, Danksagungen und vollständige
Versionslisten wurden entfernt. Format: JSON Lines, ein Eintrag je Zeile, nach Kennung sortiert.
Die vollständigen Einträge sind über `https://osv.dev/vulnerability/<Kennung>` abrufbar.

OSV fasst Daten verschiedener Herausgeber zusammen; **jede Quelle steht unter ihrer eigenen Lizenz**
(siehe [OSV: Datenquellen](https://google.github.io/osv.dev/data/)). Die Weitergabe hier erfolgt mit
Namensnennung und – wo verlangt – unter derselben Lizenz.

| Verzeichnis | Quelle (Kennungen) | Lizenz |
|---|---|---|
| `Alpine/` | Alpine Linux secdb, von OSV konvertiert (`ALPINE-…`) | [CC-BY-SA 4.0](https://secdb.alpinelinux.org/license.txt) – die gekürzten Daten in `Alpine/` stehen daher ebenfalls unter [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.de) |
| `Bitnami/` | [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb) (`BIT-…`) | [Apache 2.0](https://github.com/bitnami/vulndb/blob/main/LICENSE.md), Text: [`LIZENZEN/Apache-2.0.txt`](LIZENZEN/Apache-2.0.txt) |
| `Debian/` | [Debian Security Tracker](https://security-tracker.debian.org), von OSV konvertiert (`DEBIAN-CVE-…`, `DSA-…`, `DLA-…`, `DTSA-…`) | **keine ausdrückliche Lizenz** – siehe [unten](#debian) |
| `Go/` | [Go Vulnerability Database](https://pkg.go.dev/vuln) (`GO-…`) | [CC-BY 4.0](https://github.com/golang/vulndb#license) |
| `Maven/`, `npm/`, `Packagist/`, `PyPI/` | [GitHub Advisory Database](https://github.com/github/advisory-database) (`GHSA-…`) | [CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md) |
| `PyPI/` | [PyPA Advisory Database](https://github.com/pypa/advisory-database) (`PYSEC-…`) | [CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE) – geprüft |
| `npm/`, `PyPI/` u.a. | [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (`MAL-…`) | [Apache 2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE) – geprüft (keine NOTICE-Datei), Text: [`LIZENZEN/Apache-2.0.txt`](LIZENZEN/Apache-2.0.txt) |
| `Packagist/` | [Drupal Advisory Database](https://github.com/DrupalSecurityTeam/drupal-advisory-database) (`DRUPAL-…`) | [MIT](https://github.com/DrupalSecurityTeam/drupal-advisory-database/blob/main/LICENSE), © 2025 Ackama – geprüft, Text: [`LIZENZEN/MIT-Drupal-Advisory-Database.txt`](LIZENZEN/MIT-Drupal-Advisory-Database.txt) |

Geprüft am 4. November 2026 anhand der Lizenzdateien der Quell-Repositories und der Liste der
[OSV-Datenquellen](https://github.com/google/osv.dev/blob/master/docs/data.md), die für PyPA, OpenSSF
und Drupal dieselben Lizenzen nennt. Für die Apache-2.0-Daten gilt als Änderungshinweis (§ 4 b): die
Einträge sind gekürzt, siehe **Bearbeitung** oben.

Der Ubuntu-Export von OSV, der bei Bedarf lokal geladen werden kann, stammt aus
[Ubuntu Security Notices](https://github.com/canonical/ubuntu-security-notices) und steht laut
[OSV-Datenquellen](https://github.com/google/osv.dev/blob/master/docs/data.md) unter
[CC-BY-SA 4.0](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE). Er liegt nur
lokal in `osv-db/` und wird nicht weitergegeben.

### Debian

Für die Debian-Daten gibt es **keine ausdrückliche Lizenz**:

- Die [OSV-Datenquellen](https://github.com/google/osv.dev/blob/master/docs/data.md) führen die
  Debian-Daten als von OSV konvertierte Daten, ohne Lizenzangabe (anders als bei Alpine).
- Das Repository des [Debian Security Tracker](https://salsa.debian.org/security-tracker-team/security-tracker)
  (Quelle der Versionsangaben) enthält keine Lizenzdatei und keine Lizenzangabe; auch die Website
  des Trackers nennt keine.
- Die Ankündigungen (DSA/DLA) auf www.debian.org stehen seit 2012 unter der
  [Debian WWW Pages License](https://www.debian.org/license) (MIT/Expat oder GPL-2+). Aus ihnen
  stammt hier aber nur der Kurztitel („Paket – security update“).

Was `Debian/` tatsächlich enthält (ca. 73.000 Einträge, davon ca. 62.000 `DEBIAN-CVE-…`):

1. **Fakten** aus dem Tracker: Paketname, Debian-Release, betroffene und behobene Version,
   Dringlichkeit. Einzelne Versionsangaben sind als Tatsachen nicht urheberrechtlich geschützt; für
   die Sammlung als Ganzes ist ein Datenbankschutz (in der EU sui generis, §§ 87a ff. UrhG) nicht
   ausgeschlossen.
2. **Kurztitel**: bei `DEBIAN-CVE-…` die erste Zeile der CVE-Beschreibung (gekürzt auf 200 Zeichen).
   Diese Texte stammen aus dem CVE-Programm und dürfen nach den
   [CVE Terms of Use](LIZENZEN/CVE-Terms-of-Use.txt) (SPDX `cve-tou`) mit Copyright-Hinweis und
   Lizenztext weitergegeben werden: CVE® is a registered trademark of The MITRE Corporation.

Debian ist ein Freie-Software-Projekt und stellt die Daten ausdrücklich zur maschinellen Nutzung
bereit (JSON-Export des Trackers); OSV, Trivy und Grype verteilen sie ebenfalls weiter. Eine
schriftliche Klärung beim Debian Security Team (team@security.debian.org) steht aus; bis dahin ist
die Lizenzfrage **offen** (keine Rechtsberatung). Alternative ohne diese Frage: `Debian` nicht ins Repository übernehmen, sondern
wie Ubuntu lokal mit `--db-aktualisieren --oekosysteme Debian` laden.

Alle Angaben ohne Gewähr; maßgeblich sind die Lizenzangaben der jeweiligen Quelle.
Die Daten werden ohne Gewähr für Vollständigkeit oder Richtigkeit weitergegeben.
