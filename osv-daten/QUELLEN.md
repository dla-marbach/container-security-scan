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
| `Alpine/` | Alpine Linux secdb, von OSV konvertiert (`ALPINE-…`) | CC-BY-SA 4.0 – die gekürzten Daten in `Alpine/` stehen daher ebenfalls unter [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.de) |
| `Bitnami/` | [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb) (`BIT-…`) | Apache 2.0 |
| `Debian/` | [Debian Security Tracker](https://security-tracker.debian.org) (`DEBIAN-CVE-…`, `DSA-…`, `DLA-…`, `DTSA-…`) | *noch nicht abschließend geprüft* (öffentlich bereitgestellte Daten des Debian-Projekts) |
| `Go/` | [Go Vulnerability Database](https://pkg.go.dev/vuln) (`GO-…`) | CC-BY 4.0 |
| `Maven/`, `npm/`, `Packagist/`, `PyPI/` | [GitHub Advisory Database](https://github.com/github/advisory-database) (`GHSA-…`) | CC-BY 4.0 |
| `PyPI/` | [PyPA Advisory Database](https://github.com/pypa/advisory-database) (`PYSEC-…`) | *zu prüfen* (laut Projekt CC-BY 4.0) |
| `npm/`, `PyPI/` u.a. | [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (`MAL-…`) | *zu prüfen* (laut Projekt Apache 2.0) |
| `Packagist/` | Drupal Security Advisories (`DRUPAL-…`) | *zu prüfen* |

Alle Angaben ohne Gewähr; maßgeblich sind die Lizenzangaben der jeweiligen Quelle.
Die Daten werden ohne Gewähr für Vollständigkeit oder Richtigkeit weitergegeben.
