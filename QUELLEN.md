# Quellen und Lizenzen der Daten in diesem Branch (`daten`)

Die Dateien in diesem Verzeichnis sind **gekürzte Auszüge aus der [OSV-Datenbank](https://osv.dev)**
(Exporte unter `https://osv-vulnerabilities.storage.googleapis.com/<Ökosystem>/all.zip`). Sie werden
täglich von der GitHub Action [`.github/workflows/daten.yml`](https://github.com/felixlohmeier/container-security-scan/blob/main/.github/workflows/daten.yml) im Branch `main` neu erzeugt.

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
| `Debian/` | [Debian Security Tracker](https://security-tracker.debian.org), von OSV konvertiert (`DEBIAN-CVE-…`, `DSA-…`, `DLA-…`, `DTSA-…`) | **Todo: Lizenz klären** |
| `Ubuntu/` | [Ubuntu Security Notices](https://github.com/canonical/ubuntu-security-notices) (`UBUNTU-CVE-…`); zusätzlich gekürzt: ohne USN-Sammelmeldungen, Ubuntu Pro/FIPS/Realtime, Kernel-Quellpakete und Listen der Binärpakete | [CC-BY-SA 4.0](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE) – die gekürzten Daten in `Ubuntu/` stehen daher ebenfalls unter [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.de) |
| `SUSE/` | [SUSE Security](https://www.suse.com/support/security/), OSV-Daten von SUSE (`https://ftp.suse.com/pub/projects/security/osv/`; `SUSE-SU-…`, `SUSE-RU-…` u. a.); zusätzlich gekürzt: nur SLES 15 und 16, Listen der Binärpakete je Service Pack statt je Produkt | [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/deed.de) laut SUSE für die CSAF- und OVAL-Daten ([CSAF](https://www.suse.com/support/security/csaf/), [OVAL](https://www.suse.com/support/security/oval/)); für den OSV-Export keine eigene Angabe gefunden (auch keine Lizenzdatei im Verzeichnis, geprüft am 14. November 2026) – **Todo: für OSV bestätigen** |
| `Go/` | [Go Vulnerability Database](https://pkg.go.dev/vuln) (`GO-…`) | [CC-BY 4.0](https://github.com/golang/vulndb#license) |
| `Maven/`, `npm/`, `Packagist/`, `PyPI/` | [GitHub Advisory Database](https://github.com/github/advisory-database) (`GHSA-…`) | [CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md) |
| `PyPI/` | [PyPA Advisory Database](https://github.com/pypa/advisory-database) (`PYSEC-…`) | [CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE) – geprüft |
| `npm/`, `PyPI/` u.a. | [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (`MAL-…`) | [Apache 2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE) – geprüft (keine NOTICE-Datei), Text: [`LIZENZEN/Apache-2.0.txt`](LIZENZEN/Apache-2.0.txt) |
| `Packagist/` | [Drupal Advisory Database](https://github.com/DrupalSecurityTeam/drupal-advisory-database) (`DRUPAL-…`) | [MIT](https://github.com/DrupalSecurityTeam/drupal-advisory-database/blob/main/LICENSE), © 2025 Ackama – geprüft, Text: [`LIZENZEN/MIT-Drupal-Advisory-Database.txt`](LIZENZEN/MIT-Drupal-Advisory-Database.txt) |
| `eol-daten.json` | [endoflife.date](https://endoflife.date) (Auszug aus `/api/v1/products/full/`) | MIT, Text: [`EOL-LIZENZ.txt`](EOL-LIZENZ.txt) |
| `kev.json` | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (je CVE das Datum der Aufnahme) | [CC0 1.0](https://github.com/cisagov/kev-data/blob/main/LICENSE) – geprüft (Lizenzdatei von `cisagov/kev-data`); keine Nutzung von CISA-Logo oder DHS-Siegel, keine Billigung durch CISA/DHS |
| `suse-schweregrad.json` | SUSEs CVSS-Bewertung je CVE ([`suse-cvss-scores.yaml`](https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml); je CVE der Wert nach CVSS 3.x, sonst 4.0) | [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/deed.de) laut [Lizenzdatei im Verzeichnis](https://ftp.suse.com/pub/projects/security/yaml/LICENSE) – geprüft am 14. November 2026 (die Datei spricht von den „OVAL data“, liegt aber im Verzeichnis der YAML-Datei) |

Geprüft am 4. November 2026 anhand der Lizenzdateien der Quell-Repositories und der Liste der
[OSV-Datenquellen](https://github.com/google/osv.dev/blob/master/docs/data.md), die für PyPA, OpenSSF
und Drupal dieselben Lizenzen nennt. Für die Apache-2.0-Daten gilt als Änderungshinweis (§ 4 b): die
Einträge sind gekürzt, siehe **Bearbeitung** oben.

Alle Angaben ohne Gewähr; maßgeblich sind die Lizenzangaben der jeweiligen Quelle.
Die Daten werden ohne Gewähr für Vollständigkeit oder Richtigkeit weitergegeben.
