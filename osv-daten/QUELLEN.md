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
| `PyPI/` | [PyPA Advisory Database](https://github.com/pypa/advisory-database) (`PYSEC-…`) | [CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE) |
| `npm/`, `PyPI/` u.a. | [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (`MAL-…`) | [Apache 2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE) |
| `Packagist/` | [Drupal Advisory Database](https://github.com/DrupalSecurityTeam/drupal-advisory-database) (`DRUPAL-…`) | [MIT](https://github.com/DrupalSecurityTeam/drupal-advisory-database/blob/main/LICENSE); Lizenztext und Copyright unten |

Der Ubuntu-Export von OSV, der bei Bedarf lokal geladen werden kann, stammt aus
[Ubuntu Security Notices](https://github.com/canonical/ubuntu-security-notices) und steht laut
[OSV-Datenquellen](https://github.com/google/osv.dev/blob/master/docs/data.md) unter
[CC-BY-SA 4.0](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE).

### Drupal Advisory Database: MIT-Lizenz

```text
The MIT License (MIT)

Copyright (c) 2025 Ackama

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

Alle Angaben ohne Gewähr; maßgeblich sind die Lizenzangaben der jeweiligen Quelle.
Die Daten werden ohne Gewähr für Vollständigkeit oder Richtigkeit weitergegeben.
