# container-security-scan: Daten

Dieser Branch enthält **nur Daten**, keinen Code: gekürzte Auszüge aus [OSV](https://osv.dev) je Ökosystem
(`<Ökosystem>/*.jsonl`, `stand.json`), Supportende von [endoflife.date](https://endoflife.date)
(`eol-daten.json`) und den KEV-Katalog der CISA (`kev.json`). Die GitHub Action im Branch `main` erzeugt
sie täglich neu; Quellen und Lizenzen: [`QUELLEN.md`](QUELLEN.md).

Code und Anleitung: Branch [`main`](https://github.com/felixlohmeier/container-security-scan). Auf dem
Server holt ein Benutzer ohne Rechte diesen Branch, der Scan liest ihn mit `--db`:

```bash
runuser -u csscan -- git clone --single-branch --branch daten \
    https://github.com/felixlohmeier/container-security-scan.git /var/lib/container-security-scan/daten
/opt/container-security-scan/container-security-scan.py --db /var/lib/container-security-scan/daten --oeffentliche …
```
