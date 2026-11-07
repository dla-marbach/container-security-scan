# Tests

```bash
python3 -m unittest discover -s tests                                        # Unit-Tests, ohne Docker (ca. 1 s)
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit echten Containern (Daten unter daten/)
```

| Datei | Prüft |
|---|---|
| `test_versionen.py` | Versionsvergleiche (dpkg, rpm, apk, SemVer, PEP 440, Maven, PHP) und OSV-Versionsbereiche |
| `test_schweregrad.py` | CVSS 3/4, Vorrang von Quellen-Einstufung, Debian-Dringlichkeit, Ubuntu-Priorität, `MAL-…` |
| `test_inventar.py` | dpkg (auch distroless), apk, rpm, npm/Composer/PyPI, JS-Bibliotheken, JARs, Go-Build-Info, tar-Strom |
| `test_prozesse.py` | Prozesse, Ports und Dateien aus `/proc` (je Prozess-Benutzer bzw. über den Host, nie alle Host-Prozesse), Volumes, fester Suchpfad im Container, Benutzer der Versionsabfragen |
| `test_webserver.py` | nginx-/Apache-Konfiguration, `nginx -T` mit `-p`/`-c` und dem Benutzer des Hauptprozesses (nie root für fremde Programme/Optionen), nginx-Variablen (`set`, `map`), veröffentlichte Ports, Backends, Docker-Netze (macvlan, geroutet, Host-Netzwerk, gemeinsamer Netzwerk-Namespace), Ziele aus Traefik-/Caddy-Labels, Proxys und Tunnel direkt auf dem Host (Erkennung, Benutzer der Abfrage, Ziele über Container-IP) |
| `test_nutzung.py` | Zuordnung Komponente → Dienst, Erreichbarkeit (auch „möglicherweise“ über nicht auswertbare Proxys, Ziel-URLs und offene Verbindungen, Datenbanken als Ziel ausgenommen), Priorität P1–P4 |
| `test_osv.py` | Abgleich je Ökosystem, Quellpakete, Fremdquellen über Bitnami, Datenformat, Kürzung der Ubuntu-Daten (gleiche Funde wie vollständig), inkrementelle Aktualisierung, ungültige Kennungen (kein Pfad) |
| `test_bewertung.py` | widersprüchliche Versionsbereiche der Distribution, Kernel-Pakete, Schweregrad über die CVE, KEV (Daten erzeugen, laden, markieren), Ausnahmeliste (Format, Rechte, Ablauf), nur Windows, Relevanz, gefährliche Einstellungen (`CONF-…`), öffentliche Dienste als root (auch userns-remap/rootless) |
| `test_eol.py` | EOL-Daten erzeugen, Supportende und Vorwarnung |
| `test_ausgabe.py` | Bericht, CycloneDX-SBOM, Gesamtlauf mit Rückgabewerten 0/1/2 und bekannten Funden, KEV macht P4 relevant, gefährliche Einstellungen ergeben 1 (auch ohne Schwachstellen, Ausnahme nach Containername), root-Dienst nur Warnung (auch über Proxy-Ziel, nicht bei Loopback), Ausnahme, Kernel-Pakete |
| `test_kommandozeile.py` | Aufruf als Programm: Optionen (auch mehrfaches `--db`), Reihenfolge und Weitergabe der Erreichbarkeit mit `--alle-container`/`--oeffentliche`, `--db-aktualisieren` als root abgelehnt, holt bzw. aktualisiert nur den Branch `daten` (nie den Code), `daten/` ohne Git bricht ab, Berichte nur für den Aufrufer lesbar, docker nicht erreichbar, fehlerhafte Ausnahmeliste und unerwartete Fehler → 2 |
| `test_docker.py` | mit den Daten aus dem Branch `daten` unter `daten/`, Lauf mit `--alle-container`: nginx (`-c`) als Proxy vor Node (direkt und über `set $backend`), Traefik mit Label-Ziel und Nachbar ohne Label, gemeinsamer Netzwerk-Namespace, interner Container, Gateway in Node mit Ziel-URL und offenen Verbindungen (zu Node und Redis), nginx direkt auf dem Host vor einer Container-IP (wenn nginx installiert ist); EOL-Warnungen, Berichte, `docker diff` unverändert |
| `test_installation.py` | `VERSION` (Format, `--version`, beim Push eines Tags gleich dem Tag), Installscript und Wrapper unter `installation/` (Syntax, nur vorhandene Dateien, Code nur über `python3 -I`), Beispiele der Ausnahmeliste gültig (auskommentiert und aktiviert, mit `CONF-…`), Beispiele mit der aktuellen Version erzeugt, Links auf `beispiele/` und `installation/` gültig. |
