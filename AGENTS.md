# AGENTS.md

Hinweise für Coding-Agenten. Für Nutzer gilt das [README](README.md), für die Tests [`tests/README.md`](tests/README.md).

## Projekt

Schwachstellen-Scan für laufende Docker-Container. Der Scanner läuft auf Servern **als root**; jede Änderung
ist sicherheitsrelevant.

```
container-security-scan.py   der gesamte Scanner (eine Datei), enthält VERSION
installation/                Installscript, Wrapper, Vorlage der Ausnahmeliste
beispiele/                   erzeugte Berichte; umgebung/ = Testumgebung, erzeugen.sh erzeugt sie neu
tests/                       unittest, eine Datei je Bereich (Übersicht in tests/README.md)
.github/workflows/           tests.yml (Unit-Tests; Docker-Test bei PRs und auf main), daten.yml (Daten, täglich)
```

Die Daten (OSV-Auszug, EOL, KEV) liegen im Branch `daten` und werden nur von `daten.yml` geschrieben. Lokal
liegen sie unter `daten/` (in `.gitignore`), geholt mit `./container-security-scan.py --db-aktualisieren`.
Den Branch `daten` nie von Hand ändern.

## Regeln für den Code

- **Python ≥ 3.6 und nur die Standardbibliothek** (SLES 15). Kein `capture_output`/`text=` bei
  `subprocess.run`, keine `dataclasses`, kein Walross-Operator; Formatierung mit `%` wie im übrigen Code.
  Externe Befehle über die Hilfsfunktion `run()`.
- **Rein lesend:** Im Container nur Abfragen (find/tar, `/proc`, Versionsabfragen mit Zeitlimit), nie mit
  mehr Rechten als der jeweilige Prozess. Keine Paketlisten oder andere Daten des Servers ins Netz.
- **Im Zweifel unvollständig:** Was nicht vollständig geprüft werden konnte, ergibt Rückgabewert 2, nie 0.
  Rückgabewerte 0/1/2 und die Zeile `ERGEBNIS: …` des Wrappers sind Schnittstelle für cron und Rundeck.
- Der Wrapper startet den Code nur mit `python3 -I`. `--db-aktualisieren` lehnt root ab und bleibt so.
- Texte, Kommentare, Meldungen, Commit-Nachrichten und Dokumentation auf **Deutsch**.
- GitHub Actions nur auf einen Commit festgelegt (`uses: owner/action@<sha>  # vX.Y.Z`); Runner `ubuntu-26.04`.

## Tests

```bash
python3 -m unittest discover -s tests                                        # schnell, ohne Docker; vor jedem Commit
CSS_DOCKER_TESTS=1 python3 -m unittest discover -s tests -p test_docker.py   # mit Docker und daten/
sudo bash beispiele/erzeugen.sh                                              # Beispiele neu (Docker, daten/)
```

Beispiele und Installscript laufen nicht in der Action, sondern lokal vor dem Pull Request; die Befehle für
das Installscript (aus einem lokalen Tag, nur auf einem Testrechner) stehen im README unter „Entwicklung und
Tests“.

Neue Funktionen und Fehlerkorrekturen bekommen einen Test in der passenden Datei; `tests/README.md` nennt,
was welche Datei prüft, und wird mitgepflegt. Tests nie abschalten oder überspringen, um grün zu werden.

## Was synchron bleiben muss

- **Version:** steht nur in `VERSION` in `container-security-scan.py`. Installscript, Wrapper und README
  nennen keine aktuelle Version; das soll so bleiben. `VERSION` nur im Release-PR ändern (README: Releases).
- **Beispiele:** `test_installation.py` verlangt, dass `beispiele/` mit der aktuellen `VERSION` erzeugt ist.
  Nie von Hand bearbeiten, sondern mit `sudo bash beispiele/erzeugen.sh` neu erzeugen, und zwar im selben PR,
  der `VERSION` oder das Format der Berichte ändert.
- **Installation:** Wrapper und Vorlage der Ausnahmeliste nur unter `installation/` ändern; das Installscript
  installiert genau die Dateien, die es aus dem Tag holt. Ändert sich, was Admins tun müssen, gehört das in
  README und Release-Hinweise.
- **README:** Optionen, Rückgabewerte, Pfade und erkannte Komponenten müssen zum Code passen. Kurz und
  sachlich, keine Doppelungen. Links auf `beispiele/` und `installation/` prüft ein Test.

## Nicht tun

- Kein automatisches Update des Codes auf Servern einführen (Code nur von Hand, aus einem Tag).
- Keine Tags oder Releases anlegen; das macht der Maintainer nach dem Merge.
- Nicht direkt nach `main` pushen; Änderungen über einen Branch und Pull Request.
