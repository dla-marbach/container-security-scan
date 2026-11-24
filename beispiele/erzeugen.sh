#!/bin/bash
# Beispiele neu erzeugen (README: Releases): Testumgebung starten, alle Container scannen, Berichte nach
# beispiele/ schreiben. Voraussetzungen: Docker mit Compose, freier Port 8080, Daten unter daten/
# (./container-security-scan.py --db-aktualisieren). Als root, wie im Betrieb (sonst Warnung zum Host):
#   sudo bash beispiele/erzeugen.sh
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f beispiele/umgebung/compose.yml)
trap '"${COMPOSE[@]}" down' EXIT
"${COMPOSE[@]}" up -d
bereit() {                     # der Proxy erreicht beide Ziele
  curl -fs localhost:8080/index.php >/dev/null && curl -fs localhost:8080/ >/dev/null
}
for _ in $(seq 60); do bereit && break; sleep 1; done
bereit || { "${COMPOSE[@]}" ps -a; echo "FEHLER: Testumgebung antwortet nicht" >&2; exit 2; }
# --alle-container scannt alle laufenden Container; Berichte anderer Container (Kommandozeilen, Konfiguration)
# dürfen nicht in die öffentlichen Beispiele geraten
andere=$(comm -23 <(docker ps -q --no-trunc | sort) <("${COMPOSE[@]}" ps -q | sort))
[ -z "$andere" ] || { echo "FEHLER: Außer der Testumgebung laufen weitere Container ($(docker inspect -f \
  '{{.Name}}' $andere | tr -d / | xargs)) – stoppen oder einen eigenen Docker-Daemon verwenden" >&2; exit 2; }

rm -f beispiele/scan_* beispiele/bekannt_*.json beispiele/ausgabe.txt
rc=0
python3 -I container-security-scan.py --db daten --alle-container beispiele --nur-behebbare --bericht --sbom \
    > beispiele/ausgabe.txt 2>&1 || rc=$?
[ "$rc" -le 1 ] || { cat beispiele/ausgabe.txt; echo "FEHLER: Rückgabewert $rc" >&2; exit 2; }

# Berichte aller Container, aber nur eine SBOM (app-node) als Beispiel des Formats: die übrigen wären groß
# (PHP über 1000 Komponenten) und blähten jeden Diff auf; keine .sha256. Dateinamen ohne Zeitpunkt (feste Links)
rm -f beispiele/bekannt_*.json beispiele/scan_*.sha256
for f in beispiele/scan_*; do
  mv "$f" "$(sed -E 's/_[0-9]{8}_[0-9]{6}//' <<<"$f")"
done
find beispiele -maxdepth 1 -name 'scan_*.cdx.json' ! -name scan_app-node.cdx.json -delete
sed -E -i 's/(scan_[A-Za-z0-9_.-]+)_[0-9]{8}_[0-9]{6}/\1/g' beispiele/ausgabe.txt beispiele/scan_*.md
# Konsolenausgabe wie im Betrieb (Wrapper ohne --bericht): ohne den Hinweis auf den Bericht; ohne Rechnernamen
sed -E -i -e 's/ – Bericht: beispiele\/scan_[A-Za-z0-9_.-]+\.md$//' \
    -e 's/^Host: [^ ]+ mit ([0-9]+ laufenden)/Host: <rechner> mit \1/' beispiele/ausgabe.txt
chmod 644 beispiele/ausgabe.txt beispiele/scan_*       # öffentliche Beispiele (Berichte sonst nur für root)
[ -z "${SUDO_UID:-}" ] || chown "$SUDO_UID:$SUDO_GID" beispiele/ausgabe.txt beispiele/scan_*
echo "Beispiele erzeugt (Rückgabewert des Scans: $rc)"
