#!/bin/bash
# Beispiele neu erzeugen (README: Releases): Testumgebung starten, alle Container scannen, Berichte nach
# beispiele/ schreiben. Voraussetzungen: Docker mit Compose, freie Ports 8080 und 8081, Daten unter daten/
# (./container-security-scan.py --db-aktualisieren). Als root, wie im Betrieb (sonst Warnung zum Host):
#   sudo bash beispiele/erzeugen.sh
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f beispiele/umgebung/compose.yml)
trap '"${COMPOSE[@]}" down' EXIT
"${COMPOSE[@]}" up -d
bereit() {                     # beide Proxys erreichen ihre Ziele
  curl -fs localhost:8080/index.php >/dev/null && curl -fs localhost:8080/ >/dev/null && curl -fs localhost:8081/ >/dev/null
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
python3 -I container-security-scan.py --db daten --alle-container beispiele --nur-behebbare \
    > beispiele/ausgabe.txt 2>&1 || rc=$?
[ "$rc" -le 1 ] || { cat beispiele/ausgabe.txt; echo "FEHLER: Rückgabewert $rc" >&2; exit 2; }

# Berichte und ein SBOM, Dateinamen ohne Zeitpunkt (feste Links im README)
rm -f beispiele/bekannt_*.json beispiele/scan_*.sha256
for f in beispiele/scan_*; do
  mv "$f" "$(sed -E 's/_[0-9]{8}_[0-9]{6}//' <<<"$f")"
done
find beispiele -maxdepth 1 -name 'scan_*.cdx.json' ! -name scan_app-node.cdx.json -delete
sed -E -i 's/(scan_[A-Za-z0-9_.-]+)_[0-9]{8}_[0-9]{6}/\1/g' beispiele/ausgabe.txt beispiele/scan_*.md
chmod 644 beispiele/ausgabe.txt beispiele/scan_*       # öffentliche Beispiele (Berichte sonst nur für root)
[ -z "${SUDO_UID:-}" ] || chown "$SUDO_UID:$SUDO_GID" beispiele/ausgabe.txt beispiele/scan_*
echo "Beispiele erzeugt (Rückgabewert des Scans: $rc)"
