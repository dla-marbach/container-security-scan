#!/bin/bash
# Beispiele neu erzeugen (README: Releases): Testumgebung starten, alle Container scannen, Berichte nach
# beispiele/ schreiben; danach ein SLES-Server ohne Docker (beispiele/umgebung/host/, als Container) mit --host.
# Voraussetzungen: Docker mit Compose, freie Ports 8080 und 8081, Daten unter daten/ (mit SUSE;
# ./container-security-scan.py --db-aktualisieren). Als root, wie im Betrieb (sonst Warnung zum Host):
#   sudo bash beispiele/erzeugen.sh
# Zusätzliche Optionen für docker build (z.B. Proxy): CSS_DOCKER_BUILD_ARGS="--network host --secret id=ca,src=…"
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f beispiele/umgebung/compose.yml)
HOST=css-beispiel-host       # Name des Images
HOST_ID=                     # Container dieses Laufs: nur ihn entfernen, nie einen gleichnamigen anderen
trap '"${COMPOSE[@]}" down; [ -z "$HOST_ID" ] || docker rm -f "$HOST_ID" >/dev/null 2>&1 || true' EXIT
[ -d daten/SUSE ] || { echo "FEHLER: daten/SUSE fehlt (Daten aktualisieren: --db-aktualisieren)" >&2; exit 2; }
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

rm -f beispiele/scan_* beispiele/host_* beispiele/bekannt_*.json beispiele/ausgabe*.txt
rc=0
python3 -I container-security-scan.py --db daten --alle-container beispiele --nur-behebbare \
    > beispiele/ausgabe.txt 2>&1 || rc=$?
[ "$rc" -le 1 ] || { cat beispiele/ausgabe.txt; echo "FEHLER: Rückgabewert $rc" >&2; exit 2; }

# Berichte aller Container, aber nur ein SBOM (app-node) als Beispiel des Formats: die übrigen wären groß
# (PHP über 1000 Komponenten) und blähten jeden Diff auf; keine .sha256. Dateinamen ohne Zeitpunkt (feste Links)
rm -f beispiele/bekannt_*.json beispiele/scan_*.sha256
for f in beispiele/scan_*; do
  mv "$f" "$(sed -E 's/_[0-9]{8}_[0-9]{6}//' <<<"$f")"
done
find beispiele -maxdepth 1 -name 'scan_*.cdx.json' ! -name scan_app-node.cdx.json -delete
sed -E -i 's/(scan_[A-Za-z0-9_.-]+)_[0-9]{8}_[0-9]{6}/\1/g' beispiele/ausgabe.txt beispiele/scan_*.md
"${COMPOSE[@]}" down

# SLES-Server ohne Docker: Dienste aus den SLES-Paketen, Scan mit --host im Container (root mit den Rechten wie
# auf einem Host). Nur der Bericht und die Konsolenausgabe, ohne SBOM
# shellcheck disable=SC2086
DOCKER_BUILDKIT=1 docker build -q -t $HOST ${CSS_DOCKER_BUILD_ARGS:-} -f beispiele/umgebung/host/Dockerfile \
    beispiele/umgebung >/dev/null
HOST_ID=$(docker run -d --hostname web01.example.com --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
    -v "$PWD/container-security-scan.py:/scan/container-security-scan.py:ro" -v "$PWD/daten:/daten:ro" $HOST)
for _ in $(seq 90); do docker exec "$HOST_ID" test -e /run/bereit && break; sleep 1; done
docker exec "$HOST_ID" test -e /run/bereit \
    || { docker logs "$HOST_ID"; echo "FEHLER: SLES-Umgebung nicht bereit" >&2; exit 2; }
sleep 2
rc_host=0
docker exec "$HOST_ID" python3 -I /scan/container-security-scan.py --db /daten --host --alle-container /out \
    --nur-behebbare > beispiele/ausgabe-host.txt 2>&1 || rc_host=$?
[ "$rc_host" -le 1 ] || { cat beispiele/ausgabe-host.txt; echo "FEHLER: Rückgabewert $rc_host (Host)" >&2; exit 2; }
docker exec "$HOST_ID" sh -c 'cat /out/host_web01_*.md' > beispiele/host_web01.md
sed -E -i 's/(host_[A-Za-z0-9_.-]+)_[0-9]{8}_[0-9]{6}/\1/g' beispiele/ausgabe-host.txt beispiele/host_web01.md

chmod 644 beispiele/ausgabe*.txt beispiele/scan_* beispiele/host_*   # öffentliche Beispiele (sonst nur für root)
[ -z "${SUDO_UID:-}" ] || chown "$SUDO_UID:$SUDO_GID" beispiele/ausgabe*.txt beispiele/scan_* beispiele/host_*
echo "Beispiele erzeugt (Rückgabewert des Scans: $rc, des Hosts: $rc_host)"
