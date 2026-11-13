#!/bin/bash
# container-security-scan einrichten oder aktualisieren (README: Installation und Betrieb):
#   sudo bash installieren.sh vX.Y.Z [commit]
#   mit Proxy: sudo env https_proxy=http://proxy:3128 bash installieren.sh vX.Y.Z
# Holt den Tag vX.Y.Z (mit Commit-Hash nur, wenn der Tag genau auf diesen Commit zeigt) und installiert daraus
# Code und Wrapper. Legt Benutzer csscan, Daten und Ausnahmeliste an, falls sie fehlen.
set -euo pipefail
VERSION=${1:-}
COMMIT=${2:-}
REPO=${REPO:-https://github.com/dla-marbach/container-security-scan.git}   # Code; auch ein Bundle (README)
DATEN=${DATEN-https://github.com/dla-marbach/container-security-scan.git}  # Daten; leer: nicht holen (README)
D=/var/lib/container-security-scan

fehler() { echo "FEHLER: $*" >&2; exit 2; }
[[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fehler "Aufruf: sudo bash $0 vX.Y.Z [commit]"
[[ -z $COMMIT || $COMMIT =~ ^[0-9a-f]{40}$ ]] || fehler "Commit als vollständigen Hash (40 Zeichen) angeben"
[ "$(id -u)" -eq 0 ] || fehler "als root ausführen (sudo)"
umask 022
cd /
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Tag holen: nur ein Tag (kein Branch gleichen Namens), optional genau der angegebene Commit
S=$TMP/src
git -c advice.detachedHead=false clone -q --depth 1 --branch "$VERSION" "$REPO" "$S"
HEAD=$(git -C "$S" rev-parse HEAD)
[ "$(git -C "$S" rev-parse -q --verify "refs/tags/$VERSION^{commit}" || true)" = "$HEAD" ] \
    || fehler "$VERSION ist kein Tag"
[ -z "$COMMIT" ] || [ "$COMMIT" = "$HEAD" ] || fehler "$VERSION zeigt auf $HEAD, nicht auf $COMMIT"
grep -qx "VERSION = \"${VERSION#v}\"" "$S/container-security-scan.py" || fehler "Version im Skript ist nicht $VERSION"

# Benutzer csscan und Daten (Branch daten), falls sie fehlen (vor dem Austausch des Codes:
# scheitert das Netz, bleibt die bisherige Installation); der Proxy gilt auch für das tägliche git pull
id csscan >/dev/null 2>&1 || useradd -r -U -m -d "$D" -s /sbin/nologin csscan
[ -z "${https_proxy:-}" ] || runuser -u csscan -- git config --global http.proxy "$https_proxy"
[ -z "$DATEN" ] || [ -d "$D/daten" ] || runuser -u csscan -- git clone -q --single-branch --branch daten \
    "$DATEN" "$D/daten"

# Code: das Verzeichnis enthält danach nur das Skript
rm -rf /opt/container-security-scan
install -D -m 755 "$S/container-security-scan.py" /opt/container-security-scan/container-security-scan.py

# Wrapper als neue Datei (install ersetzt, statt zu überschreiben): ein laufender Scan bleibt unberührt
install -m 755 "$S/installation/container-security-scan-lauf" /usr/local/sbin/container-security-scan-lauf

# Ausnahmeliste, falls sie fehlt: nur auskommentierte Beispiele
[ -e /etc/container-security-scan/ausnahmen.txt ] \
    || install -D -m 644 "$S/installation/ausnahmen.txt" /etc/container-security-scan/ausnahmen.txt

echo "container-security-scan $VERSION (Commit $HEAD) installiert."
echo "Testlauf: sudo /usr/local/sbin/container-security-scan-lauf"
