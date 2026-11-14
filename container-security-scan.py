#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
container-security-scan.py – Schwachstellen-Scan LAUFENDER Docker-Container und der Dienste direkt auf dem
Host (z.B. nginx, Apache unter SLES), priorisiert danach, was tatsächlich läuft und von außen erreichbar ist.

Voraussetzungen auf dem Host: Python >= 3.6 (nur Standardbibliothek); für Container docker; optional rpm,
iproute2 (ip) und firewalld für den Scan des Hosts.
Rein lesend: Im Container werden nur Abfragen ausgeführt (find/tar, /proc lesen, "<programm> -v" u.ä.).
Kein Datenabfluss: Abgleich mit einer LOKALEN Kopie der OSV-Daten (https://osv.dev).

Aufruf:
  ./container-security-scan.py --db-aktualisieren
     im Git-Checkout: Daten aus dem Branch "daten" nach daten/ holen bzw. per "git pull" aktualisieren
     (täglich per GitHub Action gepflegt). Nie den Code: den nur nach Prüfung von Hand aktualisieren.
     Nicht als root – siehe README "Installation und Betrieb";
     mit --oekosysteme X,Y: zusätzlich diese Ökosysteme direkt von OSV nach osv-db laden (z.B. SUSE)
  ./container-security-scan.py <container> [ausgabeverzeichnis] [--nur-behebbare] [--alle] [--ausnahmen DATEI]
  ./container-security-scan.py --alle-container [ausgabeverzeichnis] [...]
     alle laufenden Container: zuerst die erreichbaren und ihre Ziele, dann alle übrigen. Erreichbar
     ("öffentlich" = von außerhalb des Docker-Hosts, Intranet oder Internet): veröffentlichte Ports,
     Host-Netzwerk, LAN-Netz; Ziele eines erreichbaren Reverse Proxys (im Container oder direkt auf dem Host)
     oder Tunnels; Ziele, die eine erreichbare Anwendung aufruft (Ziel-URL in Umgebung/Kommandozeile, offene
     Verbindung; nicht Datenbanken, Caches, Message Broker). Im Zweifel erreichbar: hinter einem Proxy, dessen
     Ziele nicht vollständig bekannt sind (Traefik, HAProxy, nginx mit $host …), gelten alle Container im
     selben Docker-Netz als möglicherweise öffentlich (P1).
  ./container-security-scan.py --oeffentliche [ausgabeverzeichnis] [...]
     wie --alle-container, aber nur die erreichbaren Container und deren Backends
  ./container-security-scan.py --host [--alle-container] [ausgabeverzeichnis] [...]
     den Host selbst: Prozesse außerhalb von Containern, OS-Pakete (rpm/dpkg) samt Kernel, Anwendungen in
     Docroots und /srv, /opt, /var/www, /usr/local; erreichbar = an einer Schnittstelle außer Loopback und
     Container-Netzen und von firewalld durchgelassen (Runtime). Webadressen aus nginx/Apache (auch über mehrere
     Proxys auf dem Host), Einstellungen der Webserver (WEB-…: Statusseiten, Verzeichnislisten, TLS 1.0/1.1).
     Mit --alle-container danach die Container; ohne Docker nur der Host (so im Wrapper)
  Daten: daten/ (Branch daten) und osv-db/ neben diesem Skript (oder --db DIR, auch mehrfach)

Ergebnis: scan_<name>_<zeit>.md        Bericht: Ergebnis, Dienste, Webadressen, Befunde nach Priorität, Anhang
          host_<rechner>_<zeit>.*      dasselbe für den Host (--host)
          scan_<name>_<zeit>.cdx.json  SBOM (CycloneDX 1.5) als Beleg; auch mit Trivy/Grype/Dependency-Track nutzbar
          scan_<name>_<zeit>.sha256    Prüfsummen
Rückgabewert: 0 = keine relevanten Schwachstellen, 1 = relevante Schwachstellen gefunden (siehe RELEVANT;
                  dazu immer aktiv ausgenutzte laut CISA-KEV-Katalog) oder gefährliche Einstellungen des
                  Containers (CONF-…: privileged, Docker-Socket, pid=host …) bzw. erreichbare Einstellungen
                  der Webserver (WEB-…),
              2 = Fehler oder Prüfung unvollständig (z.B. Datenbank fehlt) – nie als "sauber" werten!

Priorität (P1 = zuerst beheben):
  P1  Komponente wird von einem erreichbaren Dienst genutzt (Port veröffentlicht, Host-Netzwerk, LAN-Netz
      oder hinter einem erreichbaren Reverse Proxy, auch "möglicherweise")
  P2  Komponente wird von einem Dienst mit internem Port genutzt (z.B. hinter einem Reverse Proxy)
  P3  Komponente wird nur von einem Prozess ohne offenen Port genutzt
  P4  Komponente ist installiert, aber nicht in Benutzung erkannt; oder Entwicklungsabhängigkeit (dev)

Erfasst: OS-Pakete (dpkg, apk, rpm) inkl. Quellpaket, npm (jede package.json), Composer, PyPI (auch venvs),
Java (JAR/WAR/EAR, auch verschachtelt), Go-Programme, eingebettete JavaScript-Bibliotheken (jQuery u.a.),
Laufzeiten am Programm (node, php, python, java, nginx, apache, mariadb, postgresql; geprüft über den
Bitnami-Datensatz von OSV, falls nicht aus einem OS-Paket), Host-Kernel/Container-Laufzeit, Dienste.
Nicht erfasst: Rust, Ruby, .NET, Tcl, Programme ohne Versionskennung.
"Genutzt von" je Komponente: OS-Paket/Laufzeit = Programm oder geladene Bibliothek (/proc/<pid>/maps);
npm/composer/pypi = Projektverzeichnis passt zu Arbeitsverzeichnis/Skript bzw. Docroot (welche Pakete eine
Anwendung wirklich importiert, ist von außen nicht sichtbar).
"""
import argparse
import concurrent.futures
import datetime
import glob
import hashlib
import io
import ipaddress
import json
import math
import os
import posixpath
import re
import subprocess
import sys
import tarfile
import shutil
import tempfile
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib
from collections import Counter, OrderedDict, defaultdict
from functools import cmp_to_key

# Version: einzige Stelle; ein Release ist der Git-Tag v<VERSION> (README: Releases)
VERSION = "0.4.0"

# Relevant (-> Rückgabewert 1): (Priorität, Schweregrad); zusätzlich immer aktiv ausgenutzte Lücken (CISA KEV)
RELEVANT = {(1, "CRITICAL"), (1, "HIGH"), (2, "CRITICAL")}
# Gefährliche Einstellungen des Containers (-> Rückgabewert 1, Kennung CONF-… für die Ausnahmeliste): Mit ihnen
# wird aus einer Lücke im Container root auf dem Host. Nur, was ein Dienst praktisch nie braucht (keine allgemeine
# Härtung wie no-new-privileges, cap_drop, Limits).
KONF_CAPS = ("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF")
# Socket der Container-Laufzeit (auch schreibgeschützt eingebunden nutzbar) bzw. Verzeichnisse, die ihn enthalten
# (auch die Host-Wurzel)
KONF_SOCKET = re.compile(r"/|/(var/)?run(/(docker|containerd|podman))?|.*/(docker|containerd|podman)\.sock")
# Host-Pfade, die beschreibbar eingebunden den Host übernehmen lassen. Einzelne Volumes unter
# /var/lib/docker/volumes/<name> bleiben unberücksichtigt, das Verzeichnis aller Volumes nicht.
KONF_HOST_PFAD = re.compile(r"/(etc|home|dev)|/(root|boot|bin|sbin|lib\w*|proc|sys)(/.*)?"
                            r"|/usr(/(local(/(s?bin|lib\w*)(/.*)?)?|(s?bin|lib\w*)(/.*)?))?"
                            r"|/etc/(passwd|shadow|group|sudoers(\.d)?|cron[\w.]*|systemd|ssh|docker)(/.*)?"
                            r"|/home/[^/]+/\.ssh(/.*)?"
                            r"|/var/lib/docker(?!/volumes/)(/.*)?")
INKREMENT_MAX = 2000           # mehr geänderte Einträge -> Gesamtexport laden (schneller)
DB_MAX_ALTER_TAGE = 3          # ältere Datenbank -> Prüfung unvollständig (Rückgabewert 2)
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"
OSV_URL = OSV_BASE + "%s/all.zip"
# Direkt von OSV (ohne Branch daten), Gesamtexporte rund 1,2 GB, davon Ubuntu ca. 800 MB. Bei Bedarf ergänzen: SUSE, openSUSE.
OSV_ECOSYSTEMS = ["Debian", "Ubuntu", "Alpine", "SUSE", "npm", "PyPI", "Packagist", "Maven", "Go", "Bitnami"]
# Laufzeiten und Server, die nicht aus einem OS-Paket stammen (offizielle Images bauen sie aus dem Quellcode),
# werden über den Bitnami-Datensatz von OSV geprüft (z.B. PHP2Shell, Node2Shell).
BITNAMI = {"php": "php", "php-fpm": "php", "node": "node", "python": "python", "java": "jre", "nginx": "nginx",
           "apache-httpd": "apache", "mariadb": "mariadb", "postgresql": "postgresql"}
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
EOL_URL = "https://endoflife.date/api/v1/products/full/"
EOL_TYPEN = {"npm": "npm", "js-lib": "npm", "composer": "composer", "pypi": "pypi", "maven": "maven"}
# Laufzeiten/Server (Typ runtime/server) -> Produkt bei endoflife.date; nur geprüft, wenn nicht aus einem
# OS-Paket (dort zählt der Support der Distribution, die Sicherheitskorrekturen zurückportiert)
EOL_LAUFZEITEN = {"php": "php", "php-fpm": "php", "node": "nodejs", "python": "python", "nginx": "nginx",
                  "apache-httpd": "apache-http-server", "mariadb": "mariadb", "mysql": "mysql", "postgresql": "postgresql"}
# Paketkennungen, die bei endoflife.date fehlen
EOL_ZUSATZ = {"symfony": ["pkg:composer/symfony/symfony", "pkg:composer/symfony/http-kernel"],
              "cakephp": ["pkg:composer/cakephp/cakephp"], "twig": ["pkg:composer/twig/twig"],
              "shopware": ["pkg:composer/shopware/core"], "craft-cms": ["pkg:composer/craftcms/cms"],
              "contao": ["pkg:composer/contao/core-bundle"], "electron": ["pkg:npm/electron"],
              "tomcat": ["pkg:maven/org.apache.tomcat/tomcat-catalina", "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core"]}
EOL_VORWARNUNG_TAGE = 90       # Supportende innerhalb dieser Frist: Hinweis vorab
EOL_MAX_ALTER_TAGE = 30
# Katalog aktiv ausgenutzter Schwachstellen (CISA Known Exploited Vulnerabilities, CC0)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_ALTER_TAGE = 7
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
# Schweregrad für Einträge ohne eigene Bewertung (z.B. Go): dieselbe CVE in diesen Quellen nachschlagen
# (Bitnami: Bewertung der Quelle, Alpine: CVSS aus der NVD). Distributions-Dringlichkeit zählt hier nicht.
SCHWEREGRAD_QUELLEN = ("Bitnami", "Alpine")
# Kernel-Pakete im Container (Header, Images): Container nutzen den Kernel des Hosts, deren CVEs betreffen
# den Container nicht. Debian/Ubuntu führen alle Kernel-CVEs am Quellpaket "linux".
KERNEL_QUELLE = re.compile(r"linux(-signed.*|-lts|-virt|-headers|-hwe.*|-(aws|azure|gcp|oracle|kvm|lowlatency).*)?$")
KERNEL_PAKET = re.compile(r"(linux-(libc-dev|headers|image|modules|kbuild|source)|kernel-(default|devel|source|syms|"
                          r"headers|preempt|rt|azure|64kb|macros|core|modules))(\b|-|$)|kernel$")
# Titel, nach denen eine Schwachstelle nur unter Windows auftritt (Container laufen unter Linux). Groß
# geschriebenes "Windows", damit z.B. "HTTP/2 initial windows size" nicht erfasst wird.
NUR_WINDOWS = re.compile(r"\b(?:[Oo]n|[Uu]nder|[Ff]or|[Ii]n|[Aa]ffecting) (?:Microsoft )?Windows\b|\b[Oo]n windows\b"
                         r"|\bWindows[- ](?:[Oo]nly|specific|platforms?|systems?|hosts?|servers?|installations?|"
                         r"installers?|builds?|users?|absolute paths?|paths?|shares?)\b|\(Windows[,)]"
                         r"|\bUNC paths?\b|\bNTLM\b")
NICHT_NUR_WINDOWS = re.compile(r"\b(?:Linux|Unix|UNIX|POSIX|macOS|Mac OS|all platforms|other platforms|non-Windows)\b"
                               r"|\bWindows (?:and|or)\b|\b(?:and|or) Windows\b")


class ScanError(Exception):
    """Fehler, nach dem kein verlässliches Ergebnis vorliegt (Rückgabewert 2)."""


DOCKER_ENV = ["-e", "JAVA_TOOL_OPTIONS=", "-e", "JDK_JAVA_OPTIONS=", "-e", "_JAVA_OPTIONS=",
              "-e", "NO_UPDATE_NOTIFIER=1", "-e", "NPM_CONFIG_UPDATE_NOTIFIER=false",
              "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "NODE_OPTIONS=", "-e", "PYTHONPATH="]
# Suchpfad für Befehle im Container (sh, find, tar, awk, rpm …). Nicht der PATH des Images: Enthält er ein
# Verzeichnis, in das die Anwendung schreiben darf (z.B. /opt/venv/bin), könnte sie dort ein "sh" ablegen,
# das der Scan dann als root ausführt. Nur für die Versionsabfrage von Namen ohne Pfad (als nobody) gilt
# der PATH des Images.
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
NOBODY = "65534:65534"
# OSV-Kennungen (GHSA-…, DEBIAN-CVE-…, SUSE-SU-2024:1234-1 …) werden zu Dateinamen: kein "/" und kein ".." möglich
OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]*")


def log(msg):
    # sofort ausgeben: Python < 3.9 puffert stderr in einer Pipe (Wrapper: 2>&1 | tee) bis zum Ende
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def run(cmd, input=None, binary=False, stderr=False, timeout=None):
    """Befehl ausführen und (Rückgabewert, Ausgabe) liefern; nie eine Ausnahme (auch nicht bei Zeitüberschreitung)."""
    if binary and isinstance(input, str):
        input = input.encode()
    try:
        p = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, timeout=timeout,
                           stderr=subprocess.STDOUT if stderr else subprocess.DEVNULL,
                           **({} if binary else {"encoding": "utf-8", "errors": "replace"}))
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, b"" if binary else ""


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def eol_daten_erzeugen(path):
    """EOL-Daten mit Paketkennungen aus dem vollständigen endoflife.date-API-Export erzeugen."""
    with urllib.request.urlopen(EOL_URL, timeout=120) as response:
        data = json.load(response)
    if not isinstance(data.get("result"), list) or not data["result"] or data.get("total") != len(data["result"]):
        raise ScanError("Ungültige oder unvollständige endoflife.date-Antwort")
    products = []
    for product in data["result"]:
        identifiers = [x["id"] for x in product["identifiers"] if x.get("type") == "purl"
                       and x.get("id", "").startswith(("pkg:npm/", "pkg:composer/", "pkg:pypi/", "pkg:maven/"))]
        identifiers += EOL_ZUSATZ.get(product["name"], [])
        if not identifiers and product["name"] not in EOL_LAUFZEITEN.values():
            continue
        cycles = []
        for release in product["releases"]:
            name, date, ended = release["name"], release["eolFrom"], release["isEol"]
            if date is None and ended is None:
                continue
            if not isinstance(ended, bool) or (date is not None and
                    (not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date))):
                raise ScanError("Ungültige EOL-Daten für " + product["name"])
            if date:
                try:
                    datetime.datetime.strptime(date, "%Y-%m-%d")
                except ValueError:
                    raise ScanError("Ungültiges EOL-Datum für " + product["name"])
            if re.fullmatch(r"\d+(?:\.\d+)*", name):
                cycles.append({"cycle": name, "eol": date if date else ended})
        if cycles:
            products.append({"name": product["name"], "purls": sorted(set(identifiers)), "cycles": cycles})
    if not products:
        raise ScanError("Keine geeigneten endoflife.date-Produkte gefunden")
    payload = {"geprueft": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "products": products}
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(path + ".tmp", path)


def eol_laden(paths):
    """EOL-Daten lesen und prüfen; bei mehreren Dateien (Repository, osv-db/) die jüngste."""
    best, err = None, "keine Datei"
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            checked = datetime.datetime.strptime(data["geprueft"], "%Y-%m-%dT%H:%M:%SZ")
            products = data["products"]
            if not isinstance(products, list) or not products:
                raise ValueError("keine Produkte")
            for product in products:
                if not isinstance(product["name"], str) or not isinstance(product["purls"], list) \
                        or not isinstance(product["cycles"], list):
                    raise ValueError("ungültiges Produkt")
                for cycle in product["cycles"]:
                    if not isinstance(cycle["cycle"], str) or not isinstance(cycle["eol"], (str, bool)):
                        raise ValueError("ungültiger Versionszweig")
                    if isinstance(cycle["eol"], str):
                        datetime.datetime.strptime(cycle["eol"], "%Y-%m-%d")
        except (OSError, ValueError, KeyError, TypeError) as e:
            if not isinstance(e, FileNotFoundError) or err == "keine Datei":
                err = str(e)
            continue
        if best is None or checked > best[0]:
            best = (checked, products)
    if best is None:
        raise ValueError(err)
    return best


def eol_warnungen(comps, paths):
    """Warnungen für Versionszweige ohne regulären Support (oder kurz davor): Pakete über ihre Kennung,
    Laufzeiten/Server außerhalb von OS-Paketen über den Produktnamen. Ändert den Rückgabewert nicht."""
    if isinstance(paths, str):
        paths = [paths]
    try:
        checked, products = eol_laden(paths)
    except ValueError as e:
        return ["EOL-Daten fehlen oder sind ungültig (%s); Supportende nicht geprüft" % e]
    by_purl, by_name = defaultdict(list), {}
    for product in products:
        by_name[product["name"]] = product
        for purl in product["purls"]:
            by_purl[urllib.parse.unquote(purl).lower()].append(product)
    warnings = []
    if (utcnow() - checked).days >= EOL_MAX_ALTER_TAGE:
        warnings.append("EOL-Daten veraltet (Stand %s); git pull bzw. --db-aktualisieren ausführen"
                        % checked.strftime("%Y-%m-%d"))
    today = utcnow().date()
    hits = OrderedDict()
    for c in comps:
        typ = EOL_TYPEN.get(c["typ"])
        if typ:
            name = c["name"].replace(":", "/", 1) if typ == "maven" else c["name"]
            if typ == "pypi":
                name = pypi_name(name)
            candidates = by_purl.get(("pkg:%s/%s" % (typ, name)).lower(), [])
        elif c["typ"] in ("runtime", "server") and c["name"] in EOL_LAUFZEITEN and (
                not from_os_package(c) or any(h.startswith(FREMDQUELLE) for h in c["hinweise"])):
            candidates = [by_name[EOL_LAUFZEITEN[c["name"]]]] if EOL_LAUFZEITEN[c["name"]] in by_name else []
        else:
            continue
        version = c["version"].lstrip("v")
        for product in candidates:
            cycles = [r for r in product["cycles"] if re.fullmatch(r"\d+(?:\.\d+)*", r["cycle"])
                      and (version == r["cycle"] or version.startswith(r["cycle"] + "."))]
            if not cycles:
                continue
            cycle = max(cycles, key=lambda r: len(r["cycle"]))
            end = cycle["eol"]
            if end is False:
                continue
            if end is True:
                days = -1
            else:
                days = (datetime.datetime.strptime(end, "%Y-%m-%d").date() - today).days
            if days > EOL_VORWARNUNG_TAGE:
                continue
            key = (c["name"], c["version"], product["name"], cycle["cycle"], end if end is not True else "", days < 0)
            # am Tag des Supportendes gilt der Zweig noch als unterstützt (days == 0 -> "bald")
            hits.setdefault(key, []).append(c["ort"] or "?")
    for (name, version, product, cycle, end, ended), places in hits.items():
        places = list(OrderedDict.fromkeys(places))
        where = ", ".join(places[:3]) + (" und %d weitere" % (len(places) - 3) if len(places) > 3 else "")
        if ended:
            warnings.append("Supportende: %s %s (%s %s, %s; %s)" % (
                name, version, product, cycle, "seit " + end if end else "Datum unbekannt", where))
        else:
            warnings.append("Supportende bald: %s %s (%s %s, am %s; %s)" % (name, version, product, cycle, end, where))
    return warnings


def kev_daten_erzeugen(path):
    """Katalog aktiv ausgenutzter Schwachstellen (CISA KEV) laden und gekürzt speichern: CVE -> Aufnahmedatum."""
    with urllib.request.urlopen(KEV_URL, timeout=120) as response:
        data = json.load(response)
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns or data.get("count") != len(vulns):
        raise ScanError("Ungültige oder unvollständige Antwort des KEV-Katalogs")
    cves = {}
    for v in vulns:
        cve, added = v.get("cveID"), v.get("dateAdded")
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve) or not isinstance(added, str) \
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", added):
            raise ScanError("Ungültiger Eintrag im KEV-Katalog: %r" % (cve,))
        cves[cve] = added
    payload = {"geprueft": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "katalog": str(data.get("catalogVersion", "")),
               "cves": cves}
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(path + ".tmp", path)


def kev_laden(paths):
    """KEV-Daten lesen und prüfen; bei mehreren Dateien die jüngste. Liefert (Prüfzeitpunkt, {CVE: Datum})."""
    best, err = None, "keine Datei"
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            checked = datetime.datetime.strptime(data["geprueft"], "%Y-%m-%dT%H:%M:%SZ")
            cves = data["cves"]
            if not isinstance(cves, dict) or not cves or not all(
                    isinstance(k, str) and CVE_ID.fullmatch(k) and isinstance(v, str) for k, v in cves.items()):
                raise ValueError("ungültige Einträge")
        except (OSError, ValueError, KeyError, TypeError) as e:
            if not isinstance(e, FileNotFoundError) or err == "keine Datei":
                err = str(e)
            continue
        if best is None or checked > best[0]:
            best = (checked, cves)
    if best is None:
        raise ValueError(err)
    return best


def kev_markieren(findings, paths):
    """Funde aus dem KEV-Katalog markieren (f["kev"] = Aufnahmedatum). Liefert Warnungen."""
    try:
        checked, cves = kev_laden(paths)
    except ValueError as e:
        return ["KEV-Daten fehlen oder sind ungültig (%s); aktiv ausgenutzte Lücken nicht gesondert gewertet" % e]
    for f in findings:
        if f["id"] in cves:
            f["kev"] = cves[f["id"]]
    if (utcnow() - checked).days >= KEV_MAX_ALTER_TAGE:
        return ["KEV-Daten veraltet (Stand %s); git pull bzw. --db-aktualisieren ausführen" % checked.strftime("%Y-%m-%d")]
    return []


def ausnahmen_laden(path):
    """Ausnahmeliste lesen. Je Zeile: <Kennung> <Paket oder *> <gültig bis JJJJ-MM-TT> <Begründung>.
    Fehler -> ScanError (Rückgabewert 2): eine fehlerhafte Liste soll nichts stillschweigend ausblenden."""
    try:
        st = os.stat(path)
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise ScanError("Ausnahmeliste %s nicht lesbar: %s" % (path, e))
    # wie sudoers: wer die Liste ändern kann, kann Funde ausblenden
    if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
        raise ScanError("Ausnahmeliste %s darf nur ihr Eigentümer (root bzw. der aufrufende Benutzer) ändern können"
                        % path)
    result = []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4 or not OSV_ID.fullmatch(parts[0]) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", parts[2]):
            raise ScanError("Ausnahmeliste %s, Zeile %d: erwartet \"<Kennung> <Paket oder *> <JJJJ-MM-TT> "
                            "<Begründung>\"" % (path, n))
        try:
            bis = datetime.datetime.strptime(parts[2], "%Y-%m-%d").date()
        except ValueError:
            raise ScanError("Ausnahmeliste %s, Zeile %d: ungültiges Datum %s" % (path, n, parts[2]))
        result.append({"id": parts[0], "paket": parts[1], "bis": bis, "grund": parts[3], "zeile": n})
    return result


def nur_windows(title):
    """Betrifft die Schwachstelle laut Titel nur Windows?"""
    return bool(NUR_WINDOWS.search(title or "")) and not NICHT_NUR_WINDOWS.search(title or "")


def norm(path):
    """Pfad vergleichbar machen: '(deleted)' entfernen, /usr/lib == /lib usw. (usrmerge)."""
    path = re.sub(r" \(deleted\)$", "", path)
    return path[4:] if re.match(r"/usr/(lib|lib64|bin|sbin)/", path) else path


def under(path, root):
    return bool(root) and (path == root or path.startswith(root.rstrip("/") + "/"))


def comp(typ, name, version, ort="", **extra):
    """Eine Komponente des Inventars."""
    c = {"typ": typ, "name": name, "version": version, "ort": ort, "hinweise": [],
         "aktiv": [], "aktiv_ohne_port": []}
    c.update(extra)
    return c


# ===========================================================================
# Zugriff auf den Container
# ===========================================================================
class Container(object):
    def __init__(self, ref, user):
        rc, out = run(["docker", "inspect", "--type", "container", ref])
        if rc != 0:
            raise ScanError("Container '%s' nicht gefunden (oder docker nicht erreichbar)" % ref)
        self.info = json.loads(out)[0]
        if not self.info["State"]["Running"]:
            raise ScanError("Container '%s' läuft nicht" % ref)
        self.id = self.info["Id"]
        self.name = self.info["Name"].lstrip("/")
        self.user = user
        self.has_sh = self.exec(["sh", "-c", "exit 0"])[0] == 0
        tools = self.exec(["sh", "-c", "for t in find tar awk sed tr sort readlink timeout; do "
                                       "command -v $t >/dev/null && echo $t; done"])[1].split() if self.has_sh else []
        self.has_find_tar = "find" in tools and "tar" in tools
        self.has_proc_tools = all(t in tools for t in ("awk", "sed", "tr", "sort", "readlink"))
        self.has_timeout = "timeout" in tools
        # Volumes und Bind-Mounts mit Anwendungsdaten (nicht: Host-Wurzel, Docker-Daten, /proc, Sockets ...)
        self.mounts = sorted({m["Destination"] for m in self.info.get("Mounts") or []
                              if m.get("Destination", "").startswith("/")
                              and not re.match(r"/(proc|sys|dev)(/|$)", m["Destination"])
                              and (m.get("Type") == "volume" or not re.match(
                                  r"/$|/(proc|sys|dev|run|var/run|var/lib/docker|var/lib/containerd)(/|$)", m.get("Source", "/")))})

    def exec(self, cmd, input=None, binary=False, stderr=False, user=None, timeout=900, path=SAFE_PATH):
        """Programm im Container direkt (ohne Shell) ausführen, Befehle über SAFE_PATH gesucht. Versionsabfragen
        bekommen ein kurzes Zeitlimit, damit ein hängendes Programm den (täglichen) Lauf nicht blockiert."""
        user = user or self.user
        args = ["docker", "exec", "-w", "/"] + (["-i"] if input is not None else []) + (["-u", user] if user else [])
        return run(args + DOCKER_ENV + (["-e", "PATH=" + path] if path else []) + [self.id] + cmd,
                   input, binary, stderr, timeout)

    def probe(self, cmd, user, stderr=False, path=SAFE_PATH):
        """Versionsabfrage: mit den Rechten des laufenden Prozesses (nie mehr), Zeitlimit auch im Container."""
        if self.has_timeout:
            cmd = ["timeout", "50"] + cmd
        return self.exec(cmd, stderr=stderr, user=user, timeout=60, path=path)

    def sh(self, script, binary=False, user=None, args=()):
        """POSIX-sh-Skript im Container ausführen."""
        return self.exec(["sh", "-s", "--"] + list(args), input=script, binary=binary, user=user)

    def read_file(self, path):
        """Datei passiv per docker cp lesen (funktioniert auch ohne Shell)."""
        rc, data = run(["docker", "cp", "-L", "%s:%s" % (self.id, path), "-"], binary=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for m in tf:
                    if m.isfile():
                        return tf.extractfile(m).read().decode("utf-8", "replace")
        except (tarfile.TarError, EOFError):
            pass
        return ""


# ===========================================================================
# 1. Dateien holen: Paketdatenbanken und Paket-Metadaten (ein Durchgang)
# ===========================================================================
WANTED = re.compile(r"""^/(etc/os-release|usr/lib/os-release|etc/alpine-release|etc/debian_version
                       |var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+|var/lib/dpkg/info/[^/]+\.list
                       |lib/apk/db/installed)$
                      |/(package\.json|\.?package-lock\.json)$
                      |\.dist-info/METADATA$|\.egg-info/PKG-INFO$|\.egg-info$
                      |/vendor/composer/installed\.json$|/pyvenv\.cfg$""", re.X)

# Eingebettete JavaScript-Bibliotheken (wie Retire.js): npm-Name, Dateiname (regulärer Ausdruck),
# Version im Dateikopf. Abgleich über die npm-Daten von OSV.
JS_LIBS = [
    ("jquery", r"jquery([-.]\d[\d.]*)?(\.slim)?(\.min)?\.js", r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)"),
    ("jquery-ui", r"jquery-ui([-.]\d[\d.]*)?(\.custom)?(\.min)?\.js", r"jQuery UI - v(\d+\.\d+\.\d+)"),
    ("jquery-migrate", r"jquery-migrate([-.]\d[\d.]*)?(\.min)?\.js", r"jQuery Migrate - v(\d+\.\d+\.\d+)"),
    ("chart.js", r"chart(\.bundle)?([-.]\d[\d.]*)?(\.umd)?(\.min)?\.js", r"Chart\.js(?:[\s\S]{0,80}?Version:)?\s*v?(\d+\.\d+\.\d+)"),
    ("bootstrap", r"bootstrap(\.bundle)?([-.]\d[\d.]*)?(\.min)?\.js", r"Bootstrap v(\d+\.\d+\.\d+)"),
    ("moment", r"moment(-with-locales)?([-.]\d[\d.]*)?(\.min)?\.js", r"(?:version : |moment\.js v?)(\d+\.\d+\.\d+)"),
    ("video.js", r"video([-.]\d[\d.]*)?(\.min)?\.js", r"Video\.js (\d+\.\d+\.\d+)"),
    ("js-cookie", r"js\.cookie([-.]\d[\d.]*)?(\.min)?\.js", r"JavaScript Cookie v(\d+\.\d+\.\d+)"),
    ("jspdf", r"jspdf([-.]\d[\d.]*)?(\.umd|\.debug)?(\.min)?\.js", r"jsPDF[\s\S]{0,300}?Version (\d+\.\d+\.\d+)"),
    ("lodash", r"lodash([-.]\d[\d.]*)?(\.core)?(\.min)?\.js", r"(?:VERSION\s*=\s*'|[Ll]odash v?)(\d+\.\d+\.\d+)"),
    ("handlebars", r"handlebars([-.]\d[\d.]*)?(\.runtime)?(\.min)?\.js", r"handlebars v(\d+\.\d+\.\d+)"),
    ("angular", r"angular([-.]\d[\d.]*)?(\.min)?\.js", r"AngularJS v(\d+\.\d+\.\d+)"),
    ("vue", r"vue([-.]\d[\d.]*)?(\.global|\.runtime)?(\.prod)?(\.min)?\.js", r"Vue\.js v(\d+\.\d+\.\d+)"),
    ("d3", r"d3([-.]\d[\d.]*)?(\.min)?\.js", r"d3js\.org v(\d+\.\d+\.\d+)"),
    ("highlight.js", r"highlight([-.]\d[\d.]*)?(\.pack)?(\.min)?\.js", r"Highlight\.js v?(\d+\.\d+\.\d+)"),
    ("dompurify", r"purify([-.]\d[\d.]*)?(\.min)?\.js", r"DOMPurify (\d+\.\d+\.\d+)"),
    ("select2", r"select2([-.]\d[\d.]*)?(\.full)?(\.min)?\.js", r"Select2 (\d+\.\d+\.\d+)"),
    ("underscore", r"underscore([-.]\d[\d.]*)?(-min|\.min)?\.js", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("axios", r"axios([-.]\d[\d.]*)?(\.min)?\.js", r"[Aa]xios v(\d+\.\d+\.\d+)"),
    ("pikaday", r"pikaday([-.]\d[\d.]*)?(\.min)?\.js", r"Pikaday v?(\d+\.\d+\.\d+)"),
]
JS_GLOBS = sorted({rx.split("(")[0].replace("\\", "") + "*.js" for _, rx, _ in JS_LIBS})   # für find -iname
GO_MAGIC = b"\xff Go buildinf:"

# Fehler von find (z.B. unlesbare Verzeichnisse) dürfen nicht unbemerkt Dateien auslassen. POSIX-sh kennt kein
# pipefail, daher sammelt die Schleife die Meldungen von find und tar über Deskriptor 3. Ausgenommen sind Dateien,
# die während der Suche verschwinden oder sich ändern (temporäre Dateien laufender Programme): dabei geht nichts
# verloren. Alle übrigen Meldungen und Fehler ohne Meldung ergeben Exit-Code 3 (Meldungen auf stderr). Die
# Auswertung nutzt nur die Shell selbst (grep, sed fehlen in manchen Containern).
# grep/xargs liefern auch ohne Treffer einen Fehlercode und werden nicht gewertet (wie bisher).
FIND_SH = r"""
LC_ALL=C; export LC_ALL
exec 4>&1
meldungen=$( { for r in / "$@"; do
  find "$r" -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f \( \
       -path /etc/os-release -o -path /usr/lib/os-release -o -path /etc/alpine-release -o -path /etc/debian_version \
    -o -path /var/lib/dpkg/status -o -path '/var/lib/dpkg/status.d/*' -o -path '/var/lib/dpkg/info/*.list' \
    -o -path /lib/apk/db/installed -o -name package.json -o -name .package-lock.json -o -name package-lock.json \
    -o -path '*.dist-info/METADATA' -o -path '*.egg-info/PKG-INFO' -o -name '*.egg-info' \
    -o -path '*/vendor/composer/installed.json' -o -name '*.jar' -o -name '*.war' -o -name '*.ear' \
    -o -name pyvenv.cfg JSGLOBS \) -print 2>&3 || echo "@find $r" >&3
  { find "$r" -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -100 -size +1000k -print \
      2>&3 || echo "@find $r" >&3; } | xargs grep -l 'Go buildinf:' 2>/dev/null
done | sort -u | tar -cf - -T - 2>&3 || echo "@tar" >&3; } 3>&1 1>&4 )
exec 4>&-
[ -n "$meldungen" ] || exit 0
printf '%s\n' "$meldungen" | {
  rest=; find_fehler=; tar_fehler=; find_meldung=; tar_meldung=
  while IFS= read -r z; do
    case "$z" in find:*) find_meldung=1 ;; tar:*) tar_meldung=1 ;; esac
    case "$z" in
      @find*) find_fehler="$find_fehler${z#@}: Fehler ohne Meldung
" ;;
      @tar) tar_fehler="tar: Fehler ohne Meldung
" ;;
      *"emoving leading"*|*"Exiting with failure status"*) ;;
      *"No such file or directory"*|*"changed as we read it"*|*"shrank by"*) ;;
      *) rest="$rest$z
" ;;
    esac
  done
  [ -n "$find_meldung" ] || rest="$rest$find_fehler"     # Fehlercode ganz ohne Meldung
  [ -n "$tar_meldung" ] || rest="$rest$tar_fehler"
  [ -z "$rest" ] || { printf '%s' "$rest" >&2; exit 3; }
}
""".replace("JSGLOBS", " ".join("-o -iname '%s'" % g for g in JS_GLOBS))


def js_library(path, data):
    """Eingebettete JavaScript-Bibliothek erkennen (Name aus Dateiname, Version aus Dateikopf oder -name)."""
    if "/node_modules/" in path:     # npm-Pakete werden über ihre package.json erfasst
        return None
    base = posixpath.basename(path).lower()
    for name, file_rx, head_rx in JS_LIBS:
        if re.fullmatch(file_rx, base):
            m = re.search(head_rx, data[:16384].decode("utf-8", "replace"))
            if m:
                return comp("js-lib", name, m.group(1), path, datei=path)
            m = re.search(r"\d+\.\d+(\.\d+)?", base)
            c = comp("js-lib", name, m.group(0) if m else "unbekannt", path, datei=path)
            c["hinweise"].append("Version aus Dateiname" if m else "Version nicht erkennbar")
            return c
    return None


MAVEN_GENERIC = {"core", "api", "common", "commons", "util", "utils", "client", "server", "model", "parent", "lib", "main"}


def java_archive(path, data, depth=0):
    """Maven-Komponenten eines JAR/WAR/EAR, auch verschachtelte Archive (WEB-INF/lib, BOOT-INF/lib)."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return []
    result = []
    if "org/apache/catalina/util/ServerInfo.properties" in names:     # Tomcat (catalina.jar ohne pom.properties)
        m = re.search(r"^server\.number=(\d+\.\d+\.\d+)", text(z.read("org/apache/catalina/util/ServerInfo.properties")), re.M)
        if m:
            result.append(comp("maven", "org.apache.tomcat:tomcat-catalina", m.group(1), path, datei=path.split("!/")[0]))
    for n in names:
        if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n):
            p = dict(re.findall(r"^\s*(groupId|artifactId|version)\s*=\s*(\S+)", text(z.read(n)), re.M))
            if len(p) == 3:
                result.append(comp("maven", "%s:%s" % (p["groupId"], p["artifactId"]), p["version"], path, datei=path.split("!/")[0]))
    if not result:   # keine pom.properties: Dateiname und Manifest (Maven-Gruppe dann unbekannt)
        mf = dict(re.findall(r"^([\w-]+):\s*(.+?)\s*$", text(z.read("META-INF/MANIFEST.MF")), re.M)) \
            if "META-INF/MANIFEST.MF" in names else {}
        base = posixpath.basename(path.split("!/")[-1])
        m = re.match(r"^(.+?)-(\d[\w.]*?)(?:-SNAPSHOT)?\.(?:jar|war|ear)$", base, re.I)
        artifact = m.group(1) if m else re.sub(r"\.(jar|war|ear)$", "", base, flags=re.I)
        version = (m.group(2) if m else "") or mf.get("Implementation-Version") or mf.get("Bundle-Version", "")
        if version and artifact:
            c = comp("maven", artifact, version, path, maven_key="*:" + artifact, datei=path.split("!/")[0])
            c["hinweise"].append("Maven-Gruppe unbekannt, Zuordnung über Dateiname/Manifest (unsicher)")
            if mf.get("Implementation-Vendor-Id"):
                c["hinweise"].append("Hersteller-ID " + mf["Implementation-Vendor-Id"])
            result.append(c)
    if depth < 2:
        for info in z.infolist():
            if info.filename.lower().endswith((".jar", ".war")) and info.file_size < 256 * 2 ** 20:
                result += java_archive(path + "!/" + info.filename, z.read(info), depth + 1)
    return result


def go_binary(path, data):
    """Go-Version und Module aus der Build-Info eines Go-Programms (ab Go 1.18) lesen."""
    i = data.find(GO_MAGIC)
    if i < 0 or len(data) < i + 32:
        return []
    if not data[i + 15] & 2:     # Format vor Go 1.18: Module nicht lesbar -> als ungeprüft ausweisen
        return [comp("go", "Go-Programm (vor Go 1.18)", "unbekannt", path, datei=path)]

    def varbytes(pos):
        n = shift = 0
        while True:
            b = data[pos]
            pos += 1
            n |= (b & 0x7f) << shift
            shift += 7
            if b < 0x80:
                return data[pos:pos + n], pos + n
    try:
        gover, pos = varbytes(i + 32)
        mod, pos = varbytes(pos)
    except IndexError:
        return []
    k = mod.find(b"path\t")
    mod = text(mod[k:mod.rfind(b"\n") + 1]) if k >= 0 else ""
    result = []
    m = re.match(r"go(\d+(?:\.\d+)*)", text(gover))
    if m:
        result.append(comp("go", "stdlib", m.group(1), path, datei=path))
    deps, last = OrderedDict(), None
    for line in mod.splitlines():
        f = line.split("\t")
        if f[0] in ("mod", "dep") and len(f) >= 3:
            deps[f[1]], last = f[2], f[1]
        elif f[0] == "=>" and len(f) >= 3 and last:     # replace-Direktive: Ersatzmodul gilt
            deps.pop(last, None)
            deps[f[1]] = f[2]
    for name, version in deps.items():
        if version and version != "(devel)":
            result.append(comp("go", name, version, path, datei=path))
    return result


def read_tar(stream, files, extra, prefix=""):
    """tar-Strom auswerten: Metadaten-Dateien merken, JARs/Go-Programme/JS-Bibliotheken direkt untersuchen.
    Es wird nichts auf die Platte entpackt."""
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as tf:
            for m in tf:
                name = m.name[2:] if m.name.startswith("./") else m.name
                path = prefix.rstrip("/") + "/" + name.lstrip("/")
                if m.islnk():     # Hardlink auf eine schon gelesene Metadaten-Datei
                    target = prefix.rstrip("/") + "/" + m.linkname.lstrip("./").lstrip("/")
                    if target in files and WANTED.search(path):
                        files[path] = files[target]
                    continue
                if not m.isfile() or m.size > 512 * 2 ** 20:
                    continue
                low = path.lower()
                if WANTED.search(path) and m.size < 64 * 2 ** 20:
                    files[path] = tf.extractfile(m).read()
                elif low.endswith((".jar", ".war", ".ear")):
                    extra += java_archive(path, tf.extractfile(m).read())
                elif low.endswith(".js"):
                    if any(re.fullmatch(rx, posixpath.basename(low)) for _, rx, _ in JS_LIBS):
                        lib = js_library(path, tf.extractfile(m).read())
                        if lib:
                            extra.append(lib)
                elif m.mode & 0o111 and m.size > 1000 * 1024:   # mögliches Go-Programm
                    extra += go_binary(path, tf.extractfile(m).read())
    except (tarfile.TarError, EOFError):
        pass


def stream_tar(cmd, files, extra, prefix="", input=None, timeout=1800, meldungen=None):
    """tar-Strom eines Befehls lesen (ohne alles im Speicher zu halten). Liefert False bei Fehler/Zeitüberschreitung.
    meldungen: Liste, an die die Fehlerausgabe des Befehls (zeilenweise) angehängt wird."""
    with tempfile.TemporaryFile() as err:     # Datei statt Pipe: kein Blockieren bei viel Fehlerausgabe
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE if input else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=err if meldungen is not None else subprocess.DEVNULL)
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        try:
            if input:
                p.stdin.write(input.encode())
                p.stdin.close()
            read_tar(p.stdout, files, extra, prefix)
            p.stdout.close()
            rc = p.wait()
        finally:
            timer.cancel()
        if meldungen is not None:
            err.seek(0)
            meldungen.extend(x.strip() for x in err.read().decode("utf-8", "replace").splitlines() if x.strip())
    return rc == 0


def collect_files(c):
    """Liefert (Dateien, weitere Komponenten, Beschreibung, Probleme)."""
    files, extra, problems = {}, [], []
    grund = ""
    if c.has_find_tar:
        meldungen = []
        ok = stream_tar(["docker", "exec", "-i", "-w", "/", "-u", c.user or "0", "-e", "PATH=" + SAFE_PATH,
                         c.id, "sh", "-s", "--"] + c.mounts,
                        files, extra, input=FIND_SH, meldungen=meldungen)
        meldungen = list(OrderedDict.fromkeys(meldungen))    # beide find-Läufe melden dasselbe
        if ok:
            return files, extra, "find/tar im Container (inkl. %d Volumes)" % len(c.mounts), problems
        if not (meldungen and all("Permission denied" in m for m in meldungen)):
            problems.append("Dateien im Container nicht vollständig lesbar (%s)" % (
                "; ".join(meldungen[:3]) + (" … und %d weitere" % (len(meldungen) - 3) if len(meldungen) > 3 else "")
                if meldungen else "Fehler oder Zeitüberschreitung"))
            return files, extra, "find/tar im Container (inkl. %d Volumes)" % len(c.mounts), problems
        # Nur fehlende Rechte: root im Container ohne CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH (cap_drop: ALL) darf
        # nicht in Verzeichnisse anderer Benutzer. Dann wie ohne Werkzeuge passiv von außen lesen (ohne Rechte
        # im Container); das Teilergebnis von find/tar wird verworfen.
        files, extra = {}, []
        grund = ", da find/tar im Container ohne Leserechte (%d Meldungen, z. B. %s)" % (len(meldungen), meldungen[0])
    if not stream_tar(["docker", "export", c.id], files, extra):
        problems.append("docker export fehlgeschlagen")
    # Volumes sind nicht im Export enthalten -> einzeln per docker cp lesen, äußere vor inneren. Der Export enthält
    # dafür Dateien des Images, die im laufenden Container unter dem Mount verdeckt sind: vorher entfernen
    for dest in sorted(c.mounts, key=lambda d: d.rstrip("/").count("/")):
        unter = dest.rstrip("/") + "/"
        for p in [p for p in files if p == dest or p.startswith(unter)]:
            del files[p]
        extra[:] = [x for x in extra if not (x.get("datei") == dest or (x.get("datei") or "").startswith(unter))]
        if not stream_tar(["docker", "cp", "-L", "%s:%s" % (c.id, dest), "-"], files, extra,
                          prefix=posixpath.dirname(dest.rstrip("/"))):
            problems.append("Volume %s nicht lesbar" % dest)
    return files, extra, "docker export und docker cp (%d Volumes)%s" % (len(c.mounts), grund), problems


def text(data):
    return data.decode("utf-8-sig", "replace")


def json_datei(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def datei_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def os_release(files):
    raw = files.get("/etc/os-release") or files.get("/usr/lib/os-release") or b""
    info = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', text(raw), re.M))
    osinfo = {"id": info.get("ID", "unbekannt"), "version": info.get("VERSION_ID", ""),
              "pretty": info.get("PRETTY_NAME", "unbekannt")}
    if "/etc/alpine-release" in files:
        osinfo["version"] = text(files["/etc/alpine-release"]).strip()
    if osinfo["id"] == "debian" and "/etc/debian_version" in files:
        osinfo["version"] = text(files["/etc/debian_version"]).strip()
    return osinfo


# ===========================================================================
# 2. OS-Pakete (passiv aus den Paketdatenbanken, wie Trivy) und Dateizuordnung
# ===========================================================================
def paragraphs(data):
    """Debian-Kontrollformat: Absätze mit 'Feld: Wert'."""
    for block in re.split(r"\n\s*\n", text(data)):
        fields = dict(re.findall(r"^([\w-]+):[ \t]*(.*)$", block, re.M))
        if fields:
            yield fields


def os_packages(c, files):
    """Liefert (Komponenten, Dateibesitzer {pfad: {paket}}, Quelle)."""
    pkgs, owners = [], defaultdict(set)
    status = [v for k, v in files.items() if k == "/var/lib/dpkg/status"
              or (k.startswith("/var/lib/dpkg/status.d/") and not k.endswith(".md5sums"))]
    if status:
        for data in status:
            for f in paragraphs(data):
                if "Package" not in f or "Version" not in f or not f.get("Status", " installed").endswith(" installed"):
                    continue
                src, srcver = f.get("Source", f["Package"]), f["Version"]
                m = re.match(r"(\S+)\s+\((.+)\)", src)
                if m:
                    src, srcver = m.groups()
                pkgs.append(comp("os-paket", f["Package"], f["Version"], arch=f.get("Architecture", ""),
                                 src=src, srcver=srcver, maint=f.get("Maintainer", "")))
        for k, v in files.items():   # Dateilisten: info/<paket>[:arch].list, status.d/<paket>.md5sums (distroless)
            base = posixpath.basename(k)
            if k.startswith("/var/lib/dpkg/info/") and base.endswith(".list"):
                for line in text(v).splitlines():
                    owners[norm(line)].add(base[:-5].split(":")[0])
            elif k.startswith("/var/lib/dpkg/status.d/") and base.endswith(".md5sums"):
                for line in text(v).splitlines():
                    if len(line.split(None, 1)) == 2:
                        owners[norm("/" + line.split(None, 1)[1])].add(base[:-8])
        return pkgs, owners, "dpkg"

    if "/lib/apk/db/installed" in files:
        for block in text(files["/lib/apk/db/installed"]).split("\n\n"):
            f, d = {}, ""
            for line in block.splitlines():
                key, val = line[:2], line[2:]
                if key in ("P:", "V:", "A:", "o:", "m:"):
                    f[key] = val
                elif key == "F:":
                    d = val
                elif key == "R:" and "P:" in f:
                    owners[norm("/%s/%s" % (d, val))].add(f["P:"])
            if "P:" in f:
                pkgs.append(comp("os-paket", f["P:"], f.get("V:", ""), arch=f.get("A:", ""),
                                 src=f.get("o:", f["P:"]), srcver=f.get("V:", ""), maint=f.get("m:", "")))
        return pkgs, owners, "apk"

    # RPM: Datenbank ist binär -> rpm im Container, sonst rpm des Hosts (SLES) auf eine Kopie
    qf = "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
    rc, out = c.exec(["rpm", "-qa", "--qf", qf])
    how = "rpm (Host)" if isinstance(c, Host) else "rpm (im Container)"
    if isinstance(c, Host) and (rc != 0 or not out.strip()):
        out, how = "", "keine Paketdatenbank gefunden (rpm -qa ohne Ergebnis)" if rc != 127 else "keine Paketdatenbank gefunden"
    elif rc != 0 or not out.strip():
        out, how = "", "keine Paketdatenbank gefunden"
        tmp = tempfile.mkdtemp()
        for db in ("/usr/lib/sysimage/rpm/.", "/var/lib/rpm/."):
            if run(["docker", "cp", "%s:%s" % (c.id, db), tmp])[0] == 0:
                # Kopie aus dem (nicht vertrauenswürdigen) Container: symbolische Links könnten rpm als root auf
                # Host-Dateien lenken -> ablehnen; rpm wenn möglich als nobody ausführen
                if any(os.path.islink(os.path.join(d, n)) for d, ds, fs in os.walk(tmp) for n in ds + fs):
                    how = "RPM-Datenbank enthält symbolische Links – aus Sicherheitsgründen nicht gelesen"
                    break
                cmd = ["rpm", "--dbpath", tmp, "-qa", "--qf", qf]
                if os.geteuid() == 0 and run(["setpriv", "--help"])[0] == 0:
                    run(["chown", "-R", "65534:65534", tmp])
                    cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + cmd
                rc, out = run(cmd)
                how = "rpm (Datenbank mit rpm des Hosts gelesen)" if rc == 0 and out.strip() else \
                      "RPM-Datenbank gefunden, aber auf dem Host nicht lesbar"
                break
        run(["rm", "-rf", tmp])
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 4 or f[0] in ("", "gpg-pubkey"):
            continue
        name, version, arch, srpm = f[:4]
        m = re.match(r"(.+)-([^-]+-[^-]+)\.(no)?src\.rpm$", srpm)   # name-version-release.src.rpm
        src, srcver = (m.group(1), m.group(2)) if m else (name, version)
        epoch = re.match(r"\d+:", version)
        pkgs.append(comp("os-paket", name, version, arch=arch, src=src,
                         srcver=(epoch.group(0) if epoch and m else "") + srcver))
    return pkgs, owners, how


def rpm_owners(c, paths):
    """Für RPM: Besitzer der laufenden Programme/Bibliotheken und der Sprach-Komponenten. Eine Abfrage aller Dateien
    aller Pakete (rpm -qf gäbe je Pfad alle Dateien des Pakets aus: bei Hunderten Bibliotheken sehr viel).
    Format %{=NAME}: rpm 4.14 (SLES 15) verlangt es, wenn eine Liste mit einem Einzelwert steht."""
    owners = defaultdict(set)
    if paths:
        rc, out = c.exec(["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{=NAME}\n]"], timeout=300)
        want = {norm(p) for p in paths}
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) == 2 and norm(f[0]) in want:
                owners[norm(f[0])].add(f[1])
    return owners


# ===========================================================================
# 3. Anwendungspakete: npm, Composer, PyPI
# ===========================================================================
def load_json(data):
    try:
        return json.loads(text(data))
    except ValueError:
        return None


def npm_packages(files):
    dev = set()   # Paketverzeichnisse, die in einer (.)package-lock.json als "dev" markiert sind
    for path, data in files.items():
        base = posixpath.basename(path)
        if base in ("package-lock.json", ".package-lock.json"):
            root = posixpath.dirname(path)
            if base.startswith("."):          # <projekt>/node_modules/.package-lock.json
                root = posixpath.dirname(root)
            lock = load_json(data)
            for key, entry in ((lock or {}).get("packages") or {}).items() if isinstance(lock, dict) else ():
                if key and isinstance(entry, dict) and entry.get("dev"):
                    dev.add(posixpath.join(root, key))
    result = []
    for path, data in files.items():
        if posixpath.basename(path) != "package.json":
            continue
        d = load_json(data)
        if isinstance(d, dict) and isinstance(d.get("name"), str) and isinstance(d.get("version"), str) \
                and d["name"] and d["version"]:
            ort = posixpath.dirname(path)
            result.append(comp("npm", d["name"], d["version"], ort, dev=ort in dev, datei=path))
    return result


def composer_packages(files):
    result = []
    for path, data in files.items():
        if not path.endswith("/vendor/composer/installed.json"):
            continue
        d = load_json(data)
        pkgs = d.get("packages", []) if isinstance(d, dict) else (d or [])   # Composer 2 bzw. 1
        dev = set(d.get("dev-package-names", [])) if isinstance(d, dict) else set()
        ort = path[:-len("/vendor/composer/installed.json")] or "/"
        for p in pkgs:
            if isinstance(p, dict) and p.get("name") and p.get("version"):
                result.append(comp("composer", p["name"], p["version"], ort, dev=p["name"] in dev, datei=path))
    return result


def pypi_packages(files):
    result = []
    for path, data in files.items():
        if path.endswith((".dist-info/METADATA", ".egg-info/PKG-INFO")):
            ort = posixpath.dirname(posixpath.dirname(path))
        elif path.endswith(".egg-info"):
            ort = posixpath.dirname(path)
        else:
            continue
        header = text(data).split("\n\n", 1)[0]
        name = re.search(r"^Name:\s*(\S+)", header, re.M)
        version = re.search(r"^Version:\s*(\S+)", header, re.M)
        if name and version:
            c = comp("pypi", name.group(1), version.group(1), ort, datei=path)
            if re.match(r"/usr/lib(64)?/python[\d.]*/(dist|site)-packages$|/usr/lib/python3/dist-packages$", ort):
                c["hinweise"].append("per OS-Paket installiert")
            result.append(c)
    return result


# ===========================================================================
# 4. Laufende Prozesse: Programm, Arbeitsverzeichnis, Kommandozeile, geladene Dateien, Ports
# ===========================================================================
# Ausgabe je Zeile: P <pid> <exe> <cwd> <argv mit \037 getrennt> <uid:gid> <ppid> | M <pid> <datei>
#                   F <pid> <offene datei> | E <pid> <PATH=... bzw. VIRTUAL_ENV=...> | S <pid> <socket-inode>
#                   T <inode> <lokale-adresse:port> <tcp|udp>  (lauschende Sockets)
#                   C <inode> <lokale-adresse:port> <entfernte-adresse:port>  (bestehende TCP-Verbindungen)
# Nur die übergebenen PIDs (ohne Argumente: nichts) – über den Host aufgerufen sonst alle Host-Prozesse.
PROC_SH = r"""
self=$$
first=""
for pid in "$@"; do
    [ "$pid" = "$self" ] && continue
    d=/proc/$pid
    e=$(readlink "$d/exe" 2>/dev/null) || continue
    pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
    [ "$pp" = "$self" ] && continue
    [ -z "$first" ] && first=$pid
    printf 'P\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$e" "$(readlink "$d/cwd" 2>/dev/null)" "$(tr '\000\t\n' '\037  ' < "$d/cmdline" 2>/dev/null)" \
        "$(awk '/^Uid:/ { u = $3 } /^Gid:/ { g = $3 } END { print u ":" g }' "$d/status" 2>/dev/null)" "$pp"
    tr '\000' '\n' < "$d/environ" 2>/dev/null | sed -n "s/^\(PATH\|VIRTUAL_ENV\)=/E\t$pid\t&/p"
    awk -v p="$pid" '$6 ~ /^\// { f = $6; for (i = 7; i <= NF; i++) f = f " " $i; print "M\t" p "\t" f }' "$d/maps" 2>/dev/null | sort -u
    for fd in "$d"/fd/*; do
        l=$(readlink "$fd" 2>/dev/null)
        case "$l" in
            socket:\[*) i=${l#socket:[}; printf 'S\t%s\t%s\n' "$pid" "${i%]}" ;;
            /dev/*|/proc/*) ;;
            /*) printf 'F\t%s\t%s\n' "$pid" "$l" ;;
        esac
    done
done
[ -n "$first" ] && cat "/proc/$first/net/tcp" "/proc/$first/net/tcp6" 2>/dev/null | awk '$4 == "0A" { print "T\t" $10 "\t" $2 "\ttcp" }
    $4 == "01" && $10 != "0" { print "C\t" $10 "\t" $2 "\t" $3 }'
[ -n "$first" ] && cat "/proc/$first/net/udp" "/proc/$first/net/udp6" 2>/dev/null | awk '$4 == "07" { print "T\t" $10 "\t" $2 "\tudp" }'
"""


def proc_lesen(pids, proc="/proc"):
    """Wie PROC_SH, aber in Python (für den Host: liest /proc direkt, ohne awk/sed/tr; dieser Prozess zählt nicht).
    Liefert dieselben Zeilen wie PROC_SH für procs_auswerten."""
    lines, first = [], None
    for pid in pids:
        d = os.path.join(proc, pid)
        if pid == str(os.getpid()):
            continue
        try:
            exe = os.readlink(os.path.join(d, "exe"))
            with open(os.path.join(d, "status")) as f:
                status = f.read()
            with open(os.path.join(d, "cmdline"), "rb") as f:
                argv = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        uid = re.search(r"^Uid:\s*\S+\s+(\d+)", status, re.M)
        gid = re.search(r"^Gid:\s*\S+\s+(\d+)", status, re.M)
        ppid = re.search(r"^PPid:\s*(\d+)", status, re.M)
        try:
            cwd = os.readlink(os.path.join(d, "cwd"))
        except OSError:
            cwd = ""
        first = first or pid
        lines.append("P\t%s\t%s\t%s\t%s\t%s:%s\t%s" % (
            pid, exe, cwd, argv.replace("\0", "\x1f").replace("\t", " ").replace("\n", " "),
            uid.group(1) if uid else "", gid.group(1) if gid else "", ppid.group(1) if ppid else ""))
        try:
            with open(os.path.join(d, "environ"), "rb") as f:
                for e in f.read().decode("utf-8", "replace").split("\0"):
                    if e.startswith(("PATH=", "VIRTUAL_ENV=")):
                        lines.append("E\t%s\t%s" % (pid, e))
        except OSError:
            pass
        try:
            with open(os.path.join(d, "maps")) as f:
                maps = sorted({x.split(None, 5)[5].strip() for x in f if len(x.split(None, 5)) == 6
                               and x.split(None, 5)[5].startswith("/")})
            lines += ["M\t%s\t%s" % (pid, m) for m in maps]
        except OSError:
            pass
        try:
            fds = os.listdir(os.path.join(d, "fd"))
        except OSError:
            fds = []
        for fd in fds:
            try:
                l = os.readlink(os.path.join(d, "fd", fd))
            except OSError:
                continue
            if l.startswith("socket:["):
                lines.append("S\t%s\t%s" % (pid, l[8:-1]))
            elif l.startswith("/") and not l.startswith(("/dev/", "/proc/")):
                lines.append("F\t%s\t%s" % (pid, l))
    for name, art in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(os.path.join(proc, first or "self", "net", name)) as f:
                rows = f.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            x = row.split()
            if len(x) < 10:
                continue
            if (art == "tcp" and x[3] == "0A") or (art == "udp" and x[3] == "07"):
                lines.append("T\t%s\t%s\t%s" % (x[9], x[1], art))
            elif art == "tcp" and x[3] == "01" and x[9] != "0":
                lines.append("C\t%s\t%s\t%s" % (x[9], x[1], x[2]))
    return "\n".join(lines) + "\n"


def decode_addr(hexaddr):
    if set(hexaddr) == {"0"}:
        return "alle"
    if len(hexaddr) == 32 and hexaddr[:24] == "0000000000000000FFFF0000":     # ::ffff:a.b.c.d
        return decode_addr(hexaddr[24:])
    if hexaddr in ("0100007F", "00000000000000000000000001000000"):
        return "localhost"
    if len(hexaddr) == 8:
        return ".".join(str(b) for b in reversed(bytes.fromhex(hexaddr)))
    return "IPv6"


def decode_ip(hexaddr):
    """Adresse aus /proc/net/tcp(6) vollständig (für Verbindungsziele): IPv4, IPv4 in IPv6, IPv6."""
    try:
        if len(hexaddr) == 8:
            return ".".join(str(b) for b in reversed(bytes.fromhex(hexaddr)))
        ip = ipaddress.IPv6Address(b"".join(bytes.fromhex(hexaddr[i:i + 8])[::-1] for i in range(0, 32, 8)))
        return str(ip.ipv4_mapped or ip)
    except ValueError:
        return hexaddr


def nur_lokal(addr):
    """Lauscht nur auf Loopback (127.0.0.1, ::1, Dockers DNS auf 127.0.0.11): von außen nur über einen Proxy mit
    demselben Loopback erreichbar (Host-Netzwerk, gemeinsamer Netzwerk-Namespace)."""
    return addr == "localhost" or addr.startswith("127.")


def collect_procs(c):
    """Prozesse des Containers. Liefert (Prozesse, Erfassungsweg, lauschende Ports ohne sichtbaren Prozess
    {Port: (Adresse, Socket-Inode)}, z.B. eines Containers, der den Netzwerk-Namespace mitnutzt)."""
    if c.has_sh and c.has_proc_tools:
        # /proc/<pid>/exe, maps und fd fremder Benutzer darf auch root im Container nicht lesen (Docker gewährt
        # kein CAP_SYS_PTRACE). Daher je Prozess-Benutzer (z.B. solr, mysql, www-data) als dieser Benutzer lesen.
        rc, ids = c.sh(r"""for d in /proc/[0-9]*; do
            awk -v p="${d#/proc/}" '/^Uid:/ { u = $3 } /^Gid:/ { g = $3 } END { if (u != "") print p, u ":" g }' "$d/status" 2>/dev/null
        done""")
        by_user = defaultdict(list)
        for line in ids.splitlines():
            pid, ug = line.split()
            by_user[ug].append(pid)
        out = "".join(c.sh(PROC_SH, user=ug, args=pids)[1] for ug, pids in sorted(by_user.items()))
        how = "im Container (je Prozess-Benutzer)"
    else:   # ohne Shell/Werkzeuge über die Host-PIDs (root auf dem Host nötig; Volume-Pfade erscheinen als Host-Pfade)
        rc, top = run(["docker", "top", c.id, "-eo", "pid"])
        pids = top.split()[1:]
        if rc != 0 or not pids or not all(p.isdigit() for p in pids):
            raise ScanError("Prozesse des Containers nicht ermittelbar (docker top fehlgeschlagen)")
        rc, out = run(["sh", "-s", "--"] + pids, input=PROC_SH)
        how = "über /proc des Hosts"
    procs, fremd = procs_auswerten(out)
    return procs, how, fremd


def procs_auswerten(out):
    """Ausgabe von PROC_SH auswerten: (Prozesse, lauschende Ports ohne sichtbaren Prozess {Port: (Adresse, Inode)}).
    Je Prozess auch die
    ausgehenden TCP-Verbindungen (Ziel-Adresse, Ziel-Port), z.B. eines API-Gateways zu seinen Zielen."""
    procs, sockets, listen, conns = OrderedDict(), defaultdict(set), {}, []
    for line in out.splitlines():
        f = line.split("\t")
        if f[0] == "P" and len(f) >= 5:
            procs[f[1]] = {"pid": f[1], "exe": re.sub(r" \(deleted\)$", "", f[2]), "cwd": f[3],
                           "argv": [a for a in f[4].split("\x1f") if a], "user": f[5] if len(f) > 5 and f[5] != ":" else "",
                           "ppid": f[6] if len(f) > 6 else "",
                           "maps": set(), "files": set(), "env": {}, "ports": OrderedDict(), "bindungen": {},
                           "verbindungen": OrderedDict()}
        elif f[0] == "E" and f[1] in procs and "=" in f[2]:
            k, _, v = f[2].partition("=")
            procs[f[1]]["env"][k] = v
        elif f[0] == "M" and f[1] in procs:
            procs[f[1]]["maps"].add(f[2])
        elif f[0] == "F" and f[1] in procs:
            procs[f[1]]["files"].add(f[2])
        elif f[0] == "S":
            sockets[f[2]].add(f[1])
        elif f[0] == "T" and ":" in f[2]:
            addr, port = f[2].split(":")
            port = str(int(port, 16)) + ("/udp" if len(f) > 3 and f[3] == "udp" else "")   # TCP ohne Zusatz
            listen[(f[1], port)] = (port, decode_addr(addr), decode_ip(addr))
        elif f[0] == "C" and len(f) > 3 and ":" in f[2] and ":" in f[3]:
            conns.append(f[1:4])
    fremd = OrderedDict()
    for (inode, _), (port, addr, ip) in listen.items():
        owners = [pid for pid in sockets.get(inode, ()) if pid in procs]
        for pid in owners:
            # mehrere Sockets am selben Port (z.B. 127.0.0.1 und 10.0.0.5): die weiteste Bindung zählt
            alt = procs[pid]["ports"].get(port)
            if alt is None or alt != "alle" and (addr == "alle" or nur_lokal(alt)):
                procs[pid]["ports"][port] = addr
            procs[pid]["bindungen"].setdefault(port, []).append(ip)
        if not owners and not nur_lokal(addr):
            fremd[port] = (addr, inode)
    # ausgehend: lokaler Port ist kein lauschender (sonst eingehende Verbindung eines Clients)
    tcp = {port for (_, port) in listen if "/" not in port}
    for inode, local, remote in conns:
        if str(int(local.split(":")[1], 16)) in tcp:
            continue
        addr, port = remote.split(":")
        for pid in sockets.get(inode, ()):
            if pid in procs:
                procs[pid]["verbindungen"][(decode_ip(addr), str(int(port, 16)))] = None
    for p in procs.values():
        p["base"] = posixpath.basename(p["exe"])
        p["label"] = p["base"] + (":" + ",".join(p["ports"]) if p["ports"] else "")
    return procs, fremd


# ===========================================================================
# 5. Laufzeiten direkt am Programm abfragen
# ===========================================================================
NODE_JS = 'console.log(JSON.stringify({exe: require("fs").realpathSync(process.execPath), versions: process.versions}))'
PY_CODE = r"""
import json, os, platform, sys
r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}}
try:
    import ssl
    n, v = ssl.OPENSSL_VERSION.split()[:2]
    r["libs"][n.lower()] = v
except Exception:
    pass
for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"),
                        ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")):
    try:
        r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "")
    except Exception:
        pass
sys.stdout.write(json.dumps(r))
"""
PHP_CODE = r"""
$r = array("exe" => realpath(PHP_BINARY) ?: PHP_BINARY, "version" => PHP_VERSION, "sapi" => PHP_SAPI, "ext" => array(), "libs" => array());
foreach (get_loaded_extensions() as $e) { $v = phpversion($e); if ($v && strpos($v, PHP_VERSION) === false && $e !== "dom") $r["ext"][$e] = $v; }
if (defined("OPENSSL_VERSION_TEXT")) { $p = explode(" ", OPENSSL_VERSION_TEXT); $r["libs"][strtolower($p[0])] = $p[1]; }
if (function_exists("curl_version")) { $c = curl_version(); $r["libs"]["curl"] = $c["version"]; }
if (defined("LIBXML_DOTTED_VERSION")) $r["libs"]["libxml2"] = LIBXML_DOTTED_VERSION;
if (defined("PCRE_VERSION")) { $p = explode(" ", PCRE_VERSION); $r["libs"]["pcre2"] = $p[0]; }
if (defined("INTL_ICU_VERSION")) $r["libs"]["icu"] = INTL_ICU_VERSION;
if (class_exists("SQLite3")) { $s = SQLite3::version(); $r["libs"]["sqlite"] = $s["versionString"]; }
if (defined("SODIUM_LIBRARY_VERSION")) $r["libs"]["libsodium"] = SODIUM_LIBRARY_VERSION;
if (defined("ZLIB_VERSION")) $r["libs"]["zlib"] = ZLIB_VERSION;
echo json_encode($r);
"""
NODE_SKIP = {"modules", "napi", "unicode", "cldr", "tz"}


def probe_runtimes(c, procs, owners):
    """Versionen am Programm abfragen: laufende Programme + übliche Namen im PATH."""
    # Abfrage nie mit mehr Rechten als der laufende Prozess; Programme nur im PATH: als nobody
    users = {}
    for p in procs.values():
        users.setdefault(p["exe"], p["user"] or NOBODY)   # Benutzer unbekannt: nobody
    candidates = list(OrderedDict.fromkeys([p["exe"] for p in procs.values()] +
                                           ["node", "php", "python3", "python", "nginx", "httpd", "apache2", "java", "mariadbd", "mysqld", "postgres"]))
    result, seen = [], set()

    def add(typ, name, version, ort, hinweis=""):
        if not version or (typ, name, version, hinweis) in seen:
            return
        seen.add((typ, name, version, hinweis))
        x = comp(typ, name, version, ort)
        x["hinweise"] += [h for h in (hinweis,) if h]
        if owners.get(norm(ort)):   # Programm stammt aus einem OS-Paket -> Scanner prüfen es darüber
            x["hinweise"].append("aus OS-Paket " + ",".join(sorted(owners[norm(ort)])))
        result.append(x)

    def as_json(rc_out):
        try:
            return json.loads(rc_out[1]) if rc_out[0] == 0 else None
        except ValueError:
            return None

    for exe in candidates:
        base = posixpath.basename(exe)
        user = users.get(exe, NOBODY)
        if "/" not in exe:      # Name ohne Pfad: über den PATH des Images suchen, dann aber nur als nobody
            user, path = NOBODY, None
        else:
            path = SAFE_PATH

        def probe(cmd, stderr=False):
            return c.probe(cmd, user, stderr=stderr, path=path)
        if base in ("node", "nodejs"):
            d = as_json(probe([exe, "-e", NODE_JS]))
            if d:
                add("runtime", "node", d["versions"].get("node"), d["exe"])
                for k, v in d["versions"].items():
                    if k != "node" and k not in NODE_SKIP:
                        add("runtime-lib", k, v, d["exe"], "in node enthalten/gelinkt")
        elif re.match(r"python([23](\.\d+)?)?$", base):
            # -I: kein Arbeitsverzeichnis/PYTHON*-Variablen im Suchpfad, -S: keine site-Module (.pth); Python 2: -E -s -S
            d = as_json(probe([exe, "-I", "-S", "-c", PY_CODE])) or as_json(probe([exe, "-E", "-s", "-S", "-c", PY_CODE]))
            if d:
                add("runtime", "python", d["version"], d["exe"])
                for k, v in d["libs"].items():
                    add("runtime-lib", k, v, d["exe"], "von python gelinkt")
        elif re.match(r"php[\d.]*$", base):
            d = as_json(probe([exe, "-r", PHP_CODE]))
            if d:
                add("runtime", "php", d["version"], d["exe"], d["sapi"])
                for k, v in (d["ext"] or {}).items():
                    add("php-ext", k, v, d["exe"], "eigene Version (PECL o.ä.)")
                for k, v in (d["libs"] or {}).items():
                    add("runtime-lib", k, v, d["exe"], "von php gelinkt")
        elif base.startswith("php-fpm"):
            m = re.match(r"PHP (\S+)", probe([exe, "-v"])[1])
            add("runtime", "php-fpm", m and m.group(1), exe, "gleicher Build wie php-CLI angenommen")
        elif base == "nginx":
            m = re.search(r"nginx/(\S+)", probe([exe, "-v"], stderr=True)[1])
            add("server", "nginx", m and m.group(1), exe)
        elif ist_apache(base):
            m = re.search(r"Apache/(\S+)", probe([exe, "-v"], stderr=True)[1])
            add("server", "apache-httpd", m and m.group(1), exe)
        elif base == "java":
            m = re.search(r'version "([^"]+)"', probe([exe, "-XX:-UsePerfData", "-version"], stderr=True)[1])
            v = m and re.sub(r"^1\.(\d+)\.(\d+)_(\d+).*", r"\1.\2.\3", m.group(1))   # Java 8: 1.8.0_412 -> 8.0.412
            add("runtime", "java", v, exe)
        elif base in ("mariadbd", "mysqld"):
            out = probe([exe, "--version"], stderr=True)[1]
            m = re.search(r"Ver (\d+\.\d+\.\d+)", out)
            add("server", "mariadb" if "MariaDB" in out else "mysql", m and m.group(1), exe)
        elif base == "postgres":
            m = re.search(r"\(PostgreSQL\) (\d+(?:\.\d+)*)", probe([exe, "--version"], stderr=True)[1])
            add("server", "postgresql", m and m.group(1), exe)
    return result


def host_components():
    """Host-Kernel und Container-Laufzeit: werden vom Container mitgenutzt."""
    host_os = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', open("/etc/os-release", encoding="utf-8", errors="replace").read(), re.M)) \
        if os.path.exists("/etc/os-release") else {}
    result = [comp("host", "linux-kernel", os.uname().release, "Host", hinweise=[host_os.get("PRETTY_NAME", "")])]
    rc, out = run(["docker", "version", "-f", "{{json .Server.Components}}"])
    for x in (json.loads(out) if rc == 0 and out.strip().startswith("[") else []):
        name = {"Engine": "docker-engine"}.get(x["Name"], x["Name"].lower().replace(" ", "-"))
        result.append(comp("host", name, x["Version"], "Host"))
    return result


# ===========================================================================
# 6. Webserver-Konfiguration, veröffentlichte Ports, andere Container
# ===========================================================================
# Variablen, die in nginx nur den Pfad bzw. das Schema eines Ziels bilden (proxy_pass http://app$request_uri)
NGINX_PFAD_VARIABLEN = re.compile(r"\$\{?(?:request_uri|uri|document_uri|is_args|args|query_string|\d)\}?(?!\w)")


def nginx_ziele(target, variables, depth=0):
    """Variablen in einem nginx-Ziel durch ihre Werte aus set/map ersetzen (je Wert ein Ziel). Bleibt eine
    Variable ohne bekannten Wert (z.B. $host), bleibt sie stehen – das Ziel ist dann nicht auswertbar."""
    target = NGINX_PFAD_VARIABLEN.sub("", re.sub(r"\$\{?scheme\}?(?!\w)", "http", target))
    target = re.sub(r"^[a-z0-9]+://(?=[a-z0-9]+://)", "", target)    # http://$backend mit backend = http://...
    m = re.search(r"\$\{?(\w+)\}?", target)
    if not m or depth > 5 or not variables.get(m.group(1)):
        return [target]
    return [t for value in OrderedDict.fromkeys(variables[m.group(1)])
            for t in nginx_ziele(target[:m.start()] + value + target[m.end():], variables, depth + 1)]


NGINX_PASS = ("proxy_pass", "fastcgi_pass", "uwsgi_pass", "grpc_pass", "scgi_pass")
# Apache: Programmnamen (Debian/Ubuntu apache2, RHEL/Alpine/offizielles Image httpd, SLES httpd-prefork u.ä.)
APACHE = re.compile(r"(apache2|httpd2?)(-(prefork|worker|event|itk))?$")
WEBSERVER = re.compile(r"nginx$|(apache2|httpd2?)(-(prefork|worker|event|itk))?$")


def ist_apache(base):
    return bool(APACHE.match(base))


def ist_webserver(base):
    return bool(WEBSERVER.match(base))


def nginx_listen(args):
    """Argumente einer listen-Anweisung -> {"adresse", "port", "ssl", "udp"}; Unix-Sockets: None."""
    if not args or args[0].startswith("unix:"):
        return None
    a = args[0]
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", a)
    if m:
        adresse, port = m.group(1), m.group(2) or "80"
    elif a.isdigit():
        adresse, port = "*", a
    elif re.search(r":\d+$", a):
        adresse, _, port = a.rpartition(":")
    else:
        adresse, port = a, "80"
    return {"adresse": "*" if adresse in ("*", "0.0.0.0") else adresse, "port": port, "ssl": "ssl" in args[1:],
            "udp": "quic" in args[1:]}


def location_pfad(stack):
    """Pfad des innersten location-Blocks ("/app/", "~ \\.php$", "= /x"); "" außerhalb."""
    for block in reversed(stack):
        if block["words"][:1] == ["location"]:
            return " ".join(block["words"][1:])
    return ""


def nginx_beschraenkt(direktiven):
    """Zugriff in einem Block eingeschränkt (deny all, internal, Anmeldung)?"""
    return any(d[:2] == ["deny", "all"] or d[0] in ("internal", "auth_request")
               or (d[0] == "auth_basic" and d[1:2] != ["off"]) for d in direktiven)


def parse_nginx(conf, web, exe):
    """Ausgabe von 'nginx -T' auswerten: server-Blöcke, root, *_pass, upstream; Variablen aus set und map
    (proxy_pass $backend mit resolver, damit nginx auch ohne laufendes Backend startet). Je server-Block im
    http-Kontext eine Website (listen, server_name, TLS, Weiterleitungen je location) für die Webadressen, dazu
    autoindex und stub_status für die Prüfung der Einstellungen (webserver_pruefen)."""
    marken = [(m.start(), m.group(1)) for m in re.finditer(r"^# configuration file (.+?):\s*$", conf, re.M)]
    conf = re.sub(r"#[^\n]*", lambda m: " " * len(m.group(0)), conf)     # Kommentare, Positionen bleiben
    stack, stmt, vhost = [], "", None
    targets, variables, sites = [], defaultdict(list), []
    for mt in re.finditer(r"\$\{\w+\}|[{};]|(?:[^{};$]|\$(?!\{))+", conf):     # ${var} gehört zur Anweisung
        tok = mt.group(0)
        if tok == "{":
            words = stmt.split()
            stack.append({"words": words, "direktiven": []})
            stmt = ""
            if words[:1] == ["server"]:
                vhost = {"listen": [], "server_name": "", "root": [], "listen_info": [], "namen": [], "weiter": [],
                         "ssl": False, "autoindex": [], "status": [],
                         "datei": next((f for pos, f in reversed(marken) if pos < mt.start()), ""),
                         "http": not any(b["words"][:1] in (["stream"], ["mail"]) for b in stack[:-1])}
        elif tok == ";":
            words, stmt = stmt.split(), ""
            if not words:
                continue
            key, arg = words[0], (words[1] if len(words) > 1 else "")
            parent = stack[-1]["words"] if stack else []
            if stack:
                stack[-1]["direktiven"].append(words)
            if parent[:1] == ["upstream"] and key == "server" and len(parent) > 1:
                web["upstreams"][parent[1]].append(arg)
            elif parent[:1] == ["map"] and len(parent) > 2 and len(words) > 1 and key not in ("hostnames", "volatile", "include"):
                variables[parent[2].lstrip("$")].append(words[1].strip("'\""))
            elif key == "set" and len(words) > 2:
                variables[arg.lstrip("$")].append(words[2].strip("'\""))
            elif key == "listen" and vhost is not None:
                vhost["listen"].append(arg)
                info = nginx_listen(words[1:])
                if info:
                    vhost["listen_info"].append(info)
            elif key == "server_name" and vhost is not None:
                vhost["server_name"] = " ".join(words[1:])
                vhost["namen"] = [n.strip("'\"") for n in words[1:]]
            elif key == "ssl" and arg == "on" and vhost is not None:
                vhost["ssl"] = True
            elif key == "root":
                web["docroots"][exe].append(arg)
                if vhost is not None:
                    vhost["root"].append(arg)
            elif key in NGINX_PASS:
                targets.append(arg.strip("'\""))
                if vhost is not None:
                    vhost["weiter"].append((location_pfad(stack) or "/", arg.strip("'\"")))
            elif key == "fastcgi_param" and arg == "SCRIPT_FILENAME" and len(words) > 2:
                prefix = words[2].split("$")[0]
                if prefix.startswith("/"):
                    web["docroots"][exe].append(prefix)
            elif key == "autoindex" and arg == "on":
                if vhost is not None:
                    vhost["autoindex"].append(location_pfad(stack) or "/")
                elif any(b["words"][:1] == ["http"] for b in stack):
                    web["web_konf"].append({"id": "WEB-AUTOINDEX", "exe": exe, "site": None, "pfad": "",
                                            "text": "nginx: autoindex on im http-Block (Verzeichnislisten in allen "
                                                    "Servern ohne eigenes autoindex off)"})
        elif tok == "}":
            block = stack.pop() if stack else {"words": [], "direktiven": []}
            if block["words"][:1] == ["location"] and vhost is not None \
                    and any(d[0] == "stub_status" for d in block["direktiven"]):
                server = next((b for b in reversed(stack) if b["words"][:1] == ["server"]), {"direktiven": []})
                if not nginx_beschraenkt(block["direktiven"] + server["direktiven"]):
                    vhost["status"].append(" ".join(block["words"][1:]))
            if block["words"][:1] == ["server"] and vhost is not None:
                web["vhosts"][exe].append("listen " + ",".join(vhost["listen"]) +
                                          (" server_name " + vhost["server_name"] if vhost["server_name"] not in ("", "_") else "") +
                                          (" root " + ",".join(vhost["root"]) if vhost["root"] else ""))
                if vhost["http"]:
                    sites.append(vhost)
                vhost = None
        else:
            stmt += tok
    for t in targets:
        web["backends"][exe].extend(nginx_ziele(t, variables))
    for v in sites:
        listen = v["listen_info"] or ([] if v["listen"] else [{"adresse": "*", "port": "80", "ssl": False, "udp": False}])
        site = {"exe": exe, "art": "nginx", "namen": [n for n in v["namen"] if n not in ("", "_", '""')],
                "listen": [dict(l, ssl=l["ssl"] or v["ssl"]) for l in listen if not l["udp"]],
                "roots": list(OrderedDict.fromkeys(v["root"])), "datei": v["datei"],
                "weiter": [(pfad, z) for pfad, t in v["weiter"] for z in nginx_ziele(t, variables)]}
        web["sites"].append(site)
        for pfad in v["autoindex"]:
            web["web_konf"].append({"id": "WEB-AUTOINDEX", "exe": exe, "site": site, "pfad": pfad,
                                    "text": "nginx: autoindex on (Verzeichnisliste) in location %s" % pfad})
        for pfad in v["status"]:
            web["web_konf"].append({"id": "WEB-STATUS", "exe": exe, "site": site, "pfad": pfad,
                                    "text": "nginx: stub_status in location %s ohne Zugriffsbeschränkung (deny all, "
                                            "auth_basic, internal)" % pfad})


def server_masters(procs, exe):
    """Hauptprozesse eines Webservers: Prozesse mit diesem Programm, deren Elternprozess ein anderes Programm ist
    (nicht die Worker). Ihr Benutzer und ihre Optionen gelten für die Abfrage der Konfiguration."""
    same = [p for p in procs.values() if p["exe"] == exe]
    return [p for p in same if (procs.get(p.get("ppid", "")) or {}).get("exe") != exe] or same


def server_user(p):
    """Benutzer für die Abfrage der Webserver-Konfiguration: der des Hauptprozesses, nie mehr. Programm,
    Optionen und Konfiguration bestimmt der Container; als root ausgeführt, könnte ein unprivilegierter Prozess
    so root im Container werden (eigenes Programm namens nginx, load_module/LoadModule in der Konfiguration)."""
    return p["user"] or NOBODY


def apache_optionen(argv):
    """Optionen des Hauptprozesses, die bestimmen, welche Konfiguration Apache liest: -f, -d, -C, -c, -D. SLES
    startet z.B. mit -DSYSCONFIG -C "Include /etc/apache2/sysconfig.d//loadmodule.conf" -f /etc/apache2/httpd.conf;
    ohne sie zeigen -S und -M eine andere Konfiguration (ohne die Module aus /etc/sysconfig/apache2)."""
    out, i = [], 1
    while i < len(argv):
        a = argv[i]
        if a in ("-f", "-d", "-C", "-c", "-D") and i + 1 < len(argv):
            out += [a, argv[i + 1]]
            i += 2
            continue
        if re.match(r"-[fdCcD]\S", a):
            out.append(a)
        i += 1
    return out


def apache_vhosts(out):
    """vHosts aus 'httpd -S': [{"adresse", "port", "name", "aliase", "datei", "zeile"}] – maßgeblich, denn Apache
    hat dabei Include, Define und IfDefine schon ausgewertet."""
    result, nvh = [], None
    for line in out.splitlines():
        m = re.match(r"^(\S+):(\d+|\*)\s+is a NameVirtualHost\s*$", line)
        if m:
            nvh = m.groups()
            continue
        m = re.match(r"^(\S+):(\d+|\*)\s+(\S+) \((.+):(\d+)\)\s*$", line)
        if m:
            result.append({"adresse": m.group(1), "port": m.group(2), "name": m.group(3), "aliase": [],
                           "datei": m.group(4), "zeile": int(m.group(5))})
            nvh = None
            continue
        m = re.match(r"^\s+port (\d+|\*) namevhost (\S+) \((.+):(\d+)\)\s*$", line)
        if m and nvh:
            result.append({"adresse": nvh[0], "port": m.group(1), "name": m.group(2), "aliase": [],
                           "datei": m.group(3), "zeile": int(m.group(4))})
            continue
        m = re.match(r"^\s+(?:wild )?alias (\S+)\s*$", line)
        if m and result:
            result[-1]["aliase"].append(m.group(1))
        elif not line.startswith((" ", "\t")):
            nvh = None
    return result


def apache_name(word):
    """ServerName "https://www.example.org:443" -> ("www.example.org", "https" bzw. "")."""
    m = re.match(r"^(?:(https?)://)?([^/:]+|\[[^\]]+\])(?::\d+)?/?$", word)
    return (m.group(2), m.group(1) or "") if m else (word, "")


# Freigaben für den Zugriff nur von diesem Rechner (Require local, Allow from localhost …)
APACHE_NUR_LOKAL = re.compile(r"(?i)^(require (not )?(local|ip (127\.[\d.]*|::1)( (127\.[\d.]*|::1))*|host localhost)"
                              r"|allow from (localhost|127\.[\d.]*|::1)( (localhost|127\.[\d.]*|::1))*)$")


def parse_apache(c, exe, web, user=NOBODY, optionen=()):
    """Apache-Konfiguration: -S (vHosts), -M (Module), -t -D DUMP_INCLUDES (Dateien) mit den Optionen des
    Hauptprozesses; die Dateien selbst für Docroots, Weiterleitungen, TLS und die Prüfung der Einstellungen."""
    fehler = []
    optionen = list(optionen)

    def ap(*args):   # Debian/Ubuntu brauchen /etc/apache2/envvars
        cmd = [exe] + optionen + list(args)
        if c.has_sh:
            rc, out = c.exec(["sh", "-c", '[ -r /etc/apache2/envvars ] && . /etc/apache2/envvars; exec "$0" "$@"'] +
                             cmd, stderr=True, timeout=60, user=user)
        else:
            rc, out = c.exec(cmd, stderr=True, timeout=60, user=user)
        if rc != 0 and args[0] in ("-S", "-t"):
            fehler.append(" ".join(args))
        return out
    s_out, m_out = ap("-S"), ap("-M")
    raw = "--- %s -S\n%s--- %s -M\n%s" % (" ".join([exe] + optionen), s_out, exe, m_out)
    web["raw"].append(raw)
    module = set(re.findall(r"^\s*(\w+)_module\b", m_out, re.M))
    env = dict(e.split("=", 1) for e in c.info["Config"].get("Env") or [] if "=" in e)

    def path(word):      # ${APACHE_DOCUMENT_ROOT} u.ä. aus der Container-Umgebung; sonst unbrauchbar
        word = re.sub(r"\$\{(\w+)\}", lambda m: env.get(m.group(1), m.group(0)), word)
        return word if word.startswith("/") and "${" not in word else None
    m = re.search(r'Main DocumentRoot: "([^"]+)"', raw)
    haupt = {"namen": [], "roots": [m.group(1)] if m else [], "listen": [], "weiter": [], "ssl": False}
    if m:
        web["docroots"][exe].append(m.group(1))
    if "php" in " ".join(module) or re.search(r"^\s*php\d*_module", raw, re.M):
        web["modphp"].add(exe)
    includes = ap("-t", "-D", "DUMP_INCLUDES")
    if fehler:
        web["unlesbar"].add(exe)
        web["problems"].append("%s %s fehlgeschlagen: Konfiguration (vHosts, Proxy-Backends) nicht lesbar"
                               % (exe, " bzw. ".join(fehler)))
    bloecke = {}              # (Datei, Zeile von <VirtualHost>) -> vHost
    status, zugriff = [], defaultdict(list)    # Statusseiten; Freigaben je Location
    for conf in sorted(set(re.findall(r"(/\S+)\s*$", includes, re.M))):
        stack, vhost, weiter = [], None, ""
        for n, line in enumerate(c.read_file(conf).splitlines(), 1):
            if weiter:                     # Fortsetzungszeile (\ am Zeilenende)
                line, weiter = weiter + " " + line.strip(), ""
            if line.rstrip().endswith("\\"):
                weiter = line.rstrip()[:-1]
                continue
            if line.lstrip().startswith("#"):
                continue
            words = [w.strip('"') for w in line.split()]
            key = words[0].lower() if words else ""
            ort = next((b for b in reversed(stack) if b[0] in ("<location", "<locationmatch", "<files", "<filesmatch",
                                                              "<directory", "<directorymatch")), None)
            if key.startswith("</"):
                if stack:
                    stack.pop()
                if key == "</virtualhost>" and vhost is not None:
                    web["vhosts"][exe].append("VirtualHost " + vhost["listen"] + (" ServerName " + vhost["name"] if vhost["name"] else "") +
                                              (" DocumentRoot " + vhost["root"] if vhost["root"] else ""))
                    vhost = None
                continue
            if key.startswith("<"):
                arg = " ".join(words[1:]).rstrip(">").strip().strip('"') if len(words) > 1 else ""
                stack.append((key, arg))
                if key == "<virtualhost":
                    vhost = {"listen": words[1].rstrip(">") if len(words) > 1 else "", "name": "", "root": "",
                             "adressen": [w.rstrip(">") for w in words[1:] if w.rstrip(">")], "aliase": [],
                             "roots": [], "weiter": [], "ssl": False, "datei": conf}
                    bloecke[(conf, n)] = vhost
                continue
            ziel = vhost if vhost is not None else haupt
            if key == "servername" and len(words) > 1:
                name, schema = apache_name(words[1])
                if vhost is not None:
                    vhost["name"] = name
                else:
                    haupt["namen"] = [name]
                if schema == "https":
                    ziel["ssl"] = True
            elif key == "serveralias" and vhost is not None:
                vhost["aliase"] += words[1:]
            elif key == "sslengine" and len(words) > 1 and words[1].lower() == "on":
                ziel["ssl"] = True
            elif key == "listen" and len(words) > 1 and vhost is None:
                adr, _, port = words[1].rpartition(":") if ":" in words[1] else ("*", "", words[1])
                haupt["listen"].append({"adresse": "*" if adr in ("", "*", "0.0.0.0", "[::]") else adr.strip("[]"),
                                        "port": port, "ssl": len(words) > 2 and words[2].lower() == "https"})
            elif key == "documentroot" and len(words) > 1 and path(words[1]):
                web["docroots"][exe].append(path(words[1]))
                if vhost is not None:
                    vhost["root"] = path(words[1])
                    vhost["roots"].append(path(words[1]))
            elif key == "alias" and len(words) > 2 and path(words[2]):
                web["docroots"][exe].append(path(words[2]))
            elif key in ("proxypass", "proxypassmatch"):
                urls = [w for w in words[1:] if "://" in w]
                web["backends"][exe] += urls
                pfad = words[1] if len(words) > 2 and "://" not in words[1] else (ort[1] if ort else "/")
                if key == "proxypassmatch" or (ort and ort[0].endswith("match")):
                    pfad = "~ " + pfad
                ziel["weiter"] += [(pfad, u) for u in urls]
            elif key == "rewriterule" and len(words) > 3 and "://" in words[2] and re.search(r"(?i)\[(.*,)?P(,.*)?\]", words[3]):
                web["backends"][exe].append(words[2])
                ziel["weiter"].append(("~ " + words[1], words[2]))
            elif key == "sethandler" and len(words) > 1 and words[1].lower().startswith("proxy:"):
                web["backends"][exe].append(words[1][6:])
                pfad = ort[1] if ort and ort[0] in ("<location", "<locationmatch") else \
                    "~ " + ort[1] if ort and ort[0] in ("<files", "<filesmatch") else "/"
                ziel["weiter"].append((pfad, words[1][6:]))
            elif key == "sethandler" and len(words) > 1 and words[1].lower() in ("server-status", "server-info"):
                status.append((words[1].lower(), ort[1] if ort else "/", vhost, conf))
            elif key in ("require", "allow", "deny", "authtype") and ort and ort[0].startswith("<location"):
                zugriff[ort[1]].append(" ".join(words))
            elif key == "options" and any(w in ("Indexes", "+Indexes") for w in words[1:]):
                bereich = ort[1] if ort else ""
                verzeichnis = bool(ort) and ort[0] == "<directory"
                # Vorgaben der Pakete (Symbole unter /usr/share/apache2) und Verzeichnisse, die es nicht gibt (z.B.
                # SLES-Vorgabe /home/*/public_html ohne Benutzerverzeichnisse; nur auf dem Host prüfbar), zählen nicht
                if (verzeichnis and (under(bereich, "/usr/share/apache2") or (
                        isinstance(c, Host) and not glob.glob(bereich.rstrip("/") or "/")))) \
                        or (module and "autoindex" not in module):
                    continue
                web["web_konf"].append({"id": "WEB-AUTOINDEX", "exe": exe, "site": vhost,
                                        "pfad": "/" if verzeichnis or not bereich else bereich,
                                        "verzeichnis": bereich if verzeichnis else "",
                                        "text": "Apache: Options Indexes (Verzeichnisliste)%s in %s" % (
                                            " für " + bereich if bereich else "", conf)})
    # Websites: vHosts aus -S (Namen, Aliase, Adressen), ergänzt um TLS, Docroots und Weiterleitungen aus dem Block
    vhs = apache_vhosts(s_out)
    sites = []
    for v in vhs:
        b = bloecke.get((v["datei"], v["zeile"])) or {"roots": [], "weiter": [], "ssl": False, "datei": v["datei"]}
        adr = v["adresse"].strip("[]")
        sites.append({"exe": exe, "art": "apache", "namen": [v["name"]] + v["aliase"], "roots": b["roots"],
                      "weiter": b["weiter"], "datei": "%s:%d" % (v["datei"], v["zeile"]), "block": b,
                      "listen": [{"adresse": "*" if adr in ("*", "_default_", "0.0.0.0", "::") else adr,
                                  "port": v["port"], "ssl": b["ssl"]}]})
    if not vhs:                  # -S ohne vHosts bzw. fehlgeschlagen: Blöcke aus den Dateien
        for (datei, zeile), b in sorted(bloecke.items()):
            listen = []
            for a in b["adressen"]:
                adr, _, port = a.rpartition(":") if ":" in a else (a, "", "*")
                listen.append({"adresse": "*" if adr in ("*", "_default_", "0.0.0.0", "[::]") else adr.strip("[]"),
                               "port": port, "ssl": b["ssl"]})
            sites.append({"exe": exe, "art": "apache", "namen": [x for x in [b["name"]] + b["aliase"] if x],
                          "roots": b["roots"], "weiter": b["weiter"], "datei": "%s:%d" % (datei, zeile), "block": b,
                          "listen": listen})
    belegt = {l["port"] for s in sites for l in s["listen"]}
    haupt_listen = [l for l in haupt["listen"] if l["port"] not in belegt]
    for s in sites:              # Port "*" im vHost: alle Listen-Ports
        s["listen"] = [dict(l, port=h["port"]) for l in s["listen"] for h in (haupt["listen"] if l["port"] == "*" else [l])]
    if haupt_listen:             # Hauptserver: Ports ohne vHost
        sites.append({"exe": exe, "art": "apache", "namen": haupt["namen"], "roots": haupt["roots"],
                      "weiter": haupt["weiter"], "datei": "(Hauptserver)", "block": haupt, "haupt": True,
                      "listen": [dict(l, ssl=l["ssl"] or haupt["ssl"] or l["port"] == "443") for l in haupt_listen]})
    web["sites"] += sites
    for k in web["web_konf"]:    # vHost-Block -> Website
        if k["exe"] == exe and k["site"] is not None and "art" not in k["site"]:
            k["site"] = next((s for s in sites if s.get("block") is k["site"]), None)
    for handler, pfad, vhost, datei in status:
        if module and {"server-status": "status", "server-info": "info"}[handler] not in module:
            continue                 # status_module bzw. info_module nicht geladen
        regeln = zugriff.get(pfad, [])
        beschraenkt = [r for r in regeln if not re.match(r"(?i)^require all granted$|^allow from all$|^order ", r)]
        site = next((s for s in sites if vhost is not None and s.get("block") is vhost), None)
        nur_lokal = bool(beschraenkt) and all(APACHE_NUR_LOKAL.match(r) or re.match(r"(?i)^deny from all$", r)
                                              for r in beschraenkt)
        if beschraenkt and not nur_lokal:
            continue
        web["web_konf"].append({"id": "WEB-STATUS", "exe": exe, "site": site, "pfad": pfad, "nur_lokal": nur_lokal,
                                "text": "Apache: %s unter %s %s" % (handler, pfad, "nur für localhost freigegeben (%s)"
                                                                   % "; ".join(beschraenkt) if nur_lokal else
                                                                   "ohne Zugriffsbeschränkung (Require)")})


# Proxys und Weiterleitungen, deren Ziele das Skript nicht (vollständig) aus der Konfiguration liest. Ist einer
# davon erreichbar, gelten alle Container in seinen Docker-Netzen als möglicherweise erreichbar (im Zweifel
# erreichbar). Traefik und caddy-docker-proxy: Ziele aus Docker-Labels werden zusätzlich genau zugeordnet.
PROXY_UNBEKANNT = {"traefik", "caddy", "haproxy", "envoy", "varnishd", "lighttpd", "h2o", "angie", "pound", "hitch",
                   "stunnel", "stunnel4", "socat", "sniproxy", "oauth2-proxy", "squid", "frps"}
# Datenhaltung und Nachrichtenvermittlung: Anwendungen rufen sie auf, leiten aber keine Anfragen von außen
# durch -> Aufrufe (Ziel-URL, offene Verbindung) machen sie nicht erreichbar. Java-Dienste über die Kommandozeile.
DATENDIENST = re.compile(r"(mysqld|mariadbd|postgres|postmaster|redis-server|valkey-server|keydb-server|mongod|mongos|"
                         r"memcached|beam\.smp|clickhouse(-server)?|influxd|etcd|cockroach|couchdb|arangod|rethinkdb|"
                         r"meilisearch|typesense-server|qdrant|nats-server|mosquitto)$")
JAVA_DATENDIENST = re.compile(r"org\.elasticsearch\.|org\.opensearch\.|-Dsolr\.|org\.apache\.solr\.|kafka\.Kafka\b|"
                              r"org\.apache\.cassandra\.|org\.apache\.zookeeper\.|org\.apache\.activemq\.|org\.neo4j\.")
# Kennzeichen der Gründe aus Aufrufen einer erreichbaren Anwendung (für DATENDIENST und die Rückfallregel)
AUFRUF_GRUENDE = ("(Ziel-URL ", "(offene Verbindung)")
ZIEL_URL = re.compile(r"\b(https?|wss?|grpcs?)://(?:[^@\s/'\"]*@)?([^\s/'\",;?#@]+)")


def datendienst(p):
    return bool(DATENDIENST.match(p["base"]) or (p["base"].startswith("java") and JAVA_DATENDIENST.search(" ".join(p["argv"]))))


def aufruf_grund(reason):
    return any(k in reason for k in AUFRUF_GRUENDE)


def aufruf_ziele(ps, web, env):
    """Ziele, die eine erreichbare Anwendung selbst aufruft (z.B. ein API-Gateway): HTTP/WebSocket/gRPC-URLs auf
    andere Container in der Umgebung des Containers (env: [(Name, Wert)]) bzw. der Kommandozeile – mysql://,
    redis:// u.ä. zählen nicht –, dazu bestehende TCP-Verbindungen zu Containern. [(Container, Port, Quelle)]"""
    result = OrderedDict()
    quellen = [("Ziel-URL in der Kommandozeile", " ".join(p["argv"])) for p in ps] + \
        [("Ziel-URL %s" % k, v) for k, v in env]
    for quelle, text in quellen:
        for scheme, hostport in ZIEL_URL.findall(text):
            host, port = split_target(scheme + "://" + hostport)
            ct = web["containers"].get(host)
            if ct and ct != web["self"]:
                result.setdefault((ct, port), quelle)
    for p in ps:
        for addr, port in p.get("verbindungen", ()):
            ct = web["containers"].get(addr)
            if ct and ct != web["self"]:
                result.setdefault((ct, port), "offene Verbindung")
    return [(ct, port, quelle) for (ct, port), quelle in result.items()]


# Tunnel-Agenten: leiten Verkehr aus dem Internet weiter, ohne selbst auf einem Port zu lauschen -> immer erreichbar
TUNNEL = {"cloudflared", "frpc", "ngrok", "chisel"}
LAN_TREIBER = ("macvlan", "ipvlan")     # Container mit eigener Adresse im LAN, ohne veröffentlichte Ports erreichbar
# Kennzeichen im Grund eines Proxy-Ziels per 127.0.0.1/localhost in einem anderen Container, der dasselbe Loopback
# nutzt (Host-Netzwerk, gemeinsamer Netzwerk-Namespace): erreicht auch Dienste, die nur auf Loopback lauschen
LOOPBACK_GRUND = " (über Loopback)"


def docker_lage():
    """docker inspect aller laufenden Container und ihrer Netzwerke: ([Container], {Netzname: Netz})."""
    rc, ids = run(["docker", "ps", "-q"])
    if rc != 0:
        raise ScanError("docker nicht erreichbar (läuft dockerd? Rechte/Gruppe docker?)")
    infos = inspect_liste(["docker", "inspect"], ids.split())
    names = sorted({n for d in infos for n in netze_von(d)})
    return infos, {n.get("Name"): n for n in inspect_liste(["docker", "network", "inspect"], names)}


def inspect_liste(cmd, refs):
    """docker inspect mehrerer Objekte. Ist eines zwischenzeitlich entfernt (z.B. docker run --rm), liefert docker
    die übrigen und Rückgabewert 1 – das ist kein Fehler; ohne gültige Ausgabe schon."""
    if not refs:
        return []
    rc, out = run(cmd + refs)
    try:
        result = json.loads(out or "")
    except ValueError:
        result = None
    if not isinstance(result, list):
        raise ScanError("%s fehlgeschlagen" % " ".join(cmd))
    return result


def name_von(d):
    return (d.get("Name") or "").lstrip("/")


def netze_von(d):
    return list(((d.get("NetworkSettings") or {}).get("Networks") or {}))


def spender_von(d, infos):
    """Container, dessen Netzwerk-Namespace d mitnutzt (network_mode: container:<id> bzw. service:<name>)."""
    mode = (d.get("HostConfig") or {}).get("NetworkMode") or ""
    ref = mode.split(":", 1)[1] if mode.startswith("container:") else ""
    return next((x for x in infos if ref and (x.get("Id", "").startswith(ref) or name_von(x) == ref)), None) if ref else None


def direkt_erreichbar(d, infos, netze):
    """Wie ist Container d ohne Proxy von außerhalb des Docker-Hosts erreichbar (Intranet oder Internet – das ist
    auf dem Server nicht unterscheidbar und wird gleich gewertet)? Bei gemeinsamem Netzwerk-Namespace gilt der
    des Spenders. Liefert ({Port: ["IP:Port"]}, Host-Netzwerk, [LAN-Netze], Name des Spenders oder None)."""
    spender = spender_von(d, infos)
    d = spender or d
    published = defaultdict(list)
    for port, bindings in ((d.get("NetworkSettings") or {}).get("Ports") or {}).items():
        for b in bindings or []:
            ip = b.get("HostIp") or "0.0.0.0"
            key = port.split("/")[0] if port.endswith("/tcp") else port
            published[key].append("%s:%s%s" % (ip, b.get("HostPort"), " (nur lokal – vermutlich hinter "
                                               "einem Reverse Proxy auf dem Host)" if ip in ("127.0.0.1", "::1") else ""))
    lan = []
    for n in netze_von(d):
        net = netze.get(n) or {}
        if net.get("Driver") in LAN_TREIBER:
            lan.append("%s-Netz %s" % (net["Driver"], n))
        for v in ("4", "6"):
            mode = (net.get("Options") or {}).get("com.docker.network.bridge.gateway_mode_ipv" + v)
            if mode in ("routed", "nat-unprotected"):
                lan.append("Netz %s (IPv%s %s)" % (n, v, mode))
    return published, (d.get("HostConfig") or {}).get("NetworkMode") == "host", lan, name_von(spender) if spender else None


def ports_in_gruppe(names, user):
    """Ports, auf denen ein lesbarer Prozess in einem dieser Container lauscht – erfasst wie bei deren eigenem
    Scan, also genau die Ports, die dort bewertet werden."""
    ports = set()
    for name in names:
        try:
            procs = collect_procs(Container(name, user))[0]
        except ScanError:
            continue
        ports.update(port for p in procs.values() for port in p["ports"])
    return ports


def netz_gruppe(d, infos):
    """Andere Container im selben Netzwerk-Namespace wie d (Spender und alle, die ihn mitnutzen)."""
    basis = (spender_von(d, infos) or d).get("Id")
    return sorted({name_von(x) for x in infos if basis and basis in (x.get("Id"), (spender_von(x, infos) or {}).get("Id"))}
                  - {name_von(d)})


def im_host_netz(d, infos):
    return ((spender_von(d, infos) or d).get("HostConfig") or {}).get("NetworkMode") == "host"


def loopback_gruppe(d, infos):
    """Andere Container, die dasselbe Loopback wie d nutzen und dort Ziele per 127.0.0.1/localhost erreichen:
    im Host-Netzwerk alle Container im Host-Netzwerk (und der Host selbst), sonst die im selben
    Netzwerk-Namespace."""
    if im_host_netz(d, infos):
        return sorted({name_von(x) for x in infos if im_host_netz(x, infos)} - {name_von(d)})
    return netz_gruppe(d, infos)


def nachbarn_von(d, infos):
    """Container, die d über ein Docker-Netz direkt erreichen kann; im Host-Netzwerk alle mit einem Docker-Netz
    (der Host erreicht sie über ihre IP)."""
    basis = spender_von(d, infos) or d
    host = (basis.get("HostConfig") or {}).get("NetworkMode") == "host"
    eigene = set(netze_von(basis))
    return sorted({name_von(x) for x in infos
                   if (host and netze_von(spender_von(x, infos) or x)) or eigene & set(netze_von(spender_von(x, infos) or x))}
                  - {name_von(d)})


def label_ziele(proxy, infos):
    """Ziele, die Traefik bzw. caddy-docker-proxy aus den Docker-Labels anderer Container bildet:
    [(Container, Port)], Port "*" = Traefik wählt selbst (einziger freigegebener Port)."""
    result = []
    for d in infos:
        labels = (d.get("Config") or {}).get("Labels") or {}
        ports = []
        if proxy == "traefik" and labels.get("traefik.enable") != "false" and any(k.startswith("traefik.") for k in labels):
            for k, v in sorted(labels.items()):
                m = re.match(r"traefik\.(http|tcp|udp)\.services\.[^.]+\.loadbalancer\.server\.port$", k)
                if m and v.strip().isdigit():
                    ports.append(v.strip() + ("/udp" if m.group(1) == "udp" else ""))
            ports = ports or ["*"]
        elif proxy == "caddy":
            for k, v in sorted(labels.items()):
                if re.match(r"caddy(_\d+)?\.(\d+_)?reverse_proxy$", k):
                    for args in re.findall(r"\{\{\s*upstreams\b([^}]*)\}\}", v):
                        num = [a for a in args.split() if a.isdigit()]
                        ports.append(num[0] if num else "443" if "https" in args.split() else "80")
        result += [(name_von(d), port) for port in OrderedDict.fromkeys(ports)]
    return result


def web_leer():
    return {"docroots": defaultdict(list), "backends": defaultdict(list), "vhosts": defaultdict(list),
            "upstreams": defaultdict(list), "modphp": set(), "raw": [], "published": defaultdict(list), "containers": {},
            "via_proxy": {}, "problems": [], "unlesbar": set(), "label_ziele": {}, "host_network": False, "lan": [],
            "spender": None, "nachbarn": [], "netz_gruppe": [], "loopback": [], "sites": [], "web_konf": []}


def collect_web(c, procs):
    web = web_leer()
    webserver_lesen(c, procs, web)
    infos, netze = docker_lage()
    web["published"], web["host_network"], web["lan"], web["spender"] = direkt_erreichbar(c.info, infos, netze)
    web["nachbarn"] = nachbarn_von(c.info, infos)
    # Container im selben Netzwerk-Namespace (network_mode: container:/service:): lauschen auf denselben Ports
    web["netz_gruppe"] = netz_gruppe(c.info, infos)
    web["loopback"] = loopback_gruppe(c.info, infos)
    if web["host_network"]:
        web["loopback_ziele"] = loopback_ziele(loopback_ports(web), infos, name_von(c.info))
    for proxy in sorted({p["base"] for p in procs.values()} & {"traefik", "caddy"}):
        web["label_ziele"][proxy] = label_ziele(proxy, infos)
    web["containers"] = container_index(infos)
    web["env"] = [tuple(e.split("=", 1)) for e in (c.info.get("Config") or {}).get("Env") or [] if "=" in e]
    return web


def container_index(infos):
    """Namen, Aliase und IPs aller laufenden Container -> Containername (für Backends wie http://app:3000,
    app.netz oder 172.18.0.5)."""
    index = {}
    for d in infos:
        name = name_von(d)
        keys = [name, (d.get("Config") or {}).get("Hostname"),
                ((d.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.service")]
        for netname, net in ((d.get("NetworkSettings") or {}).get("Networks") or {}).items():
            names = [name] + (net.get("Aliases") or []) + (net.get("DNSNames") or [])
            keys += [net.get("IPAddress"), net.get("GlobalIPv6Address")] + names + [k + "." + netname for k in names if k]
        for k in keys:
            if k:
                index.setdefault(k, name)
    return index


def webserver_lesen(c, procs, web):
    """Konfiguration der laufenden nginx- und Apache-Server lesen (im Container bzw. auf dem Host)."""
    for exe in sorted({p["exe"] for p in procs.values() if ist_webserver(p["base"])}):
        masters = server_masters(procs, exe)
        if posixpath.basename(exe) == "nginx":
            # je Masterprozess: dessen -p/-c übernehmen (sonst liest nginx -T eine andere Konfiguration),
            # mit dessen Benutzer
            calls = OrderedDict()
            for p in masters:
                opts = OrderedDict()
                for flag, value in re.findall(r"(?:^|\s)-([cp])\s*([^\s;]+)", " ".join(p["argv"])):
                    opts.setdefault(flag, value)
                args = [x for flag in ("p", "c") if flag in opts for x in ("-" + flag, opts[flag])]
                calls.setdefault((server_user(p), tuple(args)), None)
            for user, args in calls:
                rc, conf = c.exec([exe] + list(args) + ["-T"], timeout=60, user=user)
                if rc != 0 or not conf.strip():
                    web["unlesbar"].add(exe)
                    web["problems"].append("%s %s-T fehlgeschlagen: Konfiguration (vHosts, Proxy-Backends) nicht lesbar"
                                           % (exe, " ".join(args) + " " if args else ""))
                web["raw"].append("--- %s -T (Auszug)\n" % exe + "\n".join(
                    l for l in conf.splitlines() if re.match(r"# configuration file|\s*(server|listen|server_name|root|location|\w+_pass|upstream)[\s;{]", l)))
                parse_nginx(conf, web, exe)
        else:
            # je Hauptprozess mit dessen Benutzer und dessen Optionen (-f, -C, -D …, z.B. SLES: start_apache2)
            for user, optionen in OrderedDict.fromkeys((server_user(p), tuple(apache_optionen(p["argv"])))
                                                       for p in masters):
                parse_apache(c, exe, web, user, optionen)


def resolve_backend(target, web, self_name, depth=0):
    """Backend-Ziel (http://app:3000, fcgi://php:9000, upstream-Name) einem Container zuordnen."""
    host = re.sub(r"^[a-z]+://", "", target).split("/")[0]
    ziel = split_target(target)
    if not target.startswith("unix:") and ziel in web.get("loopback_ziele", {}):
        ziele = [x for x in web["loopback_ziele"][ziel] if x[0] != self_name]
        return target + (" -> " + ", ".join("Container %s, Port %s" % x for x in ziele) if ziele else
                         " (%s)" % ("Host" if self_name == "Host" else "Host bzw. gleicher Container"))
    if target.startswith("unix:") or re.match(r"(localhost|127\.|\[::1\])", host):
        mit = [] if target.startswith("unix:") else web.get("loopback", [])
        return target + " (%s%s)" % ("Host" if self_name == "Host" else "gleicher Container",
                                     "; Loopback gemeinsam mit " + ", ".join(mit) if mit else "")
    host = re.sub(r":\d+$", "", host)
    host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if host in web["upstreams"] and depth < 3:
        return target + " = " + ", ".join(resolve_backend(t, web, self_name, depth + 1) for t in web["upstreams"][host])
    if "$" in host:
        return target + " (Variable, nicht auswertbar)"
    if host in web["containers"]:
        ct = web["containers"][host]
        return target + (" (gleicher Container)" if ct == self_name else " -> Container " + ct)
    return target + " (extern/unbekannt)"


# ===========================================================================
# 7. Zuordnen: welcher laufende Prozess nutzt welche Komponente
# ===========================================================================
def use(c, p):
    lst, lab = (c["aktiv"], p["label"]) if p["ports"] or p["base"] in TUNNEL \
        else (c["aktiv_ohne_port"], p["label"] + " (ohne Port)")
    if lab not in lst:
        lst.append(lab)
    for front in p.get("frontends", ()):     # z.B. php-fpm hinter nginx im selben Container
        lab = "%s (über %s)" % (front, p["base"])
        if lab not in c["aktiv"]:
            c["aktiv"].append(lab)


STANDARDPORTS = {"https": "443", "wss": "443", "grpcs": "443", "ajp": "8009", "fcgi": "8000", "uwsgi": "3031",
                 "scgi": "4000"}


def split_target(target):
    """Backend-Ziel in (Host, Port) zerlegen; Standardport aus dem Schema, sonst 80 (wie nginx bei
    upstream-Servern und *_pass ohne Port)."""
    m = re.match(r"^(?:([a-z0-9]+)://)?([^/]+)", target)
    if not m or target.startswith("unix:"):
        return "", ""
    hostport = m.group(2)
    host, _, port = hostport.rpartition(":") if re.search(r":\d+$", hostport) else (hostport, "", "")
    if host.startswith("[") and host.endswith("]"):      # http://[fd00::2]:8080
        host = host[1:-1]
    return host, port or STANDARDPORTS.get(m.group(1) or "", "80")


def ziel_variabel(target):
    """Enthält Host oder Port eines Ziels eine (nicht aufgelöste) Variable?"""
    return "$" in "".join(split_target(target))


def backend_containers(target, web, depth=0, nur_loopback=False):
    """[(Container, Port)] eines Backend-Ziels, upstream-Namen werden aufgelöst. Ein Ziel per 127.0.0.1/localhost
    trifft auch die Container, die dasselbe Loopback nutzen (nur_loopback: nur diese)."""
    host, port = split_target(target)
    if host in web["upstreams"] and depth < 3:
        return [x for t in web["upstreams"][host] for x in backend_containers(t, web, depth + 1, nur_loopback)]
    if host in web["containers"]:
        return [] if nur_loopback else [(web["containers"][host], port)]
    if re.match(r"(localhost|127\.|::1$)", host):
        if (host, port) in web.get("loopback_ziele", {}):   # zugeordnet: veröffentlichter Port bzw. Prozess
            ziele = web["loopback_ziele"][(host, port)]
            return [x for x in ziele if x[0] in web.get("loopback", [])] if nur_loopback else ziele
        mit = [(ct, port) for ct in web.get("loopback", [])]
        return mit if nur_loopback else [(web["self"], port)] + mit
    return []


def loopback_ports(web):
    """Backend-Ziele per 127.0.0.1/localhost/::1 (auch in upstream-Blöcken) als {(Host, TCP-Port)}."""
    ziele = set()

    def walk(t, depth=0):
        host, port = split_target(t)
        if host in web["upstreams"] and depth < 3:
            for u in web["upstreams"][host]:
                walk(u, depth + 1)
        elif re.match(r"(localhost|127\.|::1$)", host) and port.isdigit():
            ziele.add((host, port))
    for targets in web["backends"].values():
        for t in targets:
            walk(t)
    return ziele


def adresse_passt(bindung, adresse):
    """Erreicht ein Ziel an adresse (127.x.y.z oder ::1) einen Socket bzw. eine Veröffentlichung an bindung? Auf
    allen Adressen ja; "::" im Zweifel auch für IPv4 (Linux nimmt dort ohne IPV6_V6ONLY auch IPv4 an)."""
    return bindung == adresse or bindung == "::" or (bindung == "0.0.0.0" and "." in adresse)


def loopback_ziele(ziele, infos, self_name, proc="/proc"):
    """Ziele (Host, Port) per 127.0.0.1/localhost/::1 im Netzwerk-Namespace des Hosts (Proxy auf dem Host oder in
    einem Container im Host-Netzwerk) zuordnen: {(Host, Port): [(Container, Port im Container)]}. Je Adresse
    (localhost: 127.0.0.1 und ::1) zuerst eine passende Veröffentlichung eines Containers (Docker leitet weiter;
    dieselbe Adresse und denselben Port kann sonst niemand belegen), sonst die Prozesse, die passend lauschen
    (Container nach cgroup, sonst self_name: Host bzw. der Container selbst). Ziele, die nicht vollständig und
    eindeutig zuordenbar sind, fehlen; für sie gilt weiter: alle Container mit demselben Loopback."""
    veroeffentlicht = []
    for d in infos:
        for cport, bindings in ((d.get("NetworkSettings") or {}).get("Ports") or {}).items():
            if cport.endswith("/tcp"):
                veroeffentlicht += [(b.get("HostIp") or "0.0.0.0", b["HostPort"], name_von(d), cport.split("/")[0])
                                    for b in bindings or [] if b.get("HostPort")]
    adressen = {(host, port): ["127.0.0.1", "::1"] if host == "localhost" else [host] for host, port in ziele}
    offen = sorted({(a, port) for (host, port), lst in adressen.items() for a in lst
                    if not any(hp == port and adresse_passt(ip, a) for ip, hp, _, _ in veroeffentlicht)})
    besitzer = socket_besitzer(offen, infos, proc)
    ergebnis = OrderedDict()
    for (host, port), lst in sorted(adressen.items()):
        treffer, ok = [], True
        for a in lst:
            pub = [(ct, cp) for ip, hp, ct, cp in veroeffentlicht if hp == port and adresse_passt(ip, a)]
            if pub:
                treffer += pub
            elif (a, port) in besitzer:
                treffer += [(b or self_name, port) for b in besitzer[(a, port)]]
            else:
                ok = False
        if ok and treffer:      # nichts gefunden (lauscht niemand): Rückfallregel
            ergebnis[(host, port)] = list(OrderedDict.fromkeys(treffer))
    return ergebnis


def socket_besitzer(ziele, infos, proc="/proc"):
    """Wer lauscht im eigenen Netzwerk-Namespace (dem des Hosts) passend für diese Ziele (Adresse, TCP-Port)?
    {(Adresse, Port): [Containername oder None für den Host]} – nur, wenn jeder passende lauschende Socket einem
    lesbaren Prozess gehört und alle zu genau einem Container bzw. zum Host; [] wenn dort nichts lauscht."""
    gesucht, gelesen = defaultdict(set), False      # Inode -> Ziele
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc, "net", name)) as f:
                lines = f.read().splitlines()[1:]
            gelesen = True
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) > 9 and f[3] == "0A" and ":" in f[1] and f[9] != "0":
                addr, port = f[1].split(":")
                ip, port = decode_ip(addr), str(int(port, 16))
                for z in ziele:
                    if z[1] == port and adresse_passt(ip, z[0]):
                        gesucht[f[9]].add(z)
    if not gelesen:
        return {}
    ergebnis = {z: [] for z in ziele if not any(z in zs for zs in gesucht.values())}
    ids = [(d["Id"], name_von(d)) for d in infos if d.get("Id")]
    besitzer, gefunden = defaultdict(set), set()
    for pid in (x for x in os.listdir(proc) if x.isdigit()):
        try:
            links = [os.readlink(os.path.join(proc, pid, "fd", fd)) for fd in os.listdir(os.path.join(proc, pid, "fd"))]
        except OSError:          # nicht lesbar oder beendet
            continue
        inodes = {l[8:-1] for l in links if l.startswith("socket:[") and l[8:-1] in gesucht}
        if not inodes:
            continue
        try:
            with open(os.path.join(proc, pid, "cgroup")) as f:
                cgroup = f.read()
        except OSError:
            continue             # Besitzer unbekannt: Socket bleibt ohne Zuordnung
        gefunden |= inodes
        ct = next((n for i, n in ids if i in cgroup), None)
        for inode in inodes:
            for z in gesucht[inode]:
                besitzer[z].add(ct)
    # jeder passende lauschende Socket muss einem lesbaren Prozess gehören
    unbekannt = {z for inode, zs in gesucht.items() if inode not in gefunden for z in zs}
    ergebnis.update((z, list(b)) for z, b in besitzer.items() if len(b) == 1 and z not in unbekannt)
    return ergebnis


def npm_root(d):
    """Projektverzeichnis eines npm-Pakets; bei global installierten Paketen das globale Paket."""
    if "/node_modules/" not in d:
        return d
    root, rest = d.split("/node_modules/", 1)
    if re.search(r"/lib(/node)?$", root):
        m = re.match(r"(@[^/]+/)?[^/]+", rest)
        root += "/node_modules/" + m.group(0)
    return root or "/"


def mark_usage(comps, procs, owners, web):
    pkg_users = defaultdict(list)   # OS-Paket -> Prozesse, die eine seiner Dateien geladen haben
    for p in procs.values():
        for f in p["maps"] | {p["exe"]}:
            for pkg in owners.get(norm(f), ()):
                if p not in pkg_users[pkg]:
                    pkg_users[pkg].append(p)
    php_servers = [p for p in procs.values() if p["base"].startswith("php-fpm") or
                   (ist_apache(p["base"]) and p["exe"] in web["modphp"])]
    has_docroots = any(web["docroots"].values())
    # Backends im selben Container (z.B. nginx -> php-fpm per localhost:9000 oder Unix-Socket):
    # was sie nutzen, ist über den Webserver erreichbar
    for front in procs.values():
        if not front["ports"]:
            continue
        for t in web["backends"].get(front["exe"], []):
            targets = [p for ct, port in backend_containers(t, web) if ct == web["self"]
                       for p in procs.values() if port in p["ports"]]
            if t.startswith("unix:") and "php" in t:
                targets += [p for p in procs.values() if p["base"].startswith("php-fpm")]
            for p in targets:
                if p is not front and front["label"] not in p.setdefault("frontends", []):
                    p["frontends"].append(front["label"])
    # mehrstufig (nginx -> Apache -> php-fpm im selben Container bzw. auf dem Host): auch die vorderen Webserver
    nach_label = {p["label"]: p for p in procs.values()}
    for _ in range(3):
        for p in procs.values():
            for f in list(p.get("frontends", ())):
                for ff in (nach_label.get(f) or {}).get("frontends", ()):
                    if ff != p["label"] and ff not in p["frontends"]:
                        p["frontends"].append(ff)

    for c in comps:
        t, loc = c["typ"], c["ort"]
        if t == "host":
            c["aktiv"].append("Host")
        elif t == "os-paket":
            for p in pkg_users.get(c["name"], ()):
                use(c, p)
        elif t in ("runtime", "runtime-lib", "php-ext", "server"):
            for p in procs.values():
                if norm(p["exe"]) == norm(loc):
                    use(c, p)
            if posixpath.basename(loc).startswith("php"):
                for p in php_servers:
                    use(c, p)
        elif t == "npm":
            root = npm_root(loc)
            for p in procs.values():
                argv0 = posixpath.basename(p["argv"][0]) if p["argv"] else ""
                if not p["base"].startswith("node") and argv0 not in ("node", "npm", "npx", "yarn"):
                    continue
                scripts = [a if a.startswith("/") else posixpath.join(p["cwd"], a)
                           for a in p["argv"][1:] if a.startswith("/") or re.search(r"\.[cm]?js$", a)]
                if under(p["cwd"], root) or any(under(s, root) for s in scripts) \
                        or (argv0 in ("npm", "npx") and root.endswith("/node_modules/npm")) \
                        or (argv0 == "yarn" and "yarn" in root):
                    use(c, p)
        elif t == "composer":
            for exe, roots in web["docroots"].items():
                if any(under(d, loc) or under(loc, d) for d in roots):
                    for p in procs.values():
                        if p["exe"] == exe or p in php_servers:
                            use(c, p)
            for p in procs.values():
                if p["base"].startswith("php") and p not in php_servers and p["cwd"] != "/" and under(p["cwd"], loc):
                    use(c, p)
            if not c["aktiv"] and not has_docroots:
                for p in php_servers:
                    if p["ports"] and p["label"] + " (Docroot unbekannt)" not in c["aktiv"]:
                        c["aktiv"].append(p["label"] + " (Docroot unbekannt)")
        elif t == "maven":   # JAR von einem Prozess geöffnet (die JVM hält ihre JARs offen)
            jar = loc.split("!/")[0]
            for p in procs.values():
                if jar in p["files"] or jar in p["maps"]:
                    use(c, p)
        elif t == "go":
            for p in procs.values():
                if p["exe"] == loc:
                    use(c, p)
        elif t == "js-lib":  # liegt im Dokumentverzeichnis (oder dessen Projektverzeichnis) eines Webservers
            for exe, roots in web["docroots"].items():
                if any(under(loc, d) or under(loc, posixpath.dirname(d.rstrip("/"))) for d in roots):
                    for p in procs.values():
                        if p["exe"] == exe or p in php_servers:
                            use(c, p)
            if not c["aktiv"] and not has_docroots:
                for p in procs.values():
                    if p["ports"] and ist_webserver(p["base"]) and p["label"] + " (Docroot unbekannt)" not in c["aktiv"]:
                        c["aktiv"].append(p["label"] + " (Docroot unbekannt)")
        elif t == "pypi":
            for p in procs.values():
                hit = any(under(m, loc) for m in p["maps"])        # geladene C-Erweiterung
                if p["base"].startswith("python"):
                    venvs = [a.rsplit("/bin/", 1)[0] for a in p["argv"] if re.match(r"/.+/bin/[^/]+$", a)]
                    if p["env"].get("VIRTUAL_ENV"):
                        venvs.append(p["env"]["VIRTUAL_ENV"])
                    if p["argv"] and "/" not in p["argv"][0]:     # über PATH gestartet, z.B. PATH=/opt/venv/bin:...
                        venvs += [d.rsplit("/bin", 1)[0] for d in p["env"].get("PATH", "").split(":")
                                  if d.endswith("/bin") and d.rsplit("/bin", 1)[0] in web["venvs"]][:1]
                    venvs = [v for v in venvs if v not in ("/usr", "/usr/local")]
                    hit = hit or any(under(loc, v) for v in venvs)
                    prefix = p["exe"].rsplit("/bin/", 1)[0]
                    if not venvs and loc in (prefix + "/lib/" + p["base"] + "/site-packages",
                                             prefix + "/lib/" + p["base"] + "/dist-packages") \
                            or (not venvs and prefix == "/usr" and loc in ("/usr/lib/python3/dist-packages",
                                                                          "/usr/local/lib/" + p["base"] + "/dist-packages")):
                        hit = True
                if hit:
                    use(c, p)

    services = []   # ein Eintrag je Prozess mit offenen Ports (gleiches Etikett nur einmal)
    versions = {norm(c["ort"]): c["version"] for c in comps if c["typ"] in ("runtime", "server")}
    gruppen = OrderedDict()     # gleiches Etikett: Hauptprozess und Worker (erben den lauschenden Socket)
    for p in procs.values():   # auch ohne Port hinter einem Webserver (php-fpm über Unix-Socket)
        if p["ports"] or p["base"] in TUNNEL or p.get("frontends"):
            gruppen.setdefault(p["label"], []).append(p)
    erreichbar = {label: ps[-1]["base"] in TUNNEL or any(port_erreichbar(ps[-1], port, addr, web)[1]
                                                         for port, addr in ps[-1]["ports"].items())
                  for label, ps in gruppen.items()}
    # über einen erreichbaren Webserver im selben Container (auch mehrstufig): Weiterleitungen und Aufrufe zählen
    fronten = {label: {f for p in ps for f in p.get("frontends", ())} for label, ps in gruppen.items()}
    wirkt = dict(erreichbar)
    for _ in gruppen:
        for label in gruppen:
            wirkt[label] = wirkt[label] or any(wirkt.get(f) for f in fronten[label])
    env_vergeben = False
    for label, ps in gruppen.items():
        p = ps[-1]
        desc, exposed = [], erreichbar[label]
        if p["base"] in TUNNEL:
            desc.append("Tunnel-Agent: leitet Verkehr von außen weiter, ohne selbst auf einem Port zu lauschen")
        for port, addr in p["ports"].items():
            desc.append("Port %s (%s) %s" % (port if "/" in port else port + "/tcp", addr,
                                            port_erreichbar(p, port, addr, web)[0]))
        if p.get("frontends"):
            desc.append("hinter " + ", ".join(p["frontends"]) + (" (gleicher Host)" if web.get("ist_host") else
                                                                  " (gleicher Container)"))
        app = [a for i, a in enumerate(p["argv"]) if i and (a.startswith("/") or re.search(r"\.([cm]?js|py|php)$", a)
               or p["argv"][i - 1] in ("-m", "--app", "-w") or re.match(r"[\w.]+:\w+$", a))]
        if app:
            desc.append("Anwendung: " + " ".join(app))
        if p["cwd"] not in ("", "/"):
            desc.append("Arbeitsverzeichnis: " + p["cwd"])
        if web["vhosts"].get(p["exe"]):
            desc.append("Konfiguration: " + " | ".join(web["vhosts"][p["exe"]]))
        for b in OrderedDict.fromkeys(web["backends"].get(p["exe"], [])):
            desc.append("Backend " + resolve_backend(b, web, web["self"]))
        if p["exe"] in web["modphp"]:
            desc.append("PHP als Apache-Modul (mod_php)")
        backends = OrderedDict.fromkeys(web["backends"].get(p["exe"], []))
        ziele = [(ct, port) for b in backends for ct, port in backend_containers(b, web)] + \
            list(web.get("label_ziele", {}).get(p["base"], []))
        ueber_loopback = {x for b in backends for x in backend_containers(b, web, nur_loopback=True)}
        for ct, port in web.get("label_ziele", {}).get(p["base"], []):
            desc.append("Ziel aus Docker-Labels: Container %s, Port %s" % (ct, "alle" if port == "*" else port))
        # Weiterleitungen nicht vollständig bekannt: im Zweifel erreichbar -> alle Container in den Docker-Netzen
        unklar = []
        if wirkt[label]:
            if p["base"] in PROXY_UNBEKANNT or p["base"] in TUNNEL:
                unklar.append("%s: Konfiguration wird nicht ausgewertet" % p["base"])
            if p["exe"] in web.get("unlesbar", ()):
                unklar.append("Konfiguration nicht lesbar")
            unklar += ["Ziel %s" % b for b in backends if ziel_variabel(b)]
        if unklar:
            desc.append("Weiterleitungen nicht vollständig auswertbar (%s) – Container in denselben Docker-Netzen "
                        "gelten als möglicherweise öffentlich: %s" % ("; ".join(unklar), ", ".join(web.get("nachbarn", [])) or "keine"))
            ziele += [(ct, "*") for ct in web.get("nachbarn", [])]
            # dasselbe Loopback (Host-Netzwerk, gemeinsamer Netzwerk-Namespace): auch dort lauschende Dienste
            ziele += [(ct, "*") for ct in web.get("loopback", [])]
            ueber_loopback |= {(ct, "*") for ct in web.get("loopback", [])}
        # Aufrufe der Anwendung (API-Gateway, App ruft internen HTTP-Dienst): auch über einen Webserver im selben
        # Container (php-fpm hinter nginx); die Umgebung des Containers nur einmal zuordnen
        aufrufe = []
        if wirkt[label]:
            bekannt = set(ziele)
            aufrufe = [(ct, port, quelle) for ct, port, quelle in
                       aufruf_ziele(ps, web, [] if env_vergeben else web.get("env", [])) if (ct, port) not in bekannt]
            env_vergeben = True
            for ct, port, quelle in aufrufe:
                desc.append("Aufruf: Container %s, Port %s (%s)" % (ct, port, quelle))
        services.append({"label": label, "name": p["base"], "version": versions.get(norm(p["exe"]), ""), "exe": p["exe"],
                         "description": "; ".join(desc),
                         "endpoints": [("udp://" if port.endswith("/udp") else "tcp://") + e.split(" ")[0]
                                       for port in p["ports"] for e in web["published"].get(port, [])],
                         "exposed": exposed, "unklar": unklar, "frontends": list(p.get("frontends", ())),
                         "ports": OrderedDict((port, port_erreichbar(p, port, addr, web)) for port, addr in p["ports"].items()),
                         # Backends eines öffentlichen Dienstes, die keinem Container zugeordnet werden können
                         # (variable Ziele: siehe unklar)
                         "unresolved": [b for b in backends if wirkt[label] and not backend_containers(b, web)
                                        and not ziel_variabel(b)
                                        and not (b.startswith("unix:") and "php" in b and php_servers)],
                         # öffentlich erreichbare Ziele in anderen Containern (für --oeffentliche/--alle-container)
                         "backends": ([(ct, port, label + (LOOPBACK_GRUND if (ct, port) in ueber_loopback else ""))
                                       for ct, port in OrderedDict.fromkeys(ziele)
                                       if ct != web["self"]] if wirkt[label] else []) +
                                     [(ct, port, "%s (%s)" % (label, quelle)) for ct, port, quelle in aufrufe]})
    return services


def port_erreichbar(p, port, addr, web):
    """(Beschreibung, erreichbar) für einen Port eines Prozesses. Aufrufe einer erreichbaren Anwendung (Ziel-URL,
    offene Verbindung) machen Datenbanken, Caches und Message Broker nicht erreichbar."""
    via = [r for r in web["via_proxy"].get(port, []) if not (datendienst(p) and aufruf_grund(r))]
    if nur_lokal(addr):
        # Loopback erreichen nur Proxys mit demselben Loopback (auf dem Host bzw. in einem Container im
        # Host-Netzwerk, im selben Netzwerk-Namespace) – Docker-Portweiterleitung und andere Container nicht
        lo = [r for r in via if LOOPBACK_GRUND in r]
        if lo:
            return "lauscht nur auf Loopback, öffentlich über " + ", ".join(lo), True
        lo = [r for r in web["via_proxy"].get("*", []) if LOOPBACK_GRUND in r]
        if lo:
            return "lauscht nur auf Loopback, möglicherweise öffentlich über " + ", ".join(lo) + \
                " (Weiterleitungen dort nicht vollständig auswertbar)", True
        return "lauscht nur auf Loopback – von außen nicht erreichbar" + (
            " (obwohl veröffentlicht als %s)" % ", ".join(web["published"][port]) if web["published"].get(port) else ""), False
    if web.get("ist_host"):
        return host_port_erreichbar(p, port, addr, web)
    if web["published"].get(port):
        return "veröffentlicht als " + ", ".join(web["published"][port]) + (
            " (über Container %s)" % web["spender"] if web.get("spender") else ""), True
    if web["host_network"] and not nur_lokal(addr):
        return "direkt im Host-Netzwerk erreichbar", True
    if web.get("lan") and not nur_lokal(addr):
        return "direkt erreichbar im " + ", ".join(web["lan"]), True
    if via:
        return "öffentlich über " + ", ".join(via), True
    if web["via_proxy"].get("*") and not nur_lokal(addr):
        return "möglicherweise öffentlich über " + ", ".join(web["via_proxy"]["*"]) + \
            " (Weiterleitungen dort nicht vollständig auswertbar)", True
    if web["via_proxy"].get(port):
        return "nicht veröffentlicht; aufgerufen von " + ", ".join(web["via_proxy"][port]) + \
            " (Datenbank/Cache/Message Broker: dadurch nicht erreichbar)", False
    return "nicht veröffentlicht", False


# ===========================================================================
# 7b. Erreichbarkeit auf dem Host: Netzwerkschnittstellen und firewalld
# ===========================================================================
# Schnittstellen zu Containern und Pods: Verkehr von dort kommt nicht von außerhalb des Hosts
CONTAINER_NETZ = re.compile(r"(lo|docker\d*|br-[0-9a-f]{12}|veth.*|podman\d*|cni.*|cali.*|flannel.*|cilium.*|kube-.*)$")


def schnittstellen():
    """Adressen je Netzwerkschnittstelle aus 'ip -o addr': [(Name, Adresse)]; None, wenn nicht lesbar."""
    rc, out = run(["ip", "-o", "addr", "show"], timeout=30)
    if rc != 0:
        return None
    result = []
    for line in out.splitlines():
        f = line.split()
        if len(f) > 3 and f[2] in ("inet", "inet6"):
            result.append((f[1].split("@")[0], f[3].split("/")[0]))
    return result


def firewalld_bloecke(out):
    """Ausgabe von --list-all-zones/--list-all-policies: {Name: {Schlüssel: [Werte]}} (Rich Rules und
    Forward-Ports je Zeile)."""
    result, cur, key = OrderedDict(), None, None
    for line in out.splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            name = line.split()[0]
            cur = result.setdefault(name, {"_kopf": [line]})
            key = None
        elif cur is not None:
            m = re.match(r"^\s{1,2}([\w-]+( [\w-]+)?):\s*(.*)$", line)
            if m and not line.startswith("\t"):
                key = m.group(1)
                cur[key] = [m.group(3).strip()] if key in ("rich rules", "forward-ports") and m.group(3).strip() \
                    else ([] if key in ("rich rules", "forward-ports") else m.group(3).split())
            elif key in ("rich rules", "forward-ports"):
                cur[key].append(line.strip())
    return result


def firewall_lesen():
    """Runtime-Konfiguration von firewalld (nicht die permanente). Ergebnis: {"aktiv": False} ohne firewalld;
    {"aktiv": True, "fehler": …} wenn nicht abfragbar; sonst Zonen, Zuordnung der Schnittstellen, Policies und
    Dienste. Andere Paketfilter (nftables/iptables direkt) werden nicht ausgewertet (Hinweis)."""
    def fwcmd(*args):
        return run(["firewall-cmd"] + list(args), timeout=60)
    rc, state = fwcmd("--state")
    if rc == 127 or (rc != 0 and not any(p for p in _prozesse_namens("firewalld"))):
        hinweis = ""
        if run(["nft", "list", "ruleset"], timeout=30)[1].count("\n") > 2 or \
                re.search(r"^-A ", run(["iptables", "-S"], timeout=30)[1], re.M):
            hinweis = "Paketfilter ohne firewalld (nftables/iptables) nicht ausgewertet – Ports gelten als offen"
        return {"aktiv": False, "hinweis": hinweis}
    if rc != 0 or state.strip() != "running":
        return {"aktiv": True, "fehler": "firewall-cmd --state: %s" % (state.strip() or "Fehler")}
    default = fwcmd("--get-default-zone")[1].strip()
    zonen = firewalld_bloecke(fwcmd("--list-all-zones")[1])
    rc, pol = fwcmd("--list-all-policies")
    policies = firewalld_bloecke(pol) if rc == 0 else {}
    zuordnung, quellen = {}, OrderedDict()
    for name, z in zonen.items():
        for i in z.get("interfaces", []):
            zuordnung[i] = name
        if z.get("sources"):
            quellen[name] = z["sources"]
    dienste = {}

    def dienst(name, tiefe=0):
        if name not in dienste:
            dienste[name] = {"ports": [], "protocols": [], "source-ports": []}
            info = firewalld_bloecke(name + "\n" + fwcmd("--info-service=" + name)[1]).get(name, {})
            dienste[name] = {k: info.get(k, []) for k in ("ports", "protocols", "source-ports")}
            for inc in info.get("includes", []) if tiefe < 5 else []:
                for k, v in dienst(inc, tiefe + 1).items():
                    dienste[name][k] = dienste[name][k] + v
        return dienste[name]
    for block in list(zonen.values()) + list(policies.values()):
        for name in block.get("services", []):
            dienst(name)
        for regel in block.get("rich rules", []):
            for name in re.findall(r'service name="([^"]+)"', regel):
                dienst(name)
    direkt = fwcmd("--direct", "--get-all-rules")[1].strip()
    return {"aktiv": True, "default": default, "zonen": zonen, "policies": policies, "zuordnung": zuordnung,
            "quellen": quellen, "dienste": dienste,
            "hinweis": "direkte Regeln (firewall-cmd --direct) nicht ausgewertet" if direkt else ""}


def _prozesse_namens(name, proc="/proc"):
    result = []
    for pid in (x for x in os.listdir(proc) if x.isdigit()):
        try:
            with open(os.path.join(proc, pid, "comm")) as f:
                if f.read().strip() == name:
                    result.append(pid)
        except OSError:
            continue
    return result


def port_in_liste(port, proto, liste):
    """Port/Protokoll in einer firewalld-Liste ("80/tcp", "8000-8100/tcp")?"""
    for x in liste:
        p, _, pr = x.partition("/")
        lo, _, hi = p.partition("-")
        if pr == proto and lo.isdigit() and int(lo) <= int(port) <= int(hi or lo):
            return True
    return False


def firewalld_block_offen(block, port, proto, fw):
    """Lässt eine Zone bzw. Policy Verkehr zu diesem Port durch? Liefert eine Beschreibung oder ""."""
    if (block.get("target") or [""])[0] == "ACCEPT":
        return "Target ACCEPT"
    if proto in block.get("protocols", []):
        return "Protokoll %s freigegeben" % proto
    if port_in_liste(port, proto, block.get("ports", [])):
        return "Port %s/%s freigegeben" % (port, proto)
    for name in block.get("services", []):
        d = fw["dienste"].get(name, {})
        if port_in_liste(port, proto, d.get("ports", [])) or proto in d.get("protocols", []):
            return "Dienst %s" % name
    if block.get("source-ports"):
        return "Quellports %s freigegeben (damit alle Ports erreichbar)" % " ".join(block["source-ports"])
    for f in block.get("forward-ports", []):
        kv = dict(x.partition("=")[::2] for x in f.split(":"))
        if kv.get("proto") == proto and not kv.get("toaddr") and (kv.get("toport") or kv.get("port")) == port:
            return "Weiterleitung von Port %s" % kv.get("port")
    for regel in block.get("rich rules", []):
        if not re.search(r"\baccept\b", regel) or re.search(r"\b(icmp-type|icmp-block|forward-port|masquerade)\b", regel):
            continue
        m = re.search(r'(?:^|\s)port port="?(\d+)(?:-(\d+))?"? protocol="?(\w+)', regel)
        s = re.search(r'service name="([^"]+)"', regel)
        pr = re.search(r'(?:^|\s)protocol value="?(\w+)', regel)
        if m:
            passt = m.group(3) == proto and int(m.group(1)) <= int(port) <= int(m.group(2) or m.group(1))
        elif s:
            d = fw["dienste"].get(s.group(1), {})
            passt = port_in_liste(port, proto, d.get("ports", [])) or proto in d.get("protocols", [])
        elif pr:
            passt = pr.group(1) == proto
        else:
            passt = True             # Regel ohne Port/Dienst: alle Ports
        if passt:
            quelle = re.search(r'source (NOT )?(?:address|ipset|mac)="?([^"\s]+)', regel)
            return "Rich Rule%s" % (" (Quelle %s%s)" % ("nicht " if quelle.group(1) else "", quelle.group(2))
                                    if quelle else "")
    return ""


def host_port_erreichbar(p, port, addr, web):
    return host_port_pruefen(p, port, addr, web)[:2]


def host_port_pruefen(p, port, addr, web):
    """(Beschreibung, erreichbar, für jede Quelle) für einen Port eines Prozesses direkt auf dem Host: über
    Schnittstellen außer Loopback und Container-Netzen, sofern firewalld ihn durchlässt. Im Zweifel erreichbar
    (firewalld nicht abfragbar, Adresse keiner Schnittstelle zuordenbar, andere Paketfilter). "für jede Quelle":
    nicht nur für bestimmte Quelladressen (Rich Rule mit source, Zone mit Quellen)."""
    if p["base"] in ("docker-proxy", "rootlessport"):
        return "veröffentlichter Port eines Containers (Docker leitet an der Firewall vorbei weiter)", True, True
    num, _, proto = port.partition("/")
    proto = proto or "tcp"
    bindungen = p.get("bindungen", {}).get(port) or (["0.0.0.0", "::"] if addr == "alle" else [addr])
    bindungen = [b for b in bindungen if not nur_lokal(b) and b != "::1"]
    ifaces = web.get("interfaces")
    if ifaces is None:
        return "an %s (Schnittstellen nicht lesbar – als erreichbar gewertet)" % ", ".join(bindungen), True, True
    ziele = OrderedDict()
    for b in bindungen:
        if b in ("0.0.0.0", "::"):
            for name, ip in ifaces:
                if not CONTAINER_NETZ.match(name) and (b == "::" or ":" not in ip):
                    ziele.setdefault(name, []).append(ip)
        else:
            name = next((n for n, ip in ifaces if ip == b), None)
            if name is None:
                return "an %s (keiner Schnittstelle zugeordnet – als erreichbar gewertet)" % b, True, True
            if not CONTAINER_NETZ.match(name):
                ziele.setdefault(name, []).append(b)
    wo = "an allen Adressen" if any(b in ("0.0.0.0", "::") for b in bindungen) else "an " + ", ".join(bindungen)
    if not ziele:
        return "%s, aber nur über Container-Netze bzw. Loopback – von außen nicht erreichbar" % wo, False, False
    fw = web.get("firewall") or {"aktiv": False}
    if not fw["aktiv"]:
        return "%s (%s)" % (wo, fw.get("hinweis") or "keine Firewall aktiv"), True, True
    if fw.get("fehler"):
        return "%s (firewalld nicht abfragbar: %s – als erreichbar gewertet)" % (wo, fw["fehler"]), True, True
    offen = []
    for name in ziele:
        zone = fw["zuordnung"].get(name) or fw["default"]
        grund = firewalld_block_offen(fw["zonen"].get(zone, {}), num, proto, fw)
        if grund:
            offen.append(("%s: Zone %s, %s" % (name, zone, grund), "(Quelle " not in grund))
    for zone, quellen in fw["quellen"].items():
        grund = firewalld_block_offen(fw["zonen"].get(zone, {}), num, proto, fw)
        if grund:
            offen.append(("Zone %s für %s, %s" % (zone, " ".join(quellen), grund), False))
    for name, pol in fw["policies"].items():
        kopf = pol.get("_kopf", [""])[0]
        if "HOST" in pol.get("egress-zones", []) and ("(active)" in kopf or "(" not in kopf):
            grund = firewalld_block_offen(pol, num, proto, fw)
            if grund:
                offen.append(("Policy %s, %s" % (name, grund), "(Quelle " not in grund))
    hinweis = " (%s)" % fw["hinweis"] if fw.get("hinweis") else ""
    if offen:
        return "%s, firewalld lässt durch: %s%s" % (wo, "; ".join(o for o, _ in offen), hinweis), True, \
            any(frei for _, frei in offen)
    zonen = sorted({fw["zuordnung"].get(n) or fw["default"] for n in ziele})
    return "%s, aber von firewalld gesperrt (Zone %s)%s" % (wo, ", ".join(zonen), hinweis), False, False


# ===========================================================================
# 7a. Webadressen und Einstellungen der Webserver
# ===========================================================================
def site_urls(site, web):
    """Webadressen einer Website (eine je Name und Adresse): Schema aus TLS, Name aus server_name/ServerName/
    ServerAlias, Port – im Container der veröffentlichte Port des Hosts, falls vorhanden. Ohne Namen: der Name des
    Hosts (beim Scan des Hosts) bzw. "*" (jeder Name)."""
    namen = []
    for n in site["namen"]:
        if n.startswith("~"):            # regulärer Ausdruck (nginx): nicht als Adresse darstellbar
            continue
        namen += [n[1:], "*" + n] if n.startswith(".") else [n]
    namen = list(OrderedDict.fromkeys(namen)) or [web.get("fqdn") or "*"]
    urls = []
    for l in site["listen"]:
        schema = "https" if l["ssl"] else "http"
        port = l["port"]
        pub = [e.split(" ")[0].rpartition(":")[2] for e in web["published"].get(port, [])]
        port = pub[0] if pub else port
        for n in namen:
            urls.append("%s://%s%s/" % (schema, n, "" if port == {"http": "80", "https": "443"}[schema] else ":" + port))
    return list(OrderedDict.fromkeys(urls))


def url_pfad(url, pfad):
    """Webadresse und Pfad einer Weiterleitung: Präfix anhängen, reguläre Ausdrücke in Klammern."""
    m = re.match(r"^(?:= |\^~ )?(/\S*)$", pfad or "/")
    if m:
        return url if m.group(1) == "/" else url.rstrip("/") + m.group(1)
    return "%s (%s)" % (url, re.sub(r"^~\*?\s*", "", pfad))


def dienst_sites(svc, web):
    """Websites des Webservers eines Dienstes, an deren Ports der Dienst lauscht."""
    return [s for s in web.get("sites", []) if s["exe"] == svc.get("exe")
            and any(l["port"] in svc.get("ports", {}) for l in s["listen"])]


def webadressen(services, web):
    """Webadressen je Dienst (svc["webadressen"] = [{"url", "erreichbar", "weg", "site"}]): die eigenen Websites
    (an Ports, an denen er lauscht) und die Pfade, die ein Webserver im selben Container bzw. auf demselben Host an
    ihn weiterleitet (auch mehrstufig: nginx -> Apache -> php-fpm). "erreichbar" wie der Port, über den die Anfrage
    hereinkommt; "site" nur bei eigenen Websites."""
    for svc in services:
        svc["webadressen"] = []
        for site in dienst_sites(svc, web):
            for l in site["listen"]:
                if l["port"] not in svc["ports"]:
                    continue
                desc, offen = svc["ports"][l["port"]]
                for url in site_urls(dict(site, listen=[l]), web):
                    svc["webadressen"].append({"url": url, "erreichbar": offen, "weg": svc["label"], "site": site})
    ziel_von = {}            # (Port) -> Dienst im selben Container bzw. auf dem Host
    for svc in services:
        for port in svc.get("ports", {}):
            ziel_von.setdefault(port, svc)
    php = [svc for svc in services if svc.get("name", "").startswith("php-fpm")]
    for _ in range(3):       # Weiterleitungen, auch über mehrere Stufen
        neu = False
        for front in services:
            for site in dienst_sites(front, web):
                eintraege = [e for e in front["webadressen"] if e["site"] is site or e["site"] is None]
                for pfad, ziel in site["weiter"]:
                    backs = [ziel_von.get(port) for ct, port in backend_containers(ziel, web) if ct == web["self"]]
                    if ziel.startswith("unix:") and "php" in ziel:
                        backs += php
                    for back in [b for b in backs if b and b is not front]:
                        vorhanden = {e["url"] for e in back["webadressen"]}
                        for e in eintraege:
                            url = url_pfad(e["url"], pfad)
                            if url not in vorhanden:
                                back["webadressen"].append({"url": url, "erreichbar": e["erreichbar"],
                                                            "weg": e["weg"] + " → " + back["label"], "site": None})
                                vorhanden.add(url)
                                neu = True
        if not neu:
            break
    for svc in services:
        svc["webadressen"].sort(key=lambda e: not e["erreichbar"])


def komponenten_webadressen(comps, services):
    """Webadressen je Komponente (c["webadressen"]): die der Dienste, die sie direkt nutzen. Bibliotheken und
    Pakete im Dokumentverzeichnis (JavaScript, Composer): bei eigenen Websites nur die, deren Docroot passt."""
    by_label = {svc["label"]: svc for svc in services}

    def passt(c, site, genau):
        return any(under(c["ort"], r.rstrip("/")) or under(r.rstrip("/"), c["ort"]) or
                   (not genau and under(c["ort"], posixpath.dirname(r.rstrip("/")))) for r in site["roots"])
    for c in comps:
        urls = OrderedDict()
        svcs = [by_label[a.split(" (")[0]] for a in c["aktiv"] if "(über " not in a and a.split(" (")[0] in by_label]
        if c["typ"] in ("js-lib", "composer"):
            # Datei im Docroot: die Websites mit diesem Docroot (sonst dem Projektverzeichnis darüber) und was ein
            # Proxy an deren Dienst weiterleitet; ein Dienst ohne eigene Website (php-fpm) liefert sie nicht aus
            sites = [e["site"] for s in svcs for e in s.get("webadressen", []) if e["site"] is not None]
            genau = any(passt(c, site, True) for site in sites)
            treffer = []
            for s in svcs:
                eigen = [e for e in s.get("webadressen", []) if e["site"] is not None and passt(c, e["site"], genau)]
                treffer += eigen + ([e for e in s.get("webadressen", []) if e["site"] is None] if eigen else [])
        else:
            treffer = [e for s in svcs for e in s.get("webadressen", [])]
        for e in treffer:
            urls[e["url"]] = urls.get(e["url"]) or e["erreichbar"]
        c["webadressen"] = sorted(urls, key=lambda u: not urls[u])
        c["webadressen_erreichbar"] = [u for u in c["webadressen"] if urls[u]]


def webadressen_text(urls, limit=3):
    return ", ".join(urls[:limit]) + (" (+%d)" % (len(urls) - limit) if len(urls) > limit else "")


def webserver_pruefen(services, web):
    """Einstellungen der Webserver (WEB-…), die Informationen preisgeben: Statusseiten ohne Zugriffsbeschränkung
    (auch "nur localhost", wenn ein Proxy davor die Anfragen von 127.0.0.1 weiterleitet), Verzeichnislisten. Relevant
    nur, wenn der Webserver erreichbar ist. Paket für die Ausnahmeliste: Name der Website (erster Name), sonst das
    Programm. Liefert Funde wie konfiguration_pruefen, dazu "art" und "erreichbar"."""
    funde = []
    for k in web.get("web_konf", []):
        svcs = [s for s in services if s.get("exe") == k["exe"]]
        eigen = [e for s in svcs for e in s.get("webadressen", []) if k["site"] is None or e["site"] is k["site"]]
        ueber_proxy = [e for s in svcs for e in s.get("webadressen", []) if e["site"] is None and e["erreichbar"]]
        erreichbar = any(e["erreichbar"] for e in eigen) or bool(ueber_proxy) or (
            k["site"] is None and any(s["exposed"] for s in svcs))
        text = k["text"]
        if k.get("nur_lokal"):
            if not ueber_proxy:
                continue
            text += " – davor leitet ein Proxy Anfragen von dieser Maschine weiter (%s), damit greift die " \
                    "Beschränkung nicht" % webadressen_text([e["url"] for e in ueber_proxy], 2)
        urls = [e["url"] for e in eigen] or [e["url"] for e in ueber_proxy]
        pfad = k["pfad"]
        if k.get("verzeichnis"):       # Verzeichnis -> Pfad unterhalb des Docroots der Website (sonst unbekannt)
            roots = (k["site"] or {}).get("roots") or [r for s in svcs for site in dienst_sites(s, web) for r in site["roots"]]
            pfad = "/"
            for r in roots:
                if under(k["verzeichnis"].rstrip("/"), r.rstrip("/")):
                    rel = posixpath.relpath(k["verzeichnis"].rstrip("/"), r.rstrip("/"))
                    pfad = "/" if rel == "." else "/" + rel + "/"
                    break
        if urls:
            text += " – Webadressen: " + webadressen_text(list(OrderedDict.fromkeys(url_pfad(u, pfad) for u in urls)))
        site = k["site"]
        funde.append({"id": k["id"], "pkg": (site["namen"][0] if site and site["namen"] else posixpath.basename(k["exe"])),
                      "text": text, "quelle": "%s %s" % (site["datei"] if site else k["exe"], k["pfad"]),
                      "art": "web", "erreichbar": erreichbar})
    return funde


# TLS-Versionen am Dienst selbst prüfen (nur beim Scan des Hosts): ob TLS 1.0/1.1 tatsächlich angenommen wird,
# entscheiden Konfiguration, OpenSSL-Version und systemweite Vorgaben (crypto-policies) zusammen – die Konfiguration
# allein reicht nicht. Eigener Prozess ohne OpenSSL-Konfiguration (OPENSSL_CONF=/dev/null), damit die Vorgaben des
# Systems nicht schon den Client einschränken; SECLEVEL=0 erlaubt die alten Verfahren auf Seite des Clients.
# Nur ASCII: Python 3.6 mit leerer Umgebung (env -i, ohne LANG) kann eine Kommandozeile mit Umlauten nicht lesen.
TLS_PRUEFUNG = r"""
import json, socket, ssl, sys, warnings
warnings.simplefilter("ignore")
host, port, sni = sys.argv[1], int(sys.argv[2]), sys.argv[3] or None
out = {}
for name in ("TLSv1", "TLSv1.1"):
    try:
        if hasattr(ssl, "TLSVersion"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            v = ssl.TLSVersion.TLSv1 if name == "TLSv1" else ssl.TLSVersion.TLSv1_1
            ctx.minimum_version = ctx.maximum_version = v
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1 if name == "TLSv1" else ssl.PROTOCOL_TLSv1_1)
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            ctx.set_ciphers("ALL")
    except (AttributeError, ValueError, ssl.SSLError) as e:
        out[name] = "nicht pr\u00fcfbar: %s" % e
        continue
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as t:
                out[name] = "angenommen" if t.version() == name else "abgelehnt"
    except ssl.SSLError as e:
        grund = getattr(e, "reason", None) or str(e)
        out[name] = "nicht pr\u00fcfbar: %s" % grund if grund in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE") \
            else "abgelehnt"
    except (OSError, ValueError) as e:
        out[name] = "nicht pr\u00fcfbar: %s" % e
sys.stdout.write(json.dumps(out))
"""


def tls_pruefen(c, services, web, python=None):
    """Nimmt ein erreichbarer TLS-Port TLS 1.0 oder 1.1 an? Je Adresse und Port eine Prüfung (Name der ersten
    Website als SNI), als nobody. Liefert (Funde WEB-TLS-ALT, Warnungen)."""
    funde, warnungen, gesehen = [], [], set()
    python = python or sys.executable
    for svc in services:
        for site in dienst_sites(svc, web):
            for l in site["listen"]:
                if not l["ssl"] or l["port"] not in svc["ports"] or not svc["ports"][l["port"]][1]:
                    continue
                adressen = [l["adresse"]] if l["adresse"] not in ("*", "::") else \
                    ["::1"] if l["adresse"] == "::" else ["127.0.0.1", "::1"]
                if (adressen[0], l["port"]) in gesehen:
                    continue
                gesehen.add((adressen[0], l["port"]))
                sni = next((n for n in site["namen"] if re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*$", n)), "")
                ergebnis = {}
                for adr in adressen:
                    rc, out = c.exec(["env", "OPENSSL_CONF=/dev/null", python, "-I", "-c", TLS_PRUEFUNG, adr, l["port"],
                                      sni], user=NOBODY, timeout=60)
                    try:
                        ergebnis = json.loads(out) if rc == 0 else {}
                    except ValueError:
                        ergebnis = {}
                    if ergebnis and not all(v.startswith("nicht prüfbar: [Errno") or "refused" in v
                                            for v in ergebnis.values()):
                        break
                alt = [v for v in ("TLSv1", "TLSv1.1") if ergebnis.get(v) == "angenommen"]
                offen = [e["url"] for e in svc["webadressen"] if e["site"] is site]
                if alt:
                    funde.append({"id": "WEB-TLS-ALT", "pkg": site["namen"][0] if site["namen"] else svc["name"],
                                  "text": "%s nimmt %s an (veraltet, ohne Sicherheitsupdates; ssl_protocols bzw. "
                                          "SSLProtocol auf TLSv1.2 TLSv1.3 setzen) – geprüft an %s:%s – Webadressen: %s"
                                          % (svc["label"], " und ".join({"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}[v] for v in alt), adr,
                                             l["port"], webadressen_text(offen)),
                                  "quelle": "%s:%s" % (adr, l["port"]), "art": "web", "erreichbar": True})
                elif not ergebnis or any(v.startswith("nicht prüfbar") for v in ergebnis.values()):
                    warnungen.append("TLS-Versionen an Port %s (%s) nicht prüfbar: %s" % (
                        l["port"], svc["label"], "; ".join("%s %s" % kv for kv in sorted(ergebnis.items()))
                        or "Prüfung fehlgeschlagen"))
    return funde, warnungen


# ===========================================================================
# 8. CycloneDX 1.5
# ===========================================================================
PURL_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_~")
CPE = {"node": "nodejs:node.js", "php": "php:php", "python": "python:python", "nginx": "f5:nginx",
       "apache-httpd": "apache:http_server", "openssl": "openssl:openssl", "curl": "haxx:curl",
       "libxml2": "xmlsoft:libxml2", "sqlite": "sqlite:sqlite", "expat": "libexpat_project:libexpat",
       "zlib": "zlib:zlib", "nghttp2": "nghttp2:nghttp2", "undici": "nodejs:undici", "ares": "c-ares:c-ares",
       "llhttp": "llhttp:llhttp", "runc": "linuxfoundation:runc", "containerd": "linuxfoundation:containerd",
       "docker-engine": "docker:docker", "java": "oracle:openjdk", "mariadb": "mariadb:mariadb",
       "mysql": "oracle:mysql", "postgresql": "postgresql:postgresql"}


def penc(s):
    return "".join(ch if ch in PURL_SAFE else "".join("%%%02X" % b for b in ch.encode("utf-8")) for ch in s)


def split_name(name):   # "@scope/name" bzw. "vendor/name" -> "%40scope/name"
    return "/".join(penc(x) for x in name.split("/", 1))


def cdx_component(i, c, osinfo):
    props = []

    def prop(name, value):
        if value:
            props.append({"name": name, "value": value})

    entry = OrderedDict([("bom-ref", "c%d" % i), ("type", "library"), ("name", c["name"]), ("version", c["version"])])
    t = c["typ"]
    if t == "os-paket":
        osid = osinfo["id"]
        ptype = "deb" if osid in ("debian", "ubuntu") else "apk" if osid == "alpine" else "rpm"
        ns = "opensuse" if osid.startswith("opensuse") else "suse" if osid.startswith("sle") else osid
        version, quals = c["version"], [("arch", c.get("arch", ""))]
        m = re.match(r"(\d+):(.*)", version)
        if m:
            quals.append(("epoch", m.group(1)))
            version = m.group(2)
        if c.get("src") and c["src"] != c["name"]:
            quals.append(("upstream", c["src"]))
        quals.append(("distro", "%s-%s" % (osid, osinfo["version"])))
        entry["purl"] = "pkg:%s/%s/%s@%s?%s" % (ptype, penc(ns), penc(c["name"]), penc(version),
                                                "&".join("%s=%s" % (k, penc(v)) for k, v in quals if v))
        # Quellpaket so, wie Trivy es auswertet (Debian/Alpine/SUSE führen CVEs je Quellpaket)
        sv, se, sr = c.get("srcver") or c["version"], "", ""
        if ptype != "apk":
            m = re.match(r"(\d+):(.*)", sv)
            if m:
                se, sv = m.groups()
            if "-" in sv:
                sv, sr = sv.rsplit("-", 1)
        for k, v in (("SrcName", c.get("src") or c["name"]), ("SrcVersion", sv), ("SrcRelease", sr), ("SrcEpoch", se)):
            prop("aquasecurity:trivy:" + k, v)
        c["hinweise"] = ["arch=" + c.get("arch", "")] + (["src=" + c["src"]] if c.get("src") != c["name"] else []) + c["hinweise"]
    elif t == "npm":
        entry["purl"] = "pkg:npm/%s@%s" % (split_name(c["name"]), penc(c["version"]))
    elif t == "composer":
        entry["purl"] = "pkg:composer/%s@%s" % (split_name(c["name"]), penc(c["version"]))
    elif t == "js-lib" and c["version"] != "unbekannt":
        entry["purl"] = "pkg:npm/%s@%s" % (split_name(c["name"]), penc(c["version"]))
    elif t == "maven" and not c.get("maven_key"):
        g, a = c["name"].split(":", 1)
        entry["purl"] = "pkg:maven/%s/%s@%s" % (penc(g), penc(a), penc(c["version"]))
    elif t == "go":
        entry["purl"] = "pkg:golang/%s@%s" % ("/".join(penc(x) for x in c["name"].split("/")), penc(c["version"]))
    elif t in ("js-lib", "maven"):
        pass   # ohne eindeutige Paket-URL
    elif t == "pypi":
        entry["purl"] = "pkg:pypi/%s@%s" % (penc(re.sub(r"[-_.]+", "-", c["name"].lower())), penc(c["version"]))
    elif t == "host" and c["name"] == "linux-kernel":
        entry["type"] = "platform"
    else:
        entry["purl"] = "pkg:generic/%s%s@%s" % ("php-ext-" if t == "php-ext" else "", penc(c["name"]), penc(c["version"]))
        if t in ("runtime", "server"):
            entry["type"] = "application"
        if c["name"] in CPE and t != "php-ext":
            entry["cpe"] = "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*" % (CPE[c["name"]], c["version"].lstrip("v"))
    if c.get("dev"):
        entry["scope"] = "optional"
        c["hinweise"].append("dev")
    prop("container-security-scan:typ", t)
    prop("container-security-scan:fundort", c["ort"])
    prop("container-security-scan:hinweis", "; ".join(h for h in c["hinweise"] if h))
    prop("container-security-scan:aktiv", aktiv(c))
    entry["properties"] = props
    return entry


def aktiv(c, limit=4):
    labels = c["aktiv"] or c["aktiv_ohne_port"]
    return ";".join(labels if len(labels) <= limit else labels[:3] + ["… (+%d)" % (len(labels) - 3)])


def write_cdx(path, c, osinfo, comps, services):
    host = isinstance(c, Host)
    img = "" if host else c.info["Image"]
    rc, out = (1, "") if host else run(["docker", "image", "inspect", img])
    digests = (json.loads(out)[0].get("RepoDigests") or []) if rc == 0 else []
    components = [OrderedDict([("bom-ref", "os"), ("type", "operating-system"), ("name", osinfo["id"]),
                               ("version", osinfo["version"]), ("description", osinfo["pretty"])])]
    components += [cdx_component(i, x, osinfo) for i, x in enumerate(comps, 1)]
    bom = OrderedDict([
        ("bomFormat", "CycloneDX"), ("specVersion", "1.5"), ("serialNumber", "urn:uuid:%s" % uuid.uuid4()), ("version", 1),
        ("metadata", {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "container-security-scan.py", "version": VERSION}]},
            "component": {"bom-ref": "host", "type": "device", "name": c.name,
                          "properties": [{"name": "container-security-scan:kernel", "value": os.uname().release}]}
            if host else
                         {"bom-ref": "container", "type": "container", "name": c.info["Config"]["Image"], "version": img,
                          "properties": [{"name": "container-security-scan:container-name", "value": c.name},
                                         {"name": "container-security-scan:container-id", "value": c.id}] +
                                        [{"name": "container-security-scan:repo-digest", "value": d} for d in digests]}}),
        ("components", components),
        ("services", [OrderedDict([("bom-ref", "dienst:" + s["label"]), ("name", s["name"])] +
                                  ([("version", s["version"])] if s["version"] else []) +
                                  ([("endpoints", list(OrderedDict.fromkeys(
                                      s["endpoints"] + [e["url"].split(" ")[0] for e in s.get("webadressen", [])])))]
                                   if s["endpoints"] or s.get("webadressen") else []) +
                                  [("description", s["description"]),
                                   ("properties", [{"name": "container-security-scan:aktiv", "value": s["label"]},
                                                   {"name": "container-security-scan:programm", "value": s["exe"]}])])
                      for s in services]),
        ("dependencies", [{"ref": "host" if host else "container", "dependsOn": ["os"]},
                          {"ref": "os", "dependsOn": [x["bom-ref"] for x in components[1:]
                                                      if x.get("purl", "").startswith(("pkg:deb", "pkg:apk", "pkg:rpm"))]}]),
    ])
    if not services:
        del bom["services"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bom, f, ensure_ascii=False, indent=1)



# ===========================================================================
# Versionsvergleiche je Ökosystem (Rückgabe <0, 0, >0) und Schweregrad
# ===========================================================================
def _sign(x):
    return (x > 0) - (x < 0)


def _dpkg_part(a, b):
    """Vergleich nach dpkg (upstream-version bzw. debian-revision): '~' vor allem, Buchstaben vor Sonderzeichen."""
    def order(ch):
        return -1 if ch == "~" else ord(ch) if ch.isalpha() else ord(ch) + 256
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return _sign(ac - bc)
            i, j = i + 1, j + 1
        m, n = re.match(r"\d*", a[i:]).group(), re.match(r"\d*", b[j:]).group()
        if int(m or 0) != int(n or 0):
            return _sign(int(m or 0) - int(n or 0))
        i, j = i + len(m), j + len(n)
    return 0


def _split_evr(v, sep):
    epoch, _, rest = v.partition(":") if re.match(r"\d+:", v) else ("0", "", v)
    upstream, _, rev = rest.rpartition(sep) if sep in rest else (rest, "", "")
    return int(epoch), upstream, rev


def cmp_dpkg(a, b):
    ea, ua, ra = _split_evr(a, "-")
    eb, ub, rb = _split_evr(b, "-")
    return _sign(ea - eb) or _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def _rpm_part(a, b):
    """rpmvercmp: Segmente aus Ziffern/Buchstaben; '~' sortiert vor allem, '^' nach dem Ende."""
    sa, sb = re.findall(r"~|\^|\d+|[a-zA-Z]+", a), re.findall(r"~|\^|\d+|[a-zA-Z]+", b)
    for i in range(max(len(sa), len(sb))):
        x, y = (sa[i] if i < len(sa) else None), (sb[i] if i < len(sb) else None)
        if x == y:
            continue
        if x == "~" or y == "~":
            return -1 if x == "~" else 1
        if x == "^" or y == "^":   # "1.0^x" > "1.0", aber < "1.0.1"
            if x is None or y is None:
                return 1 if x == "^" else -1
            return -1 if x == "^" else 1
        if x is None or y is None:
            return -1 if x is None else 1
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        return _sign(int(x) - int(y)) if x.isdigit() else _sign((x > y) - (x < y))
    return 0


def cmp_rpm(a, b):
    ea, va, ra = _split_evr(a, "-")
    eb, vb, rb = _split_evr(b, "-")
    if not re.match(r"\d+:", a) or not re.match(r"\d+:", b):   # Epoche nur vergleichen, wenn beide eine haben
        ea = eb = 0
    return _sign(ea - eb) or _rpm_part(va, vb) or (_rpm_part(ra, rb) if ra and rb else 0)


APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}


def _apk_key(v):
    m = re.match(r"^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)(?:-r(\d+))?$", v)
    if not m:
        return None
    sfx = [(APK_SUFFIX.get(n, 4), int(d or 0)) for n, d in re.findall(r"_([a-z]+)(\d*)", m.group(3))]
    return [int(x) for x in m.group(1).split(".")], m.group(2), sfx, int(m.group(4) or 0)


def cmp_apk(a, b):
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:
        return _dpkg_part(a, b)
    (na, la, sa, ra), (nb, lb, sb, rb) = ka, kb
    if na != nb:
        return _sign((na > nb) - (na < nb))
    if la != lb:
        return 1 if la > lb else -1
    n = max(len(sa), len(sb))
    sa, sb = sa + [(4, 0)] * (n - len(sa)), sb + [(4, 0)] * (n - len(sb))   # kein Suffix liegt zwischen rc und p
    if sa != sb:
        return 1 if sa > sb else -1
    return _sign(ra - rb)


def cmp_semver(a, b):
    def key(v):
        m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", v.strip())
        if not m:
            return (0, 0, 0), [(2, v)]
        pre = m.group(4)
        # Vorabversionen (-beta.1) sortieren vor der Release-Version
        pre_key = [(0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")] if pre else [(3, "")]
        return tuple(int(x or 0) for x in m.groups()[:3]), pre_key
    ka, kb = key(a), key(b)
    return 0 if ka == kb else (1 if ka > kb else -1)


def _pep440_key(v):
    m = re.match(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
                 r"(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+.*)?$", v.strip().lower())
    if not m:
        return None
    epoch, rel, pl, pn, post1, post_l, post2, dev = m.groups()
    release = [int(x) for x in rel.split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = ({"a": 0, "alpha": 0, "b": 1, "beta": 1}.get(pl, 2), int(pn or 0)) if pl else None
    post = int(post1 or post2 or 0) if (post1 or post_l) else None
    dev_n = int(dev or 0) if dev is not None else None
    return (int(epoch or 0), release,
            pre if pre else ((-1, 0) if dev_n is not None and post is None else (9, 0)),
            (-1,) if post is None else (post,),
            (dev_n,) if dev_n is not None else (float("inf"),))


def cmp_pep440(a, b):
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return _dpkg_part(a, b)
    return 0 if ka == kb else (1 if ka > kb else -1)


MAVEN_QUAL = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3, "snapshot": 4,
              "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _maven_key(v):
    items = []
    for t in re.findall(r"\d+|[a-z]+", v.lower()):
        if t.isdigit():
            items.append((2, int(t), ""))
        else:
            while items and items[-1] == (2, 0, ""):   # 1.0-alpha == 1-alpha
                items.pop()
            items.append((1, MAVEN_QUAL.get(t, 7), "" if t in MAVEN_QUAL else t))
    while items and items[-1] in ((2, 0, ""), (1, 5, "")):    # 1.0.0 == 1.0 == 1, "-final" == ""
        items.pop()
    return items


def cmp_maven(a, b):
    """Vergleich nach Maven (ComparableVersion, vereinfacht): Zahlen > Qualifier; alpha < beta < rc < Release < sp."""
    ka, kb = _maven_key(a), _maven_key(b)
    for i in range(max(len(ka), len(kb))):
        x, y = (ka[i] if i < len(ka) else None), (kb[i] if i < len(kb) else None)
        if x == y:
            continue
        if x is None:
            return -1 if y[0] == 2 or y[1] > 5 else 1
        if y is None:
            return 1 if x[0] == 2 or x[1] > 5 else -1
        return 1 if x > y else -1
    return 0


PHP_SPECIAL = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "#": 4, "pl": 5, "p": 5}


def cmp_php(a, b):
    """Vergleich wie PHPs version_compare() (Grundlage von Composer)."""
    def canon(v):
        v = re.sub(r"[-_+]", ".", v.strip().lstrip("vV"))
        v = re.sub(r"(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)", ".", v)
        return [p for p in v.split(".") if p]

    def special(p):
        return PHP_SPECIAL.get(p.lower(), -6)
    pa, pb = canon(a), canon(b)
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1 if pb[i].isdigit() else _sign(special("#") - special(pb[i]))
        if i >= len(pb):
            return 1 if pa[i].isdigit() else _sign(special(pa[i]) - special("#"))
        x, y = pa[i], pb[i]
        if x.isdigit() and y.isdigit():
            r = _sign(int(x) - int(y))
        else:
            r = _sign(special("#" if x.isdigit() else x) - special("#" if y.isdigit() else y))
        if r:
            return r
    return 0


# ===========================================================================
# Schweregrad
# ===========================================================================
def cvss3_severity(vector):
    """Basiswert nach CVSS 3.x berechnen und als Stufe liefern."""
    m = dict(x.split(":") for x in vector.split("/")[1:] if ":" in x)
    try:
        scope = m["S"]
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = ({"N": 0.85, "L": 0.62, "H": 0.27} if scope == "U" else {"N": 0.85, "L": 0.68, "H": 0.5})[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        c, i, a = ({"H": 0.56, "L": 0.22, "N": 0}[m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * av * ac * pr * ui
    score = 0 if impact <= 0 else math.ceil(min((impact + expl) * (1 if scope == "U" else 1.08), 10) * 10 - 1e-9) / 10
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else None


def cvss4_severity(vector):
    """Näherung für CVSS 4.0: Basismetriken auf CVSS 3 abbilden und dessen Formel nutzen (die exakte
    4.0-Berechnung braucht große Tabellen). CVSS 4 gewichtet die Angriffskomplexität schwächer; sie bleibt
    deshalb unberücksichtigt – die Näherung fällt eher zu hoch als zu niedrig aus."""
    m = dict(x.split(":") for x in vector.split("/")[1:] if ":" in x)
    try:
        v3 = "CVSS:3.1/AV:%s/AC:L/PR:%s/UI:%s/S:U/C:%s/I:%s/A:%s" % (
            m["AV"], m["PR"], "N" if m["UI"] == "N" else "R",
            m["VC"], m["VI"], m["VA"])
    except KeyError:
        return None
    return cvss3_severity(v3)


def osv_severity(rec, affected):
    if rec["id"].startswith("MAL-"):          # als Schadsoftware gemeldetes Paket
        return "CRITICAL"
    db = (rec.get("database_specific") or {}).get("severity") or (affected.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db.upper() in ("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"):
        return "MEDIUM" if db.upper() == "MODERATE" else db.upper()
    urgency = ((affected.get("ecosystem_specific") or {}).get("urgency") or "").replace("*", "")
    if urgency in ("low", "medium", "high"):                      # Einstufung des Debian-Sicherheitsteams hat Vorrang
        return urgency.upper()
    if urgency in ("unimportant", "end-of-life"):
        return "LOW"
    for s in rec.get("severity") or []:                           # Ubuntu-Priorität hat ebenfalls Vorrang
        prio = str(s.get("score", "")).lower()
        if s.get("type") == "Ubuntu" and prio in ("negligible", "low", "medium", "high", "critical"):
            return "LOW" if prio == "negligible" else prio.upper()
    scores = (rec.get("severity") or []) + (affected.get("severity") or [])
    for kind, calc in (("CVSS_V3", cvss3_severity), ("CVSS_V4", cvss4_severity)):
        for s in scores:
            if s.get("type") == kind:
                sev = calc(s.get("score", ""))
                if sev:
                    return sev
    return "UNKNOWN"



def _event_key(cmp):
    """Sortierschlüssel für OSV-Ereignisse; "0" (introduced) ist die kleinste Version."""
    def compare(x, y):
        vx, vy = next(iter(x.values())), next(iter(y.values()))
        if vx == vy:
            return 0
        return -1 if vx == "0" else 1 if vy == "0" else cmp(vx, vy)
    return cmp_to_key(compare)


def affected_by(version, affected, cmp, distribution=False):
    """Ist die Version laut OSV-Eintrag betroffen? Liefert (betroffen, Fix-Version).
    distribution: Daten einer Distribution (Fixes werden in deren Versionszweig zurückportiert)."""
    hit, fixes = version in (affected.get("versions") or []), []
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        c = cmp if rng["type"] == "ECOSYSTEM" else cmp_semver
        state = False
        # "limit": obere Grenze (ausschließlich) des ganzen Bereichs, kein Fix; mehrere -> unter einer davon
        limits = [ev["limit"] for ev in rng.get("events", []) if "limit" in ev]
        if limits and not any(v == "*" or c(version, v) < 0 for v in limits):
            continue
        events = sorted((ev for ev in rng.get("events", []) if "limit" not in ev), key=_event_key(c))
        if distribution and rng["type"] == "ECOSYSTEM" and events and next(iter(events[0])) != "introduced":
            # Widersprüchlicher Bereich: Fix vor der ersten betroffenen Version (z.B. Alpine "introduced 3.4.0,
            # fixed 3.3.7-r1", die Angabe "introduced" stammt aus einem anderen Versionszweig). Die Distribution
            # hat den Fix in ihren Zweig zurückportiert, dieser war also betroffen -> ab Version 0 werten.
            events.insert(0, {"introduced": "0"})
        for ev in events:
            kind, val = next(iter(ev.items()))
            if kind == "introduced" and (val == "0" or c(version, val) >= 0):
                state = True
            elif kind == "fixed" and c(version, val) >= 0:
                state = False
            elif kind == "last_affected" and c(version, val) > 0:
                state = False
            if kind == "fixed" and c(version, val) < 0:
                fixes.append(val)
        hit = hit or state
    return hit, ", ".join(sorted(set(fixes), key=cmp_to_key(cmp))[:1])



# ===========================================================================
# 9. Schwachstellen: Abgleich mit der lokalen OSV-Datenbank
# ===========================================================================
def osv_target(c, osinfo):
    """(OSV-Datei, Ökosystem-Prüfung, Paketnamen, Version, Vergleichsfunktion) einer Komponente oder None."""
    t, name, version = c["typ"], c["name"], c["version"]
    osid, osver = osinfo["id"], osinfo["version"]
    if t == "os-paket":
        if kernel_paket(c) and not osinfo.get("host"):
            return None      # Container nutzen den Kernel des Hosts (beim Scan des Hosts zählt er)
        if osid in ("debian", "ubuntu"):       # Debian/Ubuntu führen CVEs je Quellpaket und Quellversion
            src, ver = c.get("src") or name, c.get("srcver") or version
            if osid == "ubuntu":
                return "Ubuntu", lambda e: e.startswith("Ubuntu:" + osver), {src}, ver, cmp_dpkg
            eco = "Debian:" + osver.split(".")[0]
            return "Debian", lambda e: e == eco, {src}, ver, cmp_dpkg
        if osid == "alpine":
            eco = "Alpine:v" + ".".join(osver.split(".")[:2])
            return "Alpine", lambda e: e == eco, {c.get("src") or name}, version, cmp_apk
        # SUSE führt Lücken je Quellpaket; die Binärpakete eines Eintrags gelten für das ganze Update (auch anderer
        # Quellpakete, z.B. libacl1 unter attr). Abgleich daher über das Quellpaket; das Binärpaket muss zusätzlich
        # im Eintrag stehen (osv_scan), denn ein Quellpaket kann mehrere Versionszweige haben (tiff 4.0.9 mit libtiff5
        # und tiff 4.7 mit libtiff6 in SLES 15 SP7)
        src, ver = c.get("src") or name, c.get("srcver") or version
        if osid.startswith("opensuse-leap"):
            eco = "openSUSE:Leap " + osver
            return "openSUSE", lambda e: e == eco, {src}, ver, cmp_rpm
        if osid.startswith("sle"):
            major, _, minor = osver.partition(".")
            if major.isdigit() and int(major) >= 16:     # SLES 16: "SUSE:Linux Enterprise Server 16.0"
                suffix = " " + osver
            else:                                         # SLES 15: "… 15 SP6", "… 15 SP6-LTSS"
                suffix = " %s SP%s" % (major, minor) if minor and minor != "0" else " " + major
            return "SUSE", lambda e: e.startswith("SUSE:") and (e.endswith(suffix) or e.endswith(suffix + "-LTSS")), \
                {src}, ver, cmp_rpm
        return None
    if t == "npm":
        return "npm", lambda e: e == "npm", {name}, version, cmp_semver
    if t == "composer":
        if version.startswith("dev-") or version.endswith("-dev"):
            return None      # Entwicklungszweig: Version nicht vergleichbar
        return "Packagist", lambda e: e == "Packagist", {name.lower()}, version, cmp_php
    if t == "pypi":
        return "PyPI", lambda e: e == "PyPI", {pypi_name(name)}, version, cmp_pep440
    if t == "js-lib" and version != "unbekannt":
        return "npm", lambda e: e == "npm", {name}, version, cmp_semver
    if t == "maven":
        key = c.get("maven_key") or name
        if key.startswith("*:") and key[2:].lower() in MAVEN_GENERIC:
            return None          # zu allgemeiner Dateiname für eine Zuordnung ohne Maven-Gruppe
        return "Maven", lambda e: e == "Maven", {key}, version, cmp_maven
    if t == "go" and version != "unbekannt":
        return "Go", lambda e: e == "Go", {name}, version, cmp_semver
    if t in ("runtime", "server") and name in BITNAMI and not from_os_package(c):
        return "Bitnami", lambda e: e == "Bitnami", {BITNAMI[name]}, version, cmp_semver
    return None


def from_os_package(c):
    return any(h.startswith("aus OS-Paket") for h in c["hinweise"])


def kernel_paket(c):
    """Kernel-Paket (Header, Image, Module) im Container?"""
    return c["typ"] == "os-paket" and bool(KERNEL_QUELLE.match(c.get("src") or "") or KERNEL_PAKET.match(c["name"]))


def pypi_name(n):
    return re.sub(r"[-_.]+", "-", n.lower())


def maven_wild(names, fname):
    """Maven: zusätzlich "*:<artifactId>" für JARs, deren Maven-Gruppe unbekannt ist."""
    return names | {"*:" + n.rsplit(":", 1)[-1] for n in names} if fname == "Maven" else names


OS_FILES = ("Debian", "Ubuntu", "Alpine", "SUSE", "openSUSE")
# Typische Versionskennungen von Paketquellen der Hersteller (nginx.org, NodeSource, Sury-PHP, mariadb.org,
# PostgreSQL-Repo): deren Pakete decken die Sicherheitsdaten der Distribution nicht ab
THIRD_PARTY = re.compile(r"nodesource|maria~|\+0~|pgdg|~(bookworm|bullseye|buster|trixie|jammy|noble|focal)\b")
THIRD_PARTY_MAINT = re.compile(r"NGINX Packaging|nginx-packaging@|NodeSource|MariaDB (Developers|Foundation)|@mariadb\.(org|com)"
                               r"|PostgreSQL on Debian and Ubuntu|apt\.postgresql\.org", re.I)
FREMDQUELLE = "Paket fehlt in den Sicherheitsdaten der Distribution (Fremdquelle?)"
OS_DATEN_MAX_TAGE = 120        # jüngster Eintrag für das OS-Release älter -> vermutlich ohne Support (EOL)


def db_source(dbdirs, fname):
    """Erstes Datenverzeichnis, das dieses Ökosystem enthält."""
    for d in dbdirs:
        if os.path.isdir(os.path.join(d, fname)) or os.path.exists(os.path.join(d, fname + ".zip")):
            return d
    return None


def osv_scan(comps, osinfo, dbdirs):
    """Liefert (Befunde, Datenbank-Stand, fehlende Datenbankdateien, jüngster Eintrag für das OS-Release)."""
    by_file = defaultdict(lambda: defaultdict(list))   # OSV-Datei -> Paketname -> [(Komponente, Ziel)]
    php_cli = {c["version"] for c in comps if c["typ"] == "runtime" and c["name"] == "php"}
    for c in comps:
        if c["name"] == "php-fpm" and c["version"] in php_cli:
            continue     # gleicher Build wie die php-CLI: nicht doppelt melden
        t = osv_target(c, osinfo)
        if t:
            for n in t[2]:
                by_file[t[0]][n].append((c, t))
    if osinfo["id"] not in ("debian", "ubuntu", "alpine") and not osinfo["id"].startswith(("opensuse-leap", "sle")) \
            and any(c["typ"] == "os-paket" for c in comps):
        by_file["(OS %s wird nicht unterstützt)" % osinfo["id"]] = {}
    findings, missing, dates = {}, [], []
    known_src, newest_os = set(), [""]     # Pakete mit Einträgen für dieses Release; jüngster Eintrag

    def scan_file(fname, wanted):
        dbdir = db_source(dbdirs, fname)
        if not dbdir:
            missing.append(fname)
            return
        path = os.path.join(dbdir, fname) if os.path.isdir(os.path.join(dbdir, fname)) else os.path.join(dbdir, fname + ".zip")
        stand = db_state(dbdir).get(fname, {}).get("geprueft")
        dates.append(datetime.datetime.strptime(stand[:19], "%Y-%m-%dT%H:%M:%S") if stand
                     else datetime.datetime.fromtimestamp(os.path.getmtime(path), datetime.timezone.utc).replace(tzinfo=None))
        norm_name = pypi_name if fname == "PyPI" else (str.lower if fname == "Packagist" else (lambda n: n))
        for raw in osv_records(dbdir, fname):
            names = maven_wild({norm_name(n.decode("utf-8", "replace")) for n in re.findall(rb'"name":\s*"([^"]+)"', raw)}, fname)
            if not names & set(wanted):          # schneller Vorfilter ohne JSON-Parser
                continue
            rec = json.loads(raw.decode("utf-8"))
            if rec.get("withdrawn"):
                continue
            binaries = {}           # SUSE: Binärpakete je Ökosystem-Prüfung (Service Pack)
            cves = [x for x in [rec["id"]] + (rec.get("aliases") or []) + (rec.get("upstream") or []) if x.startswith("CVE-")]
            if rec["id"].startswith("USN-") or (cves and rec["id"].startswith(("DSA-", "DLA-", "DTSA-"))):
                continue   # Sammelmeldung: listet auch CVEs anderer Versionen; je CVE gibt es genauere Einträge
            for aff in rec.get("affected", []):
                pkg = aff.get("package") or {}
                pnames = {pkg.get("name", "")}
                if fname not in ("SUSE", "openSUSE"):    # SUSE: Binärpakete des ganzen Updates (osv_target)
                    pnames |= {b for d in (aff.get("ecosystem_specific") or {}).get("binaries", []) for b in d}
                for n in maven_wild({norm_name(x) for x in pnames}, fname) & set(wanted):
                    for c, (_, eco_ok, _, version, cmp) in wanted[n]:
                        if not eco_ok(pkg.get("ecosystem", "")):
                            continue
                        if fname in ("SUSE", "openSUSE"):
                            if id(eco_ok) not in binaries:
                                binaries[id(eco_ok)] = suse_binaries(rec, eco_ok)
                            if binaries[id(eco_ok)] and c["name"] not in binaries[id(eco_ok)]:
                                continue
                        if fname in OS_FILES:
                            known_src.add(n)
                            newest_os[0] = max(newest_os[0], rec.get("published", ""))
                        hit, fix = affected_by(version, aff, cmp, fname in OS_FILES)
                        if not hit:
                            continue
                        sev = osv_severity(rec, aff)
                        for vid in cves or [rec["id"]]:
                            old = findings.get((id(c), vid))
                            if old:   # mehrere Einträge zur selben CVE (z.B. DSA und DEBIAN-CVE): zusammenführen
                                old["fix"] = old["fix"] or fix
                                old["sev"] = sev if old["sev"] == "UNKNOWN" else old["sev"]
                            else:
                                title = (rec.get("summary") or rec.get("details") or "").split("\n")[0]
                                findings[(id(c), vid)] = f = {"comp": c, "id": vid, "sev": sev, "fix": fix, "title": title}
                                # Distributionsdaten führen nur, was die Distribution betrifft; andere Quellen
                                # (GitHub, Bitnami) auch Lücken, die nur unter Windows auftreten
                                if fname not in OS_FILES and nur_windows(title):
                                    f["ausgenommen"] = "betrifft laut Titel nur Windows"

    for fname in [f for f in list(by_file) if f in OS_FILES]:
        scan_file(fname, by_file[fname])
    # Laufzeiten aus einem OS-Paket, das die Distribution gar nicht kennt (Fremdquelle wie Sury-PHP, NodeSource,
    # mariadb.org): dafür gibt es keine Distributionsdaten -> über Bitnami prüfen
    src_of = {x["name"]: x.get("src") or x["name"] for x in comps if x["typ"] == "os-paket"}
    ver_of = {x["name"]: x["version"] for x in comps if x["typ"] == "os-paket"}
    maint_of = {x["name"]: x.get("maint", "") for x in comps if x["typ"] == "os-paket"}
    if any(f in OS_FILES and f not in missing for f in by_file):
        for c in comps:
            owner = [h[len("aus OS-Paket "):] for h in c["hinweise"] if h.startswith("aus OS-Paket ")]
            if c["typ"] in ("runtime", "server") and c["name"] in BITNAMI and owner and (
                    not any(src_of.get(o, o) in known_src for o in owner[0].split(","))
                    or any(THIRD_PARTY.search(ver_of.get(o, "")) or THIRD_PARTY_MAINT.search(maint_of.get(o, ""))
                           for o in owner[0].split(","))):
                c["hinweise"].append(FREMDQUELLE + " – über Bitnami geprüft")
                by_file["Bitnami"][BITNAMI[c["name"]]].append(
                    (c, ("Bitnami", lambda e: e == "Bitnami", {BITNAMI[c["name"]]}, c["version"], cmp_semver)))
    for fname in [f for f in list(by_file) if f not in OS_FILES]:
        scan_file(fname, by_file[fname])
    # Funde ohne Schweregrad (z.B. Go-Daten): Bewertung derselben CVE aus einer anderen Quelle übernehmen
    if any(f["sev"] == "UNKNOWN" and f["id"].startswith("CVE-") for f in findings.values()):
        index = schweregrad_index(dbdirs)
        for f in findings.values():
            if f["sev"] == "UNKNOWN" and f["id"] in index:
                f["sev"], f["sev_quelle"] = index[f["id"]]
    os_newest = None
    if newest_os[0]:
        os_newest = datetime.datetime.strptime(newest_os[0][:19], "%Y-%m-%dT%H:%M:%S")
    return list(findings.values()), (min(dates) if dates else None), missing, os_newest


_SCHWEREGRAD_CACHE = {}


def suse_binaries(rec, eco_ok):
    """Binärpakete eines SUSE-Eintrags für die Produkte, die eco_ok annimmt (alle Pakete des Updates, auch anderer
    Quellpakete). Gekürzte Daten führen sie je Service Pack ("15 SP7", "16.0"; LTSS eingeschlossen, wie bei
    eco_ok), der Gesamtexport je betroffenem Paket und Produkt."""
    if isinstance(rec.get("binaries"), dict):
        return {b for k, lst in rec["binaries"].items() if eco_ok("SUSE: " + k) for b in lst}
    return {b for a in rec.get("affected") or [] if eco_ok((a.get("package") or {}).get("ecosystem", ""))
            for d in (a.get("ecosystem_specific") or {}).get("binaries", []) for b in d}


def schweregrad_index(dbdirs):
    """CVE -> (Schweregrad, Kennung der Quelle) aus SCHWEREGRAD_QUELLEN; bei mehreren Angaben die höchste.
    Einmal je Lauf aufgebaut (ca. 1 s), nur wenn ein Fund ohne Schweregrad vorliegt."""
    key = tuple(dbdirs)
    if key in _SCHWEREGRAD_CACHE:
        return _SCHWEREGRAD_CACHE[key]
    index = {}
    for fname in SCHWEREGRAD_QUELLEN:
        dbdir = db_source(dbdirs, fname)
        if not dbdir:
            continue
        for raw in osv_records(dbdir, fname):
            if b"CVE-" not in raw:
                continue
            rec = json.loads(raw.decode("utf-8"))
            if rec.get("withdrawn"):
                continue
            sevs = [osv_severity(rec, aff) for aff in rec.get("affected") or [{}]]
            sevs = [s for s in sevs if s != "UNKNOWN"]
            if not sevs:
                continue
            sev = min(sevs, key=SEV.index)
            for cve in {x for x in [rec["id"]] + (rec.get("aliases") or []) + (rec.get("upstream") or [])
                        if x.startswith("CVE-")}:
                if cve not in index or SEV.index(sev) < SEV.index(index[cve][0]):
                    index[cve] = (sev, rec["id"])
    _SCHWEREGRAD_CACHE[key] = index
    return index


def db_state(dbdir):
    """Je Ökosystem: "stand" = Zeitstempel des neuesten Eintrags (für das inkrementelle Update),
    "geprueft" = Zeitpunkt der letzten erfolgreichen Aktualisierung (für die Altersprüfung). Datei stand.json."""
    try:
        raw = json_datei(os.path.join(dbdir, "stand.json"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)}


def osv_update(dbdir, ecosystems, full=False):
    """OSV-Datenbank aktualisieren. Erstmals (oder mit --voll) den Gesamtexport je Ökosystem laden,
    danach nur die seit dem letzten Stand geänderten Einträge (Änderungsliste modified_id.csv, neueste zuerst)."""
    os.makedirs(dbdir, exist_ok=True)
    state = db_state(dbdir)

    def save():
        with open(os.path.join(dbdir, "stand.json.tmp"), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1)
        os.replace(os.path.join(dbdir, "stand.json.tmp"), os.path.join(dbdir, "stand.json"))

    for eco in ecosystems:
        target, overlay = os.path.join(dbdir, eco + ".zip"), os.path.join(dbdir, eco + ".neu")
        known = state.get(eco, {}).get("stand", "")
        complete = full or not known or not os.path.exists(target)      # Gesamtexport nötig?
        changed = []
        with urllib.request.urlopen(OSV_BASE + eco + "/modified_id.csv", timeout=300) as r:
            for line in r:
                ts, _, vid = line.decode("utf-8", "replace").strip().partition(",")
                if not complete and ts[:19] < known[:19]:
                    break                                   # ab hier bereits bekannt
                if not OSV_ID.fullmatch(vid):               # wird Dateiname in <eco>.neu/: kein Pfad
                    raise ScanError("Ungültige Kennung in %s/modified_id.csv: %r" % (eco, vid[:100]))
                changed.append((ts, vid))
                if complete or len(changed) > INKREMENT_MAX:
                    break
        complete = complete or len(changed) > INKREMENT_MAX or (
            os.path.isdir(overlay) and len(os.listdir(overlay)) + len(changed) > 5 * INKREMENT_MAX)
        if complete:
            log("Lade %s ..." % (OSV_URL % eco))
            with urllib.request.urlopen(OSV_URL % eco, timeout=300) as r, open(target + ".tmp", "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
            if zipfile.ZipFile(target + ".tmp").testzip() is not None:
                raise ScanError("Download von %s beschädigt" % eco)
            os.replace(target + ".tmp", target)
            for n in os.listdir(overlay) if os.path.isdir(overlay) else []:
                os.remove(os.path.join(overlay, n))
            log("  %s: Gesamtexport, %d MB" % (eco, os.path.getsize(target) >> 20))
        elif changed:
            os.makedirs(overlay, exist_ok=True)

            def fetch(vid):
                url = OSV_BASE + eco + "/" + urllib.request.quote(vid, safe="") + ".json"
                try:
                    with urllib.request.urlopen(url, timeout=60) as r:
                        data = r.read()
                except urllib.error.HTTPError as e:
                    e.close()        # enthält die offene Antwort
                    if e.code != 404:
                        raise
                    data = json.dumps({"id": vid, "withdrawn": "entfernt"}).encode()   # verdeckt den alten Eintrag
                with open(os.path.join(overlay, vid + ".json.tmp"), "wb") as f:
                    f.write(data)
                os.replace(os.path.join(overlay, vid + ".json.tmp"), os.path.join(overlay, vid + ".json"))
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(fetch, sorted({vid for _, vid in changed})))
            log("  %s: %d geänderte Einträge" % (eco, len(changed)))
        else:
            log("  %s: aktuell" % eco)
        state[eco] = {"stand": changed[0][0] if changed else known,
                      "geprueft": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
        save()


DATEN_BRANCH = "daten"         # Branch mit den Daten (ohne Code), siehe README "Installation und Betrieb"
DATEN_OEKOSYSTEME = ["Debian", "Ubuntu", "Alpine", "SUSE", "npm", "PyPI", "Packagist", "Maven", "Go", "Bitnami"]
# SUSE im Branch daten: nur SLES 15 und neuer (Abgleich nur gegen "SUSE:… 15 SPx[-LTSS]" bzw. "SUSE:… 16.0[-LTSS]",
# osv_target); openSUSE und ältere Produkte lädt --db-aktualisieren --oekosysteme SUSE,openSUSE direkt von OSV
SUSE_DATEN = re.compile(r"SUSE:.* (15( SP\d+)?|1[6-9]\.\d+)(-LTSS)?$")
DATEN_TEILE = {"Debian": 8, "Ubuntu": 8, "npm": 8, "PyPI": 2}     # Dateien je Ökosystem (jede deutlich < 50 MB)


# Versionsvergleich je Ökosystem wie beim Abgleich (osv_target)
OSV_CMP = {"Debian": cmp_dpkg, "Ubuntu": cmp_dpkg, "Alpine": cmp_apk, "SUSE": cmp_rpm, "openSUSE": cmp_rpm,
           "npm": cmp_semver, "PyPI": cmp_pep440, "Packagist": cmp_php, "Maven": cmp_maven, "Go": cmp_semver,
           "Bitnami": cmp_semver}


def _in_ranges(version, ranges, ecosystem):
    """Deckt schon ein Bereich die explizit genannte Version ab? (Dann ist sie für den Abgleich entbehrlich.)
    Ohne bekannten Vergleich oder bei einem Vergleichsfehler: nein, die Version bleibt erhalten."""
    cmp = OSV_CMP.get(ecosystem.split(":")[0])
    if not cmp:
        return False
    try:
        return affected_by(version, {"ranges": ranges}, cmp)[0]
    except Exception:
        return False


def osv_compact(rec, eco=None):
    """Nur die Felder eines OSV-Eintrags, die der Abgleich braucht; None, wenn er nie abgeglichen wird.
    Ubuntu (entpackt rund 8 GB): ohne USN-Sammelmeldungen (osv_scan überspringt sie), ohne Ubuntu Pro, FIPS,
    Realtime u.ä. (Abgleich nur gegen "Ubuntu:<VERSION_ID>…") und ohne Kernel-Quellpakete (KERNEL_QUELLE, werden
    im Container nicht geprüft) – die Ergebnisse bleiben dieselben wie mit dem vollständigen Export.
    SUSE: nur Produkte ab SLES 15 (SUSE_DATEN); openSUSE-Einträge im SUSE-Export werden nie abgeglichen."""
    if eco == "Ubuntu" and rec["id"].startswith("USN-"):
        return None
    out = {k: rec[k] for k in ("id", "aliases", "upstream", "published", "withdrawn") if rec.get(k)}
    summary = rec.get("summary") or (rec.get("details") or "").split("\n")[0]
    if summary:
        out["summary"] = summary[:200]
    if rec.get("severity"):
        out["severity"] = rec["severity"]
    if (rec.get("database_specific") or {}).get("severity"):
        out["database_specific"] = {"severity": rec["database_specific"]["severity"]}
    out["affected"] = []
    for a in rec.get("affected") or []:
        x = {"package": {k: v for k, v in (a.get("package") or {}).items() if k in ("name", "ecosystem")}}
        if eco == "Ubuntu" and (not re.match(r"Ubuntu:\d", x["package"].get("ecosystem", ""))
                                or KERNEL_QUELLE.match(x["package"].get("name", ""))):
            continue
        if eco == "SUSE" and not SUSE_DATEN.match(x["package"].get("ecosystem", "")):
            continue
        ranges = [r for r in a.get("ranges") or [] if r.get("type") in ("ECOSYSTEM", "SEMVER")]
        if ranges:
            x["ranges"] = ranges
        versions = [v for v in a.get("versions") or [] if not (ranges and _in_ranges(v, ranges, x["package"].get("ecosystem", "")))]
        if versions:
            x["versions"] = versions
        # nur die Debian-Dringlichkeit; "binaries" (Ubuntu: rund 80 % der Daten) trägt zum Abgleich nichts bei:
        # Debian/Ubuntu werden über das Quellpaket abgeglichen, Ubuntu führt dort zudem Objekte statt Namen
        es = {k: v for k, v in (a.get("ecosystem_specific") or {}).items() if k == "urgency"}
        if es:
            x["ecosystem_specific"] = es
        if (a.get("database_specific") or {}).get("severity"):
            x["database_specific"] = {"severity": a["database_specific"]["severity"]}
        if a.get("severity"):
            x["severity"] = a["severity"]
        out["affected"].append(x)
    if eco in ("Ubuntu", "SUSE") and not out["affected"]:
        return None
    if eco == "SUSE":       # Binärpakete je Service Pack statt je Produkt (rund 2 statt 40 MB), siehe suse_binaries
        binaries = defaultdict(set)
        for a in rec.get("affected") or []:
            m = SUSE_DATEN.match((a.get("package") or {}).get("ecosystem", ""))
            if m:
                binaries[m.group(1)].update(b for d in (a.get("ecosystem_specific") or {}).get("binaries", []) for b in d)
        if any(binaries.values()):
            out["binaries"] = {k: sorted(v) for k, v in sorted(binaries.items()) if v}
    return out


def daten_erzeugen(target, ecosystems=DATEN_OEKOSYSTEME):
    """Gekürzte, deterministisch sortierte Daten für das Git-Repository schreiben (tägliche GitHub Action)."""
    tmp = tempfile.mkdtemp()
    try:
        osv_update(tmp, ecosystems, full=True)
        state = {"_format": "osv-kompakt-1"}
        old = os.path.join(target, "stand.json")
        if os.path.exists(old):
            state.update(json_datei(old))
        for eco in ecosystems:
            n = DATEN_TEILE.get(eco, 1)
            parts = [[] for _ in range(n)]
            with zipfile.ZipFile(os.path.join(tmp, eco + ".zip")) as z:
                for info in z.infolist():
                    rec = osv_compact(json.loads(z.read(info).decode("utf-8")), eco)
                    if rec is None:
                        continue
                    line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    parts[zlib.crc32(rec["id"].encode()) % n].append((rec["id"], line))
            d = os.path.join(target, eco)
            os.makedirs(d, exist_ok=True)
            for f in os.listdir(d):
                if f.endswith(".jsonl"):
                    os.remove(os.path.join(d, f))
            for i, lines in enumerate(parts):
                with open(os.path.join(d, "%02d.jsonl" % i), "w", encoding="utf-8") as f:
                    f.write("".join(l + "\n" for _, l in sorted(lines)))
            state[eco] = db_state(tmp)[eco]
            log("  %s: %d Einträge in %d Datei(en)" % (eco, sum(len(x) for x in parts), n))
        with open(old, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1, sort_keys=True)
            f.write("\n")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def osv_records(dbdir, fname):
    """Alle Einträge eines Ökosystems: gekürzte Daten (<eco>/*.jsonl, aus dem Git-Repository) oder
    Gesamtexport (<eco>.zip), überlagert von nachgeladenen Änderungen (<eco>.neu/)."""
    if os.path.isdir(os.path.join(dbdir, fname)):
        for n in sorted(os.listdir(os.path.join(dbdir, fname))):
            if n.endswith(".jsonl"):
                with open(os.path.join(dbdir, fname, n), "rb") as f:
                    for line in f:
                        if line.strip():
                            yield line
        return
    overlay = os.path.join(dbdir, fname + ".neu")
    newer = set(os.listdir(overlay)) if os.path.isdir(overlay) else set()
    with zipfile.ZipFile(os.path.join(dbdir, fname + ".zip")) as z:
        for info in z.infolist():
            if info.filename not in newer:
                yield z.read(info)
    for n in newer:
        if n.endswith(".json"):
            with open(os.path.join(overlay, n), "rb") as f:
                yield f.read()


# ===========================================================================
# 9a. Gefährliche Einstellungen des Containers
# ===========================================================================
def konfiguration_pruefen(c):
    """Gefährliche Einstellungen aus docker inspect. Je Fund Kennung CONF-… (für die Ausnahmeliste, als Paket
    gilt der Containername) und Text."""
    h = c.info.get("HostConfig") or {}
    funde = []

    def fund(kennung, text, quelle=""):     # quelle: unterscheidet mehrere Mounts derselben Kennung ("neu")
        funde.append({"id": kennung, "pkg": c.name, "text": text, "quelle": quelle})

    if h.get("Privileged"):
        fund("CONF-PRIVILEGED", "--privileged: alle Capabilities und Zugriff auf alle Geräte des Hosts")
    else:   # privileged umfasst die folgenden ohnehin
        for cap in OrderedDict.fromkeys(re.sub(r"^CAP_", "", x.upper()) for x in h.get("CapAdd") or []):
            if cap in KONF_CAPS:
                fund("CONF-CAP-" + cap.replace("_", "-"), "cap_add %s: ermöglicht den Ausbruch aus dem Container" % cap)
        for opt in h.get("SecurityOpt") or []:
            k, _, v = re.sub(r"[:=]", "=", opt, count=1).partition("=")
            if k in ("seccomp", "apparmor") and v == "unconfined":
                fund("CONF-%s-UNCONFINED" % k.upper(), "%s=unconfined: Schutzprofil abgeschaltet" % k)
    if h.get("PidMode") == "host":
        fund("CONF-PID-HOST", "pid=host: sieht und beeinflusst alle Prozesse des Hosts")
    for m in c.info.get("Mounts") or []:
        if m.get("Type") != "bind":
            continue
        src = (m.get("Source") or "").rstrip("/") or "/"
        if KONF_SOCKET.fullmatch(src):
            fund("CONF-SOCKET", "%s eingebunden als %s: Zugriff auf die Container-Laufzeit = root auf dem Host "
                                "(auch schreibgeschützt)" % (src, m.get("Destination")), src)
        elif m.get("RW") and KONF_HOST_PFAD.fullmatch(src):
            fund("CONF-HOST-PFAD", "%s beschreibbar eingebunden als %s" % (src, m.get("Destination")), src)
    return funde


def userns_aktiv(c):
    """Ist root im Container nicht root auf dem Host (Daemon mit userns-remap oder rootless, nicht abgeschaltet)?"""
    if (c.info.get("HostConfig") or {}).get("UsernsMode") == "host":
        return False
    rc, out = run(["docker", "info", "--format", "{{json .SecurityOptions}}"])
    return rc == 0 and bool(re.search(r"name=(userns|rootless)\b", out))


# Auf dem Host üblich als root an öffentlichen Ports: Privilegientrennung (sshd) bzw. Socket-Aktivierung (systemd)
ROOT_DIENSTE_HOST = {"sshd", "systemd", "xinetd", "inetd"}


def root_dienste(c, procs, web):
    """Warnungen (kein Rückgabewert): öffentliche Ports, deren Prozesse alle als root laufen. Je Port geprüft:
    Bei nginx/Apache/php-fpm (Master root, Worker unprivilegiert) hält mindestens ein Worker den Port."""
    ports = OrderedDict()
    for p in procs.values():
        for port, addr in p["ports"].items():
            if port_erreichbar(p, port, addr, web)[1]:     # wie die Priorität: auch LAN, "möglicherweise", nicht Loopback
                ports.setdefault(port, []).append(p)
    host = isinstance(c, Host)
    found = OrderedDict()   # Programm(e) -> Ports
    for port, ps in ports.items():
        if all(p["user"].split(":")[0] == "0" for p in ps) and not (host and all(p["base"] in ROOT_DIENSTE_HOST for p in ps)):
            found.setdefault("/".join(sorted({p["base"] for p in ps})), []).append(port)
    if not found or (not host and userns_aktiv(c)):
        return []
    if host:
        return ["Öffentlicher Dienst %s:%s läuft als root (UID 0, ohne unprivilegierte Worker) – eine Lücke darin "
                "gibt root auf dem Host; als eigener Benutzer starten (systemd: User=)" % (base, ",".join(ports))
                for base, ports in found.items()]
    return ["Öffentlicher Dienst %s:%s läuft als root (UID 0, ohne unprivilegierte Worker) – eine Lücke darin "
            "gibt root im Container; Benutzer setzen (user:, USER) oder non-root-Image" % (base, ",".join(ports))
            for base, ports in found.items()]


def offene_datendienste(procs, web):
    """Warnungen (kein Rückgabewert): Datenbanken, Caches und Message Broker, die direkt von außerhalb des Hosts
    erreichbar sind – Port an eine Adresse außer Loopback veröffentlicht, Host-Netzwerk oder LAN-Netz. Anwendungen
    erreichen sie über das Docker-Netz; offen sind sie Ziel von Anmeldeversuchen und Lücken im Protokoll."""
    found = OrderedDict()   # Programm:Port -> Wege
    for p in procs.values():
        if not datendienst(p):
            continue
        for port, addr in p["ports"].items():
            if nur_lokal(addr):
                continue
            if web.get("ist_host"):
                desc, offen, frei = host_port_pruefen(p, port, addr, web)
                if offen and frei:
                    found.setdefault("%s:%s" % (p["base"], port), [desc])
                continue
            wege = ["veröffentlicht als " + e.split(" ")[0] for e in web["published"].get(port, [])
                    if not (nur_lokal(e.split(" ")[0].rpartition(":")[0]) or e.startswith("::1:"))]
            if web["host_network"]:
                wege.append("Host-Netzwerk")
            wege += ["im " + n for n in web.get("lan", [])]
            if wege:
                found.setdefault("%s:%s" % (p["base"], port), wege)
    if web.get("ist_host"):
        return ["Datenbank/Cache/Message Broker %s direkt von außerhalb des Hosts erreichbar, ohne Beschränkung der "
                "Quelle (%s) – nur an 127.0.0.1 binden bzw. per firewalld auf die Anwendungsserver beschränken (Rich "
                "Rule mit source address)" % (label, ", ".join(wege)) for label, wege in found.items()]
    return ["Datenbank/Cache/Message Broker %s direkt von außerhalb des Hosts erreichbar (%s) – Anwendungen "
            "erreichen ihn über das Docker-Netz: Port nicht veröffentlichen (ports: entfernen) oder nur an 127.0.0.1 "
            "binden" % (label, ", ".join(wege)) for label, wege in found.items()]


def konf_text(k, fett=""):
    return "%s%s%s: %s" % (fett, k["id"], fett, k["text"])


# ===========================================================================
# 10. Bericht (Markdown)
# ===========================================================================
def fix_text(ver, fix):
    if not fix:
        return ""
    a, b = re.match(r"(\d+:)?(\d+)", ver), re.match(r"(\d+:)?(\d+)", fix)
    return fix + (" (anderer Versionszweig: Upgrade nötig)" if a and b and a.group(2) != b.group(2) else "")


def priority(c, published):
    if c.get("dev"):
        return 4
    labels = {a.split(" (")[0] for a in c["aktiv"]}
    return 1 if labels & published else 2 if labels else 3 if c["aktiv_ohne_port"] else 4


def nutzer_text(x):
    """Dienste, die eine Komponente nutzen: jeder einmal – direkt, sonst mit dem ersten Weg ("über …")."""
    labels = x["aktiv"] or x["aktiv_ohne_port"]
    direkt = {a.split(" (über ")[0] for a in labels if " (über " not in a}
    out = OrderedDict()
    for a in labels:
        base = a.split(" (über ")[0]
        if (" (über " in a and base in direkt) or any(o.split(" (über ")[0] == base for o in out):
            continue
        out[a] = None
    return ", ".join(out) or "–"


def md(s):
    return str(s).replace("|", "/").replace("\n", " ")


def ausnahmen_anwenden(rows, ausnahmen, warnings):
    """Einträge der Ausnahmeliste auf Funde anwenden (r["ausgenommen"]); abgelaufene nur melden."""
    today = utcnow().date()
    for a in ausnahmen:
        hits = [r for r in rows if r["id"] == a["id"] and a["paket"] in ("*", r["pkg"])]
        if not hits:
            continue
        if a["bis"] < today:
            warnings.append("Ausnahme für %s (%s) abgelaufen am %s – Fund zählt wieder; prüfen und Liste "
                            "anpassen (Zeile %d)" % (a["id"], a["paket"], a["bis"].isoformat(), a["zeile"]))
            continue
        for r in hits:
            r["ausgenommen"] = "Ausnahme bis %s: %s" % (a["bis"].isoformat(), a["grund"])


def ist_relevant(r, nur_behebbare):
    return not r.get("ausgenommen") and ((r["prio"], r["sev"]) in RELEVANT or bool(r.get("kev"))) \
        and bool(r["fix"] or not nur_behebbare)


def schwere_text(r):
    return r["sev"] + ("*" if r.get("sev_quelle") else "") + (" KEV" if r.get("kev") else "")


def fund_text(r, fett=""):
    """Eine Zeile je relevantem Fund – im Bericht (fett = "**") und auf der Konsole."""
    return "%s%s%s (%s) in %s %s – " % (fett, r["id"], fett, schwere_text(r), r["pkg"], r["ver"]) + \
        (("behoben in " + fix_text(r["ver"], r["fix"])) if r["fix"] else "noch kein Fix") + \
        " – genutzt von %(users)s" % r + \
        (" – Webadressen: " + webadressen_text(r["urls"]) if r.get("urls") else "") + \
        (" – %saktiv ausgenutzt%s (KEV seit %s)" % (fett, fett, r["kev"]) if r.get("kev") else "")


def write_report(path, c, osinfo, comps, services, procs, web, how, findings, db_info, alle, nur_behebbare, known,
                 ausnahmen=(), konf=()):
    published = {s["label"] for s in services if s["exposed"]}
    rows = []
    for f in findings:
        x = f["comp"]
        rows.append(dict(f, prio=priority(x, published), pkg=x["name"], ver=x["version"],
                         users=nutzer_text(x),
                         urls=x.get("webadressen_erreichbar") or x.get("webadressen") or []))
    rows.sort(key=lambda r: (r["prio"], SEV.index(r["sev"]), r["fix"] == "", r["pkg"], r["id"]))
    how.setdefault("warnungen", [])
    ausnahmen_anwenden(rows, ausnahmen, how["warnungen"])
    relevant = [r for r in rows if ist_relevant(r, nur_behebbare)]
    # ausgenommen, wäre sonst relevant: im Ergebnis gesondert ausweisen
    ausgenommen = [r for r in rows if r.get("ausgenommen") and ist_relevant(dict(r, ausgenommen=""), nur_behebbare)]
    for r in relevant:     # neu gegenüber dem letzten Lauf (ohne vorherigen Lauf: alle neu)
        r["neu"] = known is None or (r["pkg"], r["ver"], r["id"]) not in known
    relevant.sort(key=lambda r: not r["neu"])

    out = []
    w = out.append
    i = c.info
    host = isinstance(c, Host)
    kernel = sum(1 for x in comps if kernel_paket(x))
    if host:
        w("# Host-Scan: %s\n" % c.name)
        w("- Host: %s, Kernel %s  \n" % (c.name, os.uname().release) +
          "- OS: %s  \n- Zeitpunkt: %s  \n- Scanner: container-security-scan %s  \n- Datenbank: %s  \n" % (
              osinfo["pretty"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), VERSION, db_info["text"]) +
          "- Erfassung: OS-Pakete %s; Dateien %s; Prozesse %s%s\n" % (
              how["pkgdb"], how["files"], how["procs"], "; %d Sprach-Komponenten aus OS-Paketen (über das OS-Paket "
              "geprüft)" % how["os_owned"] if how["os_owned"] else "") +
          "- Firewall: %s\n" % how.get("firewall", "–"))
    else:
        w("# Container-Scan: %s\n" % c.name)
        w("- Image: %s (%s)  \n- OS: %s  \n- Zeitpunkt: %s  \n- Scanner: container-security-scan %s  \n- Datenbank: %s  \n- Erfassung: OS-Pakete %s; Dateien %s; Prozesse %s%s%s\n" % (
            i["Config"]["Image"], i["Image"][:19], osinfo["pretty"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            VERSION, db_info["text"], how["pkgdb"], how["files"], how["procs"],
            "; %d Sprach-Komponenten aus OS-Paketen (über das OS-Paket geprüft)" % how["os_owned"] if how["os_owned"] else "",
            "; %d Kernel-Pakete nicht geprüft (Container nutzen den Kernel des Hosts)" % kernel if kernel else ""))

    w("## Ergebnis\n")
    if db_info["problems"]:
        w("**PRÜFUNG UNVOLLSTÄNDIG (Rückgabewert 2):** " + "; ".join(db_info["problems"]) + "\n")
    for warn in how.get("warnungen", []):
        w("**Warnung:** %s  " % warn)
    w("**%d relevante Schwachstellen** (Kriterium: %s; aktiv ausgenutzte (KEV) unabhängig von Priorität und "
      "Schweregrad%s)\n" % (len(relevant), ", ".join(
          "P%d %s" % k for k in sorted(RELEVANT, key=lambda k: (k[0], SEV.index(k[1])))),
          "; nur mit verfügbarem Fix" if nur_behebbare else ""))
    if known is not None:
        w("Davon **%d neu** seit dem letzten Lauf.\n" % sum(r["neu"] for r in relevant))
    for r in relevant[:30]:
        w(("- NEU: " if r["neu"] and known is not None else "- ") + fund_text(r, "**"))
    if len(relevant) > 30:
        w("- … weitere %d in der Tabelle unten" % (len(relevant) - 30))
    konf_gezaehlt = [k for k in konf if konf_zaehlt(k) and k.get("art") != "web"]
    if konf_gezaehlt:
        w("\n**%d gefährliche Einstellungen des Containers** (eine Lücke im Container führt damit zu root auf dem "
          "Host; Kennung für die Ausnahmeliste, Paket = Containername)\n" % len(konf_gezaehlt))
        for k in konf_gezaehlt:
            w(("- NEU: " if k.get("neu") and known is not None else "- ") + konf_text(k, "**"))
    elif not host:
        w("\nGefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.")
    web_gezaehlt = [k for k in konf if konf_zaehlt(k) and k.get("art") == "web"]
    if web_gezaehlt:
        w("\n**%d Einstellungen der Webserver** (erreichbar; Kennung für die Ausnahmeliste, Paket = Name der "
          "Website)\n" % len(web_gezaehlt))
        for k in web_gezaehlt:
            w(("- NEU: " if k.get("neu") and known is not None else "- ") + konf_text(k, "**"))
    else:
        w("\nEinstellungen der Webserver (Statusseiten, Verzeichnislisten%s): keine gezählt." % (
            ", TLS 1.0/1.1" if host else ""))
    konf_ausgenommen = [k for k in konf if k.get("ausgenommen")]
    web_intern = [k for k in konf if not k.get("ausgenommen") and k.get("art") == "web" and not k.get("erreichbar")
                  and not k.get("nur_warnung")]
    if ausgenommen or konf_ausgenommen or web_intern:
        w("\nNicht gezählt (wären sonst relevant):")
        for r in ausgenommen[:30]:
            w("- %s (%s) in %s %s – %s" % (r["id"], schwere_text(r), r["pkg"], r["ver"], r["ausgenommen"]))
        for k in konf_ausgenommen:
            w("- %s – %s" % (konf_text(k), k["ausgenommen"]))
        for k in web_intern:
            w("- %s – Webserver von außen nicht erreichbar" % konf_text(k))
    unknown = sum(1 for r in rows if r["prio"] == 1 and r["sev"] == "UNKNOWN")
    if unknown:
        w("\nHinweis: %d Befunde in P1 haben noch keinen Schweregrad (UNKNOWN) – bitte mit ansehen." % unknown)

    w("\n## Laufende Dienste\n")
    if services:
        w("| Dienst | Programm | Ports / Konfiguration |\n|---|---|---|")
        for s in services:
            w("| %s | %s %s | %s |" % (s["label"], s["name"], s["version"], md(s["description"])))
    else:
        w("Keine Prozesse mit offenen TCP-Ports gefunden.")
    adressen = [(s, e) for s in services for e in s.get("webadressen", [])]
    if adressen:
        w("\n## Webadressen\n")
        w("Aus der Konfiguration der Webserver (server_name, ServerName/ServerAlias, listen bzw. vHost, TLS); "
          "Pfade, die ein Proxy auf %s weiterleitet, beim Ziel. „Erreichbar“ wie der Port, über den die Anfrage "
          "hereinkommt.\n" % ("demselben Host" if host else "denselben Container"))
        w("| Webadresse | Erreichbar | Dienst | Weg | Website | Docroot / Ziel |\n|---|---|---|---|---|---|")
        for s, e in adressen:
            site = e["site"]
            ziel = ", ".join((site or {}).get("roots") or []) or ", ".join(
                "%s → %s" % (pf, z) for pf, z in ((site or {}).get("weiter") or [])[:3])
            w("| %s | %s | %s | %s | %s | %s |" % (md(e["url"]), "ja" if e["erreichbar"] else "nein", s["label"],
                                                  md(e["weg"]), md(site["datei"]) if site else "(weitergeleitet)",
                                                  md(ziel) or "–"))

    w("\n## Übersicht (Anzahl Befunde)\n")
    cnt = Counter((r["prio"], r["sev"]) for r in rows)
    w("| Priorität | " + " | ".join(SEV) + " |\n|---|" + "---|" * len(SEV))
    for p, name in ((1, "P1 Dienst mit veröffentlichtem Port"), (2, "P2 Dienst intern"),
                    (3, "P3 Prozess ohne Port"), (4, "P4 nicht genutzt / dev")):
        w("| %s | " % name + " | ".join(str(cnt[(p, s)]) for s in SEV) + " |")

    shown = [r for r in rows if alle or r["prio"] <= 2 or r["sev"] in ("CRITICAL", "HIGH") or r.get("kev")]
    w("\n## Befunde (%d von %d%s)\n" % (len(shown), len(rows), "" if alle else "; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle"))
    w("| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Webadressen | Titel |\n"
      "|---|---|---|---|---|---|---|---|---|")
    for r in shown:
        w("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["prio"], schwere_text(r), r["id"], r["pkg"], r["ver"], fix_text(r["ver"], r["fix"]) or "kein Fix",
            md(r["users"]), md(webadressen_text(r["urls"], 2)) or "–", ("[nicht gezählt: %s] " % md(r["ausgenommen"]) if r.get("ausgenommen") else "") + md(r["title"])[:90]))
    if any(r.get("sev_quelle") for r in shown):
        w("\n\\* Schweregrad aus einer anderen Quelle zur selben CVE (%s), da der zutreffende Eintrag keinen nennt."
          % ", ".join(sorted({r["sev_quelle"] for r in shown if r.get("sev_quelle")})[:5]
                      + (["…"] if len({r["sev_quelle"] for r in shown if r.get("sev_quelle")}) > 5 else [])))
    if any(r.get("kev") for r in shown):
        w("\nKEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).")

    unchecked = [x for x in comps if (x["typ"] in ("runtime", "server", "host", "php-ext")
                 and not from_os_package(x) and x["name"] not in BITNAMI)
                 or (x["typ"] in ("js-lib", "go") and x["version"] == "unbekannt")
                 or (x["typ"] == "composer" and (x["version"].startswith("dev-") or x["version"].endswith("-dev")))
                 or (x["typ"] == "maven" and x.get("maven_key", "")[2:].lower() in MAVEN_GENERIC)]
    if unchecked:
        w("\n## Nicht automatisch geprüft – bitte gesondert prüfen\n")
        w("Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. "
          "Für sie gibt es in OSV keine (eindeutigen) Paketdaten.\n")
        w("| Typ | Name | Version | Fundort | Genutzt von |\n|---|---|---|---|---|")
        for x in unchecked:
            w("| %s | %s | %s | %s | %s |" % (x["typ"], x["name"], x["version"], x["ort"], ", ".join(x["aktiv"] or x["aktiv_ohne_port"]) or "–"))

    w("\n## Anhang\n\n### Komponenten (gesamt / von Diensten mit offenem Port genutzt)\n")
    w("| Typ | gesamt | genutzt | dev |\n|---|---|---|---|")
    for t in sorted({x["typ"] for x in comps}):
        g = [x for x in comps if x["typ"] == t]
        w("| %s | %d | %d | %d |" % (t, len(g), sum(1 for x in g if x["aktiv"] and t != "host"), sum(1 for x in g if x.get("dev"))))
    if host:
        w("\n### Host\n\n```\nName:      %s\nKernel:    %s\nAdressen:  %s\n```" % (
            c.name, os.uname().release, " ".join("%s=%s" % x for x in web.get("interfaces") or [])))
        w("\n### Laufende Prozesse (außerhalb von Containern)\n\n```\n%s\n```" % "\n".join(
            ["PID     USER       COMMAND"] + ["%-7s %-10s %s" % (p["pid"], p["user"].split(":")[0], " ".join(p["argv"])[:200])
                                           for p in procs.values()]))
    else:
        w("\n### Container\n\n```\nID:        %s\nGestartet: %s\nKommando:  %s %s\nMounts:    %s\nHost:      Kernel %s\n```" % (
            c.id, i["State"]["StartedAt"], json.dumps(i["Config"].get("Entrypoint")), json.dumps(i["Config"].get("Cmd")),
            " ".join("%s->%s" % (m.get("Source"), m.get("Destination")) for m in i.get("Mounts") or []), os.uname().release))
        w("\n### Laufende Prozesse\n\n```\n%s\n```" % run(["docker", "top", c.id, "-eo", "pid,user,args"])[1].rstrip())
    stale = [(p, sorted(m for m in p["maps"] if m.endswith(" (deleted)") and not re.match(r"/(dev/|memfd:|SYSV)", m)))
             for p in procs.values()]
    stale = [(p, m) for p, m in stale if m]
    w("\n### Prozesse mit gelöschten (veralteten) Dateien im Speicher\n")
    for p, m in stale:
        w("- PID %s (%s): %s" % (p["pid"], p["exe"], " ".join(m)))
    w("\nACHTUNG: Diese Prozesse nutzen noch alte Dateiversionen – Dienst neu starten." if stale else "Keine gefunden.")
    if web["raw"]:
        w("\n### Webserver-Konfiguration (Auszug)\n\n```\n%s\n```" % "\n".join(web["raw"]))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    return rows, relevant


# ===========================================================================
def scan_container(name, a, via_proxy=None):
    """Einen Container scannen. Liefert (Rückgabewert, öffentliche Backends [(Container, Port, Dienst)])."""
    c = Container(name, a.user)
    log("Erfasse Container '%s' ..." % c.name)
    how = {}
    files, extra, how["files"], problems = collect_files(c)
    osinfo = os_release(files)
    pkgs, owners, how["pkgdb"] = os_packages(c, files)
    procs, how["procs"], fremd = collect_procs(c)
    lang = npm_packages(files) + composer_packages(files) + pypi_packages(files) + extra
    if how["pkgdb"] == "rpm (im Container)":
        owners.update(rpm_owners(c, {norm(f) for p in procs.values() for f in p["maps"] | {p["exe"]}} |
                                 {x["datei"] for x in lang}))
    # Sprach-Komponenten, deren Datei zu einem OS-Paket gehört (z.B. gosu, python3-*-Pakete, libxyz-java),
    # prüft der Abgleich über das OS-Paket – sonst würden sie doppelt gezählt (so hält es auch Trivy)
    how["os_owned"] = sum(1 for x in lang if owners.get(norm(x["datei"])))
    comps = pkgs + [x for x in lang if not owners.get(norm(x["datei"]))]
    comps += probe_runtimes(c, procs, owners) + host_components()
    web = collect_web(c, procs)
    problems.extend(web["problems"])
    web["self"] = c.name
    web["via_proxy"] = via_proxy or {}
    web["venvs"] = {posixpath.dirname(f) for f in files if f.endswith("/pyvenv.cfg")}
    services = mark_usage(comps, procs, owners, web)

    # Ports, auf denen ein Container lauscht, der den Netzwerk-Namespace mitnutzt: dort bewertet
    warnings = []
    listening = {port for p in procs.values() for port in p["ports"]}
    ohne_prozess = fremd       # lauschende Sockets ohne sichtbaren Prozess
    # nur, wenn dort ein lesbarer Prozess auf dem Port lauscht (also bewertet wird); sonst Rückfallregel
    besitz = ports_in_gruppe(web["netz_gruppe"], a.user) if web.get("netz_gruppe") and fremd else set()
    fremd = OrderedDict((port, v) for port, v in fremd.items() if port not in listening and port in besitz)
    for port in fremd:
        services.append({"label": "Port %s" % port, "name": "–", "version": "", "exe": "", "exposed": False,
                         "backends": [], "unresolved": [], "unklar": [], "endpoints": [],
                         "description": "Port %s (%s): Prozess in einem Container mit demselben Netzwerk (%s) – dort "
                                        "bewertet" % (port if "/" in port else port + "/tcp", fremd[port][0],
                                                      ", ".join(web["netz_gruppe"]))})
    # Veröffentlichte Ports ohne erkannten Prozess (Prozesse nicht lesbar, z.B. nach Benutzerwechsel, oder
    # Werkzeuge fehlen): Zuordnung unmöglich -> vorsichtshalber alles als öffentlich genutzt werten. Lauscht dort
    # ein nicht lesbarer Prozess (oder ist gar keiner lesbar), könnte es ein Proxy sein -> Container in denselben
    # Docker-Netzen gelten als möglicherweise öffentlich
    # Ziele nur aus Aufrufen (Ziel-URL, Verbindung), auf denen nichts lauscht: nichts erreichbar (z.B. URL für eine
    # andere Umgebung) – anders als bei einem Proxy-Ziel kein Anlass, alles als öffentlich zu werten
    # Ziele über Loopback, auf denen hier nichts lauscht: gelten einem anderen Container mit demselben Loopback
    # (Host-Netzwerk, gemeinsamer Netzwerk-Namespace) oder dem Host selbst – außer im gemeinsamen
    # Netzwerk-Namespace lauscht dort ein Socket, dessen Prozess nicht nachweisbar ist (dann Rückfallregel). Im
    # Host-Netzwerk sind das auch alle Sockets des Hosts; sie gehören nicht zu diesem Container.
    unmatched = sorted(port for port in web["published"] if port not in listening and port not in fremd
                       and port not in web["via_proxy"]) + \
        sorted(port for port, reasons in web["via_proxy"].items() if port != "*" and port not in listening
               and port not in fremd
               and (any(LOOPBACK_GRUND not in r for r in reasons) or (port in ohne_prozess and not web["host_network"]))
               and not (all(aufruf_grund(r) for r in reasons if LOOPBACK_GRUND not in r) and port not in ohne_prozess))
    if unmatched or (not procs and (web["published"] or web["host_network"] or web.get("lan") or web["via_proxy"])):
        label = "unbekannter Dienst:" + (",".join(unmatched) or "?")
        for x in comps:
            if x["typ"] != "host" and label not in x["aktiv"]:
                x["aktiv"].append(label)
        # könnte ein Proxy sein: Nachbarn in den Docker-Netzen, Container mit demselben Loopback auch dort, wo
        # nur auf Loopback gelauscht wird
        unbekannt = not procs or any(port in ohne_prozess for port in unmatched)
        loopback = list(web.get("loopback", [])) if unbekannt else []
        nachbarn = [ct for ct in web.get("nachbarn", []) if ct not in loopback] if unbekannt else []
        services.append({"label": label, "name": "?", "version": "", "exe": "?", "exposed": True,
                         "backends": [(ct, "*", label) for ct in nachbarn] +
                                     [(ct, "*", label + LOOPBACK_GRUND) for ct in loopback],
                         "unresolved": [], "unklar": ["Prozess nicht ermittelbar"],
                         "endpoints": [e for port in unmatched for e in web["published"].get(port, [])],
                         "description": "Kein lesbarer Prozess für Port %s – alle Komponenten werden als öffentlich "
                                        "genutzt gewertet%s" % (", ".join(unmatched) or "?",
                                        ", Container in denselben Docker-Netzen bzw. mit demselben Loopback als "
                                        "möglicherweise öffentlich: " + ", ".join(nachbarn + loopback)
                                        if nachbarn or loopback else "")})
        warnings.append("Prozess zu Port %s nicht ermittelbar (%s) – alle Komponenten als öffentlich genutzt gewertet"
                        % (", ".join(unmatched) or "?", how["procs"]))
    for svc in services:
        for b in svc["unresolved"]:
            warnings.append("Backend %s von %s keinem Container zuordenbar – dort ggf. gesondert scannen" % (b, svc["label"]))
        if svc["unklar"] and svc["name"] != "?":
            warnings.append("Weiterleitungen von %s nicht vollständig auswertbar (%s) – %s" % (
                svc["label"], "; ".join(svc["unklar"]),
                "Container in denselben Docker-Netzen gelten als möglicherweise öffentlich: " + ", ".join(web["nachbarn"])
                if web.get("nachbarn") else "keine Container in denselben Docker-Netzen"))
    warnings.extend(root_dienste(c, procs, web))
    warnings.extend(offene_datendienste(procs, web))
    how["warnungen"] = warnings
    konf = konfiguration_pruefen(c)
    webadressen(services, web)
    komponenten_webadressen(comps, services)
    # Einstellungen der Webserver im Container: vorerst nur Warnung (neue Prüfung, bestehende Images wie php:apache
    # hätten sonst sofort Rückgabewert 1); auf dem Host zählen sie
    konf += [dict(k, nur_warnung=True) for k in webserver_pruefen(services, web)]
    code, base = abschliessen(c, c.name, "scan_" + c.name, "bekannt_%s.json" % c.name, a, comps, pkgs, osinfo,
                              services, procs, web, how, problems, konf)
    return code, [(ct, port, "%s in %s" % (label, c.name)) for s in services for ct, port, label in s["backends"]], base


def konf_zaehlt(k):
    """Zählt eine Einstellung (CONF-…, WEB-…) für den Rückgabewert? Webserver nur, wenn erreichbar und nicht nur als
    Warnung (Container, siehe scan_container)."""
    return not k.get("ausgenommen") and not k.get("nur_warnung") and (k.get("art") != "web" or k.get("erreichbar"))


def abschliessen(z, prefix, basisname, known_name, a, comps, pkgs, osinfo, services, procs, web, how, problems, konf):
    """Gemeinsam für Container und Host: Abgleich mit den OSV-Daten, Bericht, SBOM, Prüfsummen, bekannte Funde und
    Ausgabe auf der Konsole (Zeilen mit prefix). Liefert (Rückgabewert, Basis der Berichtsdateien)."""
    warnings = how["warnungen"]
    ausnahmen_anwenden(konf, getattr(a, "ausnahmen_liste", None) or [], warnings)
    konf_relevant = [k for k in konf if konf_zaehlt(k)]
    for k in konf:
        if k.get("nur_warnung") and k.get("erreichbar") and not k.get("ausgenommen"):
            warnings.append("Einstellung des Webservers (im Container vorerst nur Warnung, zählt nicht für den "
                            "Rückgabewert): " + konf_text(k))

    log("Abgleich mit OSV-Daten %s ..." % ", ".join(a.dbdirs))
    findings, db_date, missing, os_newest = osv_scan(comps, osinfo, a.dbdirs)
    # nach osv_scan: erst dort werden Laufzeiten aus Fremdquellen (nginx.org, NodeSource …) erkannt
    warnings.extend(eol_warnungen(comps, [os.path.join(d, "eol-daten.json") for d in a.dbdirs]))
    warnings.extend(kev_markieren(findings, [os.path.join(d, "kev.json") for d in a.dbdirs]))
    if missing:
        problems.append("Daten fehlen für: " + ", ".join(missing) + " (--db-aktualisieren --oekosysteme " + ",".join(missing) + ")")
    if not pkgs:
        problems.append("keine OS-Paketdatenbank gefunden (%s)" % how["pkgdb"])
    elif not missing and db_date and (not os_newest or (db_date - os_newest).days > OS_DATEN_MAX_TAGE):
        # für eine unterstützte Distribution erscheinen laufend neue Einträge; fehlen sie, ist sie vermutlich EOL
        problems.append("keine aktuellen Sicherheitsdaten für %s (jüngster Eintrag: %s) – Distribution vermutlich "
                        "ohne Support (EOL), Ergebnis nicht aussagekräftig" % (
                            osinfo["pretty"], os_newest.strftime("%Y-%m-%d") if os_newest else "keiner"))
    if db_date and (utcnow() - db_date).days >= DB_MAX_ALTER_TAGE:
        problems.append("Daten veraltet (Stand %s, älter als %d Tage – git pull bzw. --db-aktualisieren)" % (
            db_date.strftime("%Y-%m-%d"), DB_MAX_ALTER_TAGE))
    db_info = {"problems": problems, "text": "OSV, Stand %s UTC (%s)" % (db_date.strftime("%Y-%m-%d %H:%M") if db_date else "?", ", ".join(a.dbdirs))}
    known_file = os.path.join(a.ausgabe, known_name)    # relevante Funde des letzten Laufs
    try:
        known = {tuple(k) for k in json_datei(known_file)}
    except (OSError, ValueError):
        known = None
    for k in konf_relevant:
        k["neu"] = known is None or (k["pkg"], k["quelle"], k["id"]) not in known

    os.makedirs(a.ausgabe, exist_ok=True)
    base = os.path.join(a.ausgabe, "%s_%s" % (basisname, datetime.datetime.now().strftime("%Y%m%d_%H%M%S")))
    rows, relevant = write_report(base + ".md", z, osinfo, comps, services, procs, web, how, findings, db_info,
                                  a.alle, a.nur_behebbare, known, getattr(a, "ausnahmen_liste", None) or [], konf)
    if not problems:
        with open(known_file, "w", encoding="utf-8") as f:
            json.dump(sorted([[r["pkg"], r["ver"], r["id"]] for r in relevant] +
                             [[k["pkg"], k["quelle"], k["id"]] for k in konf_relevant]), f)
    write_cdx(base + ".cdx.json", z, osinfo, comps, services)
    with open(base + ".sha256", "w") as f:
        for ext in (".md", ".cdx.json"):
            f.write("%s  %s\n" % (datei_sha256(base + ext), os.path.basename(base + ext)))

    code = 2 if problems else 1 if relevant or konf_relevant else 0
    public = [s["label"] for s in services if s["exposed"]]
    unknown = sum(1 for r in rows if r["prio"] == 1 and r["sev"] == "UNKNOWN")
    kev = sum(1 for r in relevant if r.get("kev"))
    for warn in how["warnungen"]:
        print("%s: WARNUNG: %s" % (prefix, warn))
    konf_c = [k for k in konf_relevant if k.get("art") != "web"]
    konf_w = [k for k in konf_relevant if k.get("art") == "web"]
    funde = " und ".join(x for x in ("RELEVANTE SCHWACHSTELLEN" if relevant else "",
                                     "GEFÄHRLICHE EINSTELLUNGEN" if konf_c else "",
                                     "EINSTELLUNGEN DER WEBSERVER" if konf_w else "") if x)
    print("%s: %s – %d Befunde, davon %d relevant (%d neu%s)%s%s; öffentlich: %s – Bericht: %s.md" % (
        prefix, {0: "OK", 1: funde, 2: "UNVOLLSTÄNDIG: " + "; ".join(problems)}[code],
        len(rows), len(relevant), sum(r["neu"] for r in relevant), ", %d aktiv ausgenutzt" % kev if kev else "",
        ", P1 ohne Schweregrad: %d" % unknown if unknown else "",
        "".join(x for x in (", %d gefährliche Einstellungen" % len(konf_c) if konf_c else "",
                            ", %d Einstellungen der Webserver" % len(konf_w) if konf_w else "")),
        ", ".join(public) or "nichts", base))
    for svc in services:          # Webadressen der Dienste, erreichbare zuerst
        if svc.get("webadressen"):
            offen = [e["url"] for e in svc["webadressen"] if e["erreichbar"]]
            intern = [e["url"] for e in svc["webadressen"] if not e["erreichbar"]]
            print("%s:   Webadressen %s: %s" % (prefix, svc["label"], "; ".join(
                x for x in ("erreichbar: " + webadressen_text(offen, 8) if offen else "",
                            "nicht von außen: " + webadressen_text(intern, 4) if intern else "") if x)))
    # relevante Funde auch auf der Konsole (Rundeck-Log, Mail), neue zuerst – Details im Bericht
    for k in sorted(konf_relevant, key=lambda k: not k["neu"]):
        print("%s:   %s%s" % (prefix, "NEU: " if k["neu"] and known is not None else "", konf_text(k)))
    for r in relevant:
        print("%s:   %s%s" % (prefix, "NEU: " if r["neu"] and known is not None else "", fund_text(r)))
    sys.stdout.flush()
    return code, base


def container_liste(infos, netze):
    """Laufende Container: (direkt erreichbare, übrige, {Container: [andere im selben Netzwerk-Namespace]}).
    Direkt erreichbar: veröffentlichte Ports, Host-Netzwerk, LAN-Netz (macvlan/ipvlan, geroutet) – auch über
    einen Container, dessen Netzwerk-Namespace mitgenutzt wird; vorgezogen auch Tunnel-Agenten (nach Image bzw.
    Befehl), damit ihre Ziele schon mit ihrer Erreichbarkeit geprüft werden."""
    public, rest = [], []
    for d in sorted(infos, key=name_von):
        published, host, lan, _ = direkt_erreichbar(d, infos, netze)
        cfg = d.get("Config") or {}
        befehl = " ".join([cfg.get("Image") or ""] + list(cfg.get("Entrypoint") or []) + list(cfg.get("Cmd") or []))
        tunnel = any(re.search(r"\b%s\b" % t, befehl) for t in TUNNEL)
        (public if published or host or lan or tunnel else rest).append(name_von(d))
    return public, rest, {name_von(d): netz_gruppe(d, infos) for d in infos}


# ===========================================================================
# Reverse Proxys und Tunnel direkt auf dem Host
# ===========================================================================
HOST_PROXYS = {"nginx", "apache2", "httpd", "httpd2"} | {"%s-%s" % (a, m) for a in ("apache2", "httpd", "httpd2")
                                                        for m in ("prefork", "worker", "event", "itk")} \
    | PROXY_UNBEKANNT | TUNNEL


class Host(object):
    """Gegenstück zu Container für den Host selbst (Proxys auf dem Host, Scan des Hosts): Abfragen mit dem Benutzer
    des jeweiligen Prozesses (nie mehr, ohne Angabe nobody), leerer Umgebung und festem Suchpfad."""
    has_sh = True
    ist_host = True
    info = {"Config": {"Env": []}}

    @property
    def name(self):
        if not hasattr(self, "_name"):
            rc, out = run(["hostname", "-f"], timeout=5)
            self._name = out.strip() if rc == 0 and out.strip() and " " not in out.strip() else os.uname().nodename
        return self._name

    def probe(self, cmd, user, stderr=False, path=SAFE_PATH):
        """Versionsabfrage wie im Container: mit den Rechten des laufenden Prozesses, Zeitlimit."""
        return self.exec(cmd, stderr=stderr, user=user, timeout=60, path=path or SAFE_PATH)

    def exec(self, cmd, input=None, binary=False, stderr=False, user=None, timeout=60, path=SAFE_PATH):
        uid, _, gid = (user or NOBODY).partition(":")
        if (uid, gid) == (str(os.geteuid()), str(os.getegid())):
            pre = []
        elif os.geteuid() == 0 and uid.isdigit() and gid.isdigit():
            pre = ["setpriv", "--reuid=" + uid, "--regid=" + gid, "--clear-groups", "--"]
        else:
            return 126, ""
        return run(pre + ["env", "-i", "PATH=" + path] + cmd, input, binary, stderr, timeout)

    def read_file(self, path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""


def host_proxy_pids(infos, proc="/proc", alle=False):
    """PIDs von Proxys und Tunneln direkt auf dem Host: Programmname bekannt, gleiches Wurzelverzeichnis wie
    dieses Skript (nicht in einem Container) und nicht in der cgroup eines Containers. alle: alle Prozesse des Hosts
    (Scan des Hosts), ohne diesen. Liefert (PIDs, Anzahl nicht lesbarer Prozesse)."""
    root = os.stat("/")
    ids = [d["Id"] for d in infos if d.get("Id")]
    pids, gesperrt = [], 0
    for pid in sorted((x for x in os.listdir(proc) if x.isdigit()), key=int):
        try:
            exe = os.readlink(os.path.join(proc, pid, "exe"))
            st = os.stat(os.path.join(proc, pid, "root"))
        except PermissionError:
            gesperrt += 1
            continue
        except OSError:             # Kernel-Thread oder beendet
            continue
        if (not alle and posixpath.basename(re.sub(r" \(deleted\)$", "", exe)) not in HOST_PROXYS) \
                or (alle and pid == str(os.getpid())) or (st.st_dev, st.st_ino) != (root.st_dev, root.st_ino):
            continue
        try:
            with open(os.path.join(proc, pid, "cgroup")) as f:
                cgroup = f.read()
        except OSError:
            cgroup = ""
        if not any(i in cgroup for i in ids):
            pids.append(pid)
    return pids, gesperrt


def host_proxys(infos):
    """Reverse Proxys und Tunnel direkt auf dem Host, z.B. nginx vor einem Container ohne veröffentlichten Port
    (proxy_pass http://172.18.0.5:3000). Liefert (Ziele [(Container, Port, Grund)], Dienste, Warnungen, Probleme).
    Ziele per Container-IP; nicht auswertbare Weiterleitungen machen alle Container mit Docker-Netz möglicherweise
    erreichbar (der Host erreicht sie über ihre IP)."""
    pids, gesperrt = host_proxy_pids(infos)
    warnings = ["Prozesse auf dem Host nicht vollständig lesbar (%d; Skript nicht als root?) – Reverse Proxys auf "
                "dem Host ggf. nicht erkannt" % gesperrt] if gesperrt else []
    if not pids:
        return [], [], warnings, []
    rc, out = run(["sh", "-s", "--"] + pids, input=PROC_SH)
    procs, _ = procs_auswerten(out)
    web = web_leer()
    web.update(self="Host", host_network=True, containers=container_index(infos),
               nachbarn=sorted(name_von(d) for d in infos if netze_von(spender_von(d, infos) or d)),
               loopback=sorted(name_von(d) for d in infos if im_host_netz(d, infos)))
    webserver_lesen(Host(), procs, web)
    web["loopback_ziele"] = loopback_ziele(loopback_ports(web), infos, "Host")
    for proxy in sorted({p["base"] for p in procs.values()} & {"traefik", "caddy"}):
        web["label_ziele"][proxy] = label_ziele(proxy, infos)
    services = mark_usage([], procs, {}, web)
    ziele = [(ct, port, grund.replace(svc["label"], svc["label"] + " auf dem Host", 1))
             for svc in services for ct, port, grund in svc["backends"]]
    for svc in services:
        svc["label"] += " auf dem Host"
        for b in svc["unresolved"]:
            warnings.append("Backend %s von %s keinem Container zuordenbar (anderer Server?)" % (b, svc["label"]))
        if svc["unklar"]:
            warnings.append("Weiterleitungen von %s nicht vollständig auswertbar (%s) – alle Container mit einem "
                            "Docker-Netz gelten als möglicherweise öffentlich" % (svc["label"], "; ".join(svc["unklar"])))
    return ziele, services, warnings, web["problems"]


def host_ausgeben(services, warnings, problems):
    """Ergebnis der Proxys auf dem Host auf der Konsole; Rückgabewert 2 bei unvollständiger Prüfung, sonst 0."""
    for warn in warnings:
        print("Host: WARNUNG: %s" % warn)
    for svc in services:
        ziele = OrderedDict()
        for ct, port, _ in svc["backends"]:
            ziele.setdefault(ct, []).append("alle Ports" if port == "*" else port)
        print("Host: %s – %s" % (svc["label"], ("erreichbar; Ziele in Containern: " + ", ".join(
            "%s (%s)" % (ct, ", ".join(p)) for ct, p in ziele.items()) if ziele else "erreichbar; keine Ziele in Containern")
            if svc["exposed"] else "nicht von außen erreichbar (nur Loopback)"))
    if problems:
        print("Host: UNVOLLSTÄNDIG: " + "; ".join(problems))
    sys.stdout.flush()
    return 2 if problems else 0


# ===========================================================================
# Scan des Hosts selbst (--host): Dienste direkt auf dem Server, z.B. nginx und Apache unter SLES
# ===========================================================================
# Verzeichnisse mit Anwendungen (neben dem Wurzel-Dateisystem; unter SLES mit btrfs eigene Subvolumes, die find
# -xdev sonst nicht betritt) – dazu Docroots und Arbeitsverzeichnisse der laufenden Dienste
HOST_WURZELN = ("/srv", "/opt", "/var/www", "/usr/local")
# nie durchsuchen: Daten der Container (eigene Scans), Snapshots, flüchtige und Systemverzeichnisse
HOST_AUSGENOMMEN = ("/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/lib/docker", "/var/lib/containerd",
                    "/var/lib/containers", "/var/lib/kubelet", "/var/log", "/var/cache", "/.snapshots")
# Go-Programme nur außerhalb der Verzeichnisse der Distribution suchen (dort stammt alles aus Paketen)
HOST_OHNE_GO = ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share", "/bin", "/sbin",
                "/lib", "/lib64", "/boot")


def _prune(pfade):
    return r"\( " + " -o ".join("-path %s" % p for p in pfade) + r" \) -prune"


_STANDARD_PRUNE = r"\( -path /proc -o -path /sys -o -path /dev \) -prune"
assert FIND_SH.count(_STANDARD_PRUNE) == 2
_teile = FIND_SH.split(_STANDARD_PRUNE)
HOST_FIND_SH = _teile[0] + _prune(HOST_AUSGENOMMEN) + _teile[1] + _prune(HOST_AUSGENOMMEN + HOST_OHNE_GO) + _teile[2]


def geraet(pfad):
    """Dateisystem eines Verzeichnisses (für find -xdev)."""
    try:
        return os.stat(pfad).st_dev
    except OSError:
        return None


def host_wurzeln(procs, web):
    """Verzeichnisse, die neben "/" durchsucht werden (je Dateisystem, -xdev): HOST_WURZELN, Docroots (und
    Projektverzeichnis darüber) und Arbeitsverzeichnisse der Dienste mit Port bzw. hinter einem Webserver."""
    kandidaten = list(HOST_WURZELN)
    for roots in web["docroots"].values():
        for r in roots:
            kandidaten += [r, posixpath.dirname(r.rstrip("/"))]
    kandidaten += [p["cwd"] for p in procs.values() if (p["ports"] or p.get("frontends")) and p["cwd"]]
    result = []
    for k in kandidaten:
        k = posixpath.normpath(k) if k.startswith("/") else ""
        if k in ("", "/") or any(under(k, x) for x in HOST_AUSGENOMMEN) or k in result or not os.path.isdir(k):
            continue
        # schon erfasst: unter einem anderen Verzeichnis (bzw. "/") auf demselben Dateisystem (find -xdev)
        if any(under(k, r) and geraet(k) == geraet(r) for r in result + ["/"]):
            continue
        result.append(k)
    return result


def host_dateien(wurzeln):
    """Metadaten-Dateien und Archive auf dem Host (wie im Container per find/tar, als root, nichts wird entpackt).
    Liefert (Dateien, weitere Komponenten, Beschreibung, Probleme)."""
    files, extra, meldungen = {}, [], []
    ok = stream_tar(["env", "-i", "PATH=" + SAFE_PATH, "sh", "-s", "--"] + list(wurzeln), files, extra,
                    input=HOST_FIND_SH, meldungen=meldungen)
    meldungen = list(OrderedDict.fromkeys(meldungen))
    problems = [] if ok else ["Dateien auf dem Host nicht vollständig lesbar (%s)" % (
        "; ".join(meldungen[:3]) + (" … und %d weitere" % (len(meldungen) - 3) if len(meldungen) > 3 else "")
        if meldungen else "Fehler oder Zeitüberschreitung")]
    return files, extra, "find/tar auf dem Host (%s)" % " ".join(["/"] + list(wurzeln)), problems


def kernel_markieren(comps, release=None, cmp=cmp_rpm):
    """Kernel-Pakete auf dem Host: das des laufenden Kernels gilt als genutzt ("Kernel (läuft)", P2), die übrigen
    nicht (P4). Liefert Warnungen: neuerer Kernel installiert (Neustart nötig), Live-Patches (Kernel-Funde können
    schon behoben sein)."""
    release = release or os.uname().release
    basis, _, flavor = release.rpartition("-")
    kerne = [c for c in comps if kernel_paket(c)]
    laeuft = []
    for c in kerne:
        ver = c["version"].split(":")[-1]
        if c["name"] == "linux-image-" + release or (
                c["name"] in ("kernel-" + flavor, "kernel", "kernel-core") and (
                    ver == basis or ver.startswith(basis + ".") or release.startswith(ver + "."))):
            laeuft.append(c)
            c["aktiv"].append("Kernel (läuft)")
        else:
            c["hinweise"].append("nicht der laufende Kernel (%s)" % release)
    warnungen = []
    for c in laeuft:
        neuer = [x for x in kerne if x["name"] == c["name"] and x is not c and cmp(x["version"], c["version"]) > 0]
        if neuer:
            n = max(neuer, key=cmp_to_key(lambda x, y: cmp(x["version"], y["version"])))
            warnungen.append("Neuerer Kernel installiert (%s %s), läuft noch %s – Neustart nötig; bis dahin gelten "
                             "die Lücken des laufenden Kernels" % (n["name"], n["version"], release))
    live = sorted({c["name"] for c in comps if c["typ"] == "os-paket" and c["name"].startswith("kernel-livepatch")})
    if live:
        warnungen.append("Kernel-Live-Patches installiert (%s): Funde im laufenden Kernel können bereits behoben "
                         "sein (nicht ausgewertet)" % ", ".join(live[:3]))
    return warnungen


def host_web(h, procs, infos):
    """Webserver und Netz des Hosts: Konfiguration von nginx/Apache, Container (Ziele von Proxys), Schnittstellen
    und firewalld."""
    web = web_leer()
    web.update(self="Host", host_network=True, ist_host=True, fqdn=h.name, containers=container_index(infos),
               nachbarn=sorted(name_von(d) for d in infos if netze_von(spender_von(d, infos) or d)),
               loopback=sorted(name_von(d) for d in infos if im_host_netz(d, infos)), via_proxy={})
    webserver_lesen(h, procs, web)
    web["loopback_ziele"] = loopback_ziele(loopback_ports(web), infos, "Host")
    for proxy in sorted({p["base"] for p in procs.values()} & {"traefik", "caddy"}):
        web["label_ziele"][proxy] = label_ziele(proxy, infos)
    web["interfaces"] = schnittstellen()
    web["firewall"] = firewall_lesen()
    return web


def firewall_text(fw):
    if not fw.get("aktiv"):
        return "firewalld nicht aktiv" + (" – " + fw["hinweis"] if fw.get("hinweis") else "")
    if fw.get("fehler"):
        return "firewalld nicht abfragbar (%s)" % fw["fehler"]
    zonen = OrderedDict()
    for i, z in sorted(fw["zuordnung"].items()):
        zonen.setdefault(z, []).append(i)
    return "firewalld aktiv (Runtime), Standardzone %s%s%s" % (
        fw["default"], "".join("; Zone %s: %s" % (z, ", ".join(i)) for z, i in zonen.items()),
        "".join("; Zone %s für Quellen %s" % (z, " ".join(q)) for z, q in fw["quellen"].items()))


def scan_host(a, infos=()):
    """Den Host selbst scannen: Prozesse außerhalb von Containern, OS-Pakete (rpm/dpkg), Anwendungen in
    Docroots und Anwendungsverzeichnissen, Kernel; Erreichbarkeit über Schnittstellen und firewalld; Webadressen
    und Einstellungen der Webserver. Liefert (Rückgabewert, Ziele in Containern [(Container, Port, Grund)], Basis
    der Berichtsdateien)."""
    h = Host()
    log("Erfasse Host '%s' ..." % h.name)
    how, problems, warnings = {}, [], []
    if os.geteuid() != 0:
        problems.append("Scan des Hosts nicht als root: Prozesse, Dateien und Firewall nicht vollständig lesbar")
    pids, gesperrt = host_proxy_pids(infos, alle=True)
    if gesperrt:
        problems.append("%d Prozesse auf dem Host nicht lesbar" % gesperrt)
    procs, _ = procs_auswerten(proc_lesen(pids))
    if not procs:
        problems.append("Prozesse auf dem Host nicht lesbar")
    how["procs"] = "über /proc des Hosts (%d Prozesse außerhalb von Containern)" % len(procs)
    web = host_web(h, procs, infos)
    problems.extend(web["problems"])
    how["wurzeln"] = host_wurzeln(procs, web)
    files, extra, how["files"], probs = host_dateien(how["wurzeln"])
    problems.extend(probs)
    osinfo = os_release(files)
    osinfo["host"] = True
    pkgs, owners, how["pkgdb"] = os_packages(h, files)
    lang = npm_packages(files) + composer_packages(files) + pypi_packages(files) + extra
    if how["pkgdb"].startswith("rpm"):
        owners.update(rpm_owners(h, {norm(f) for p in procs.values() for f in p["maps"] | {p["exe"]}} |
                                 {x["datei"] for x in lang}))
    how["os_owned"] = sum(1 for x in lang if owners.get(norm(x["datei"])))
    comps = pkgs + [x for x in lang if not owners.get(norm(x["datei"]))]
    comps += probe_runtimes(h, procs, owners)
    web["venvs"] = {posixpath.dirname(f) for f in files if f.endswith("/pyvenv.cfg")}
    services = mark_usage(comps, procs, owners, web)
    warnings.extend(kernel_markieren(comps, cmp=cmp_rpm if how["pkgdb"].startswith("rpm") else cmp_dpkg))
    for svc in services:
        for b in svc["unresolved"]:
            warnings.append("Backend %s von %s keinem Container bzw. Dienst des Hosts zuordenbar (anderer Server? "
                            "Dort gesondert scannen)" % (b, svc["label"]))
        if svc["unklar"]:
            warnings.append("Weiterleitungen von %s nicht vollständig auswertbar (%s) – alle Container mit einem "
                            "Docker-Netz gelten als möglicherweise öffentlich" % (svc["label"], "; ".join(svc["unklar"])))
    warnings.extend(root_dienste(h, procs, web))
    warnings.extend(offene_datendienste(procs, web))
    how["firewall"] = firewall_text(web["firewall"])
    if web["firewall"].get("fehler") or web["firewall"].get("hinweis"):
        warnings.append("Firewall: %s%s" % (how["firewall"], "" if "gelten als offen" in how["firewall"] else
                                            " – Ports gelten im Zweifel als erreichbar"))
    how["warnungen"] = warnings
    webadressen(services, web)
    komponenten_webadressen(comps, services)
    konf = webserver_pruefen(services, web)
    tls, tls_warnungen = tls_pruefen(h, services, web)
    konf += tls
    warnings.extend(tls_warnungen)
    kurz = re.sub(r"[^A-Za-z0-9_.-]", "_", h.name.split(".")[0]) or "host"
    code, base = abschliessen(h, "Host", "host_" + kurz, "bekannt-host.json", a, comps, pkgs, osinfo, services,
                              procs, web, how, problems, konf)
    ziele = [(ct, port, grund.replace(svc["label"], svc["label"] + " auf dem Host", 1))
             for svc in services for ct, port, grund in svc["backends"]]
    return code, ziele, base


def docker_vorhanden():
    """Gibt es auf diesem Server Docker? Nein, wenn der Befehl fehlt oder weder Daemon noch Socket da sind (dann
    wird nur der Host geprüft). Ist Docker eingerichtet, aber nicht erreichbar, ist das ein Fehler (docker_lage)."""
    if not shutil.which("docker"):
        return False
    return bool(os.environ.get("DOCKER_HOST") or _prozesse_namens("dockerd")
                or any(os.path.exists(p) for p in ("/var/run/docker.sock", "/run/docker.sock")))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data_dir, local_db = os.path.join(here, "daten"), os.path.join(here, "osv-db")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("container", nargs="?", help="Name oder ID des laufenden Containers")
    ap.add_argument("ausgabe", nargs="?", default=".", help="Ausgabeverzeichnis (Standard: aktuelles Verzeichnis)")
    ap.add_argument("--oeffentliche", action="store_true",
                    help="alle Container mit veröffentlichten Ports scannen, dazu deren Backends hinter einem Proxy")
    ap.add_argument("--alle-container", action="store_true",
                    help="wie --oeffentliche, danach alle übrigen laufenden Container (empfohlen, so im Wrapper): "
                         "was nicht als erreichbar erkannt wird, fehlt so nicht, sondern erscheint mindestens als P2")
    ap.add_argument("--host", action="store_true",
                    help="den Host selbst prüfen: Dienste direkt auf dem Server (nginx, Apache, php-fpm …), OS-Pakete, "
                         "Kernel, firewalld, Webadressen; mit --alle-container/--oeffentliche danach die Container, "
                         "ohne Docker nur den Host (so im Wrapper)")
    ap.add_argument("--db", action="append", metavar="DIR",
                    help="Verzeichnis mit OSV-Daten, mehrfach möglich: je Ökosystem gilt das erste, das es enthält "
                         "(Standard: daten und osv-db neben diesem Skript)")
    ap.add_argument("--daten-erzeugen", metavar="VERZEICHNIS", help=argparse.SUPPRESS)   # für die GitHub Action
    ap.add_argument("--eol-daten-erzeugen", metavar="DATEI", help=argparse.SUPPRESS)
    ap.add_argument("--kev-daten-erzeugen", metavar="DATEI", help=argparse.SUPPRESS)
    ap.add_argument("--ausnahmen", metavar="DATEI",
                    help="Ausnahmeliste: je Zeile \"<Kennung> <Paket oder *> <gültig bis JJJJ-MM-TT> <Begründung>\"; "
                         "passende Funde zählen nicht als relevant (README: Ausnahmen)")
    ap.add_argument("--db-aktualisieren", action="store_true",
                    help="Daten aktualisieren: im Git-Checkout den Branch daten nach daten/ (nie den Code), sonst direkt "
                         "von OSV (Internet nötig; nach dem ersten Mal nur Änderungen)")
    ap.add_argument("--voll", action="store_true", help="mit --db-aktualisieren: Gesamtexporte neu laden")
    ap.add_argument("--oekosysteme", help="mit --db-aktualisieren: zusätzlich diese Ökosysteme direkt von OSV laden "
                                           "(z.B. SUSE); ohne daten/ Standard: " + ",".join(OSV_ECOSYSTEMS))
    ap.add_argument("--nur-behebbare", action="store_true",
                    help="für den Rückgabewert nur Funde zählen, für die es einen Fix gibt")
    ap.add_argument("--alle", action="store_true", help="alle Befunde in die Tabelle (sonst P3/P4 nur CRITICAL/HIGH)")
    ap.add_argument("--user", default="0", help="Benutzer für docker exec (Standard 0 = root, nötig für /proc)")
    ap.add_argument("--version", action="version", version="container-security-scan " + VERSION)
    a = ap.parse_args()
    mehrere = a.oeffentliche or a.alle_container
    if (mehrere or a.host) and a.container:   # dann ist das erste Argument das Ausgabeverzeichnis
        a.ausgabe, a.container = a.container, None
    if a.daten_erzeugen:
        daten_erzeugen(a.daten_erzeugen)
        return 0
    if a.eol_daten_erzeugen:
        eol_daten_erzeugen(a.eol_daten_erzeugen)
        return 0
    if a.kev_daten_erzeugen:
        kev_daten_erzeugen(a.kev_daten_erzeugen)
        return 0
    a.dbdirs = a.db or [d for d in (data_dir, local_db) if os.path.isdir(d)]
    if a.db_aktualisieren:
        if a.db and len(a.db) > 1:
            ap.error("--db-aktualisieren: nur ein --db angeben (Zielverzeichnis)")
        if os.geteuid() == 0:
            # Daten aus dem Netz nicht als root schreiben: Gehört das Zielverzeichnis einem anderen Benutzer, könnte
            # er root über symbolische Links (z.B. stand.json.tmp -> /etc/...) beliebige Dateien überschreiben lassen
            raise ScanError("--db-aktualisieren als root abgelehnt: Daten als eigener Benutzer ohne Rechte laden "
                            "(z.B. runuser -u csscan -- ... --db DIR --db-aktualisieren) und beim Scan mit --db "
                            "verwenden (README: \"Installation und Betrieb\").")
        # Daten liegen im Branch "daten" (ohne Code), Code im Branch "main". Hier wird nur der Daten-Branch geholt
        # bzw. aktualisiert, nie der Code: den aktualisiert man von Hand nach Prüfung (git pull im Code-Checkout).
        daten_git = not a.db and os.path.isdir(os.path.join(data_dir, ".git"))
        code_git = not a.db and not os.path.exists(data_dir) and os.path.isdir(os.path.join(here, ".git"))
        repo_data = daten_git or code_git
        if not a.db and not daten_git and os.path.isdir(data_dir) and os.path.isdir(os.path.join(here, ".git")):
            raise ScanError("%s ist kein Git-Checkout des Branches %s: entfernen und --db-aktualisieren erneut "
                            "aufrufen oder das Verzeichnis mit --db angeben" % (data_dir, DATEN_BRANCH))
        if daten_git:
            rc, out = run(["git", "-C", data_dir, "pull", "--ff-only", "--quiet"], stderr=True, timeout=600)
            if rc != 0:
                raise ScanError("git pull in daten/ fehlgeschlagen: " + out.strip()[-300:])
            log("Daten (Branch %s) in daten/ per git pull aktualisiert" % DATEN_BRANCH)
        elif code_git:
            rc, url = run(["git", "-C", here, "remote", "get-url", "origin"], timeout=60)
            if rc != 0 or not url.strip():
                raise ScanError("Git-Remote origin nicht ermittelbar; Daten von Hand holen: git clone --single-branch "
                                "--branch %s <url> daten" % DATEN_BRANCH)
            rc, out = run(["git", "clone", "--quiet", "--single-branch", "--branch", DATEN_BRANCH, url.strip(), data_dir],
                          stderr=True, timeout=1800)
            if rc != 0:
                raise ScanError("git clone des Branches %s fehlgeschlagen: %s" % (DATEN_BRANCH, out.strip()[-300:]))
            log("Daten (Branch %s) nach daten/ geholt" % DATEN_BRANCH)
        if a.oekosysteme or not repo_data:
            osv_update(a.db[0] if a.db else local_db, [e for e in (a.oekosysteme or ",".join(OSV_ECOSYSTEMS)).split(",") if e], a.voll)
        if not repo_data:                 # ohne Git: EOL- und KEV-Daten direkt von der Quelle
            for label, func, fname in (("EOL-Daten von endoflife.date", eol_daten_erzeugen, "eol-daten.json"),
                                       ("KEV-Daten der CISA", kev_daten_erzeugen, "kev.json")):
                try:
                    func(os.path.join(a.db[0] if a.db else local_db, fname))
                    log(label + " aktualisiert")
                except (OSError, ValueError, KeyError, TypeError, ScanError) as e:
                    log("WARNUNG: %s nicht aktualisiert: %s" % (label, e))
        a.dbdirs = a.db or [d for d in (data_dir, local_db) if os.path.isdir(d)]
        if not a.container and not mehrere and not a.host:
            return 0
    if not a.container and not mehrere and not a.host:
        ap.error("Container fehlt (oder --host, --oeffentliche bzw. --alle-container)")
    # Berichte enthalten Kommandozeilen der Prozesse (oft mit Passwörtern) und Konfigurationsauszüge:
    # nur für den aufrufenden Benutzer lesbar, auch ohne umask im Aufruf (cron, Rundeck, von Hand)
    os.umask(0o077)
    if not a.dbdirs or not all(os.path.isdir(d) for d in a.dbdirs):
        raise ScanError("keine OSV-Daten gefunden (%s) – zuerst: %s --db-aktualisieren" % (", ".join(a.db or [data_dir]), sys.argv[0]))
    a.ausnahmen_liste = ausnahmen_laden(a.ausnahmen) if a.ausnahmen else []
    print("container-security-scan %s" % VERSION)
    if a.host:
        # Host zuerst: Ziele seiner Proxys in Containern gelten als erreichbar; ohne Docker nur der Host
        infos, netze, docker_fehler = [], {}, None
        if docker_vorhanden():
            try:
                infos, netze = docker_lage()
            except ScanError as e:
                docker_fehler = str(e)
                log("FEHLER: %s" % e)
        elif mehrere:
            print("Docker nicht vorhanden – nur der Host wird geprüft.")
        try:
            host_code, ziele, _ = scan_host(a, infos)
        except ScanError as e:
            log("FEHLER beim Host: %s" % e)
            host_code, ziele = 2, []
        if not mehrere:
            if docker_fehler:
                print("Host: WARNUNG: Container nicht ermittelbar (%s) – Ziele von Proxys in Containern ggf. nicht "
                      "zugeordnet" % docker_fehler)
            return host_code
        if docker_fehler:
            return 2
        if not infos:
            return host_code
        public, rest, gruppen = container_liste(infos, netze)
        return container_lauf(a, public, rest, gruppen, ziele, host_code)
    if not mehrere:
        # auch ein Einzelscan kennt Proxys auf dem Host (ohne die in anderen Containern)
        try:
            infos, netze = docker_lage()
        except ScanError:
            return scan_container(a.container, a)[0]       # meldet den Fehler selbst
        d = next((x for x in infos if a.container in (name_von(x), x.get("Id")) or x.get("Id", "").startswith(a.container)), {})
        ziele, services, warnings, problems = host_proxys(infos)
        host_code = host_ausgeben(services, warnings, problems)
        namen = {name_von(d)} | set(netz_gruppe(d, infos)) if d else set()
        via = {}
        for ct, port, reason in ziele:
            if ct in namen and reason not in via.setdefault(port, []):
                via[port].append(reason)
        code = scan_container(a.container, a, via)[0]
        return 2 if 2 in (code, host_code) else code
    try:
        infos, netze = docker_lage()
        public, rest, gruppen = container_liste(infos, netze)
        ziele, services, warnings, problems = host_proxys(infos)
    except ScanError as e:
        log("FEHLER: %s" % e)
        return 2
    host_code = host_ausgeben(services, warnings, problems)
    return container_lauf(a, public, rest, gruppen, ziele, host_code)


def container_lauf(a, public, rest, gruppen, ziele, host_code):
    """Erreichbare Container und ihre Ziele, mit --alle-container danach die übrigen. ziele: Ziele von Proxys auf
    dem Host [(Container, Port, Grund)]; host_code: Ergebnis des Hosts (fließt in den Gesamtwert ein)."""

    # Erreichbare Container, dabei (wiederholt) deren Backends in anderen Containern – vorgezogen, damit sie
    # schon mit ihrer Erreichbarkeit geprüft werden; mit --alle-container danach die übrigen
    queue = OrderedDict((n, {}) for n in public)
    for ct, port, reason in ziele:          # Ziele von Proxys auf dem Host: erreichbar, vorgezogen
        for ziel in [ct] + gruppen.get(ct, []):
            queue.setdefault(ziel, {}).setdefault(port, []).append(reason)
            queue.move_to_end(ziel, last=False)
    spaeter = list(rest) if a.alle_container else []
    if not queue and not spaeter:
        print("Keine laufenden Container gefunden." if a.alle_container else "Keine Container mit veröffentlichten Ports gefunden.")
        return host_code
    vias, codes, reports, runs = {}, {}, {}, Counter()
    while queue or spaeter:
        if not queue:
            n = spaeter.pop(0)
            if n not in vias:
                queue[n] = {}
            continue
        name, via = queue.popitem(last=False)
        vias[name] = via
        runs[name] += 1
        try:
            codes[name], backends, base = scan_container(name, a, via)
        except ScanError as e:
            if run(["docker", "ps", "-q"])[0] == 0 and run(["docker", "inspect", "--type", "container", name])[0] != 0:
                print("%s: übersprungen – Container nicht mehr vorhanden (z.B. mit --rm beendet)" % name)
                del vias[name]
                continue
            log("FEHLER bei %s: %s" % (name, e))
            codes[name], backends, base = 2, [], None
        if reports.get(name) and reports[name] != base:   # erneute Prüfung ersetzt den ersten Bericht dieses Laufs
            # (bei gleichem Namen – Prüfung in derselben Sekunde – ist er schon überschrieben)
            for ext in (".md", ".cdx.json", ".sha256"):
                if os.path.exists(reports[name] + ext):
                    os.remove(reports[name] + ext)
        reports[name] = base
        for ct, port, reason in backends:
            # bei gemeinsamem Netzwerk-Namespace lauscht ggf. ein anderer Container der Gruppe auf dem Port
            for ziel in [ct] + gruppen.get(ct, []):
                merged = {k: list(v) for k, v in (queue.get(ziel) or vias.get(ziel) or {}).items()}
                if reason in merged.get(port, []):
                    continue
                merged.setdefault(port, []).append(reason)
                if ziel in vias and runs[ziel] >= 3:
                    continue          # Schutz vor Endlosschleifen bei gegenseitigen Proxys
                queue[ziel] = merged
                queue.move_to_end(ziel, last=False)
    code = 2 if 2 in codes.values() or host_code == 2 else 1 if 1 in codes.values() or host_code == 1 else 0
    print("Gesamt: %s%d Container geprüft – %s" % ("Host und " if a.host else "", len(codes), {
        0: "OK", 1: "RELEVANTE FUNDE (Schwachstellen bzw. gefährliche Einstellungen)",
        2: "mindestens eine Prüfung UNVOLLSTÄNDIG"}[code]))
    return code


if __name__ == "__main__":
    # Python 3.6 mit LANG=C (cron, minimale SSH-Sitzung) gibt sonst nur ASCII aus und bricht an Umlauten ab
    if (sys.stdout.encoding or "").lower() in ("ascii", "ansi_x3.4-1968"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    try:
        sys.exit(main())
    except ScanError as e:
        log("FEHLER: %s" % e)
        sys.exit(2)
    except Exception:   # unerwarteter Fehler: nie als "keine Befunde" (0) oder "Befunde" (1) melden
        traceback.print_exc()
        sys.exit(2)
