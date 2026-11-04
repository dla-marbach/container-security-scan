"""Gemeinsame Hilfen für die Tests: Skript als Modul laden, Komponenten und Daten bauen."""
import importlib.util
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKRIPT = os.environ.get("CSS_SKRIPT") or os.path.join(ROOT, "container-security-scan.py")

_spec = importlib.util.spec_from_file_location("container_security_scan", SKRIPT)
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)


def proc(pid, exe, argv=None, cwd="/", ports=None, maps=(), files=(), env=None, user="0:0"):
    """Prozess wie von collect_procs geliefert."""
    p = {"pid": str(pid), "exe": exe, "cwd": cwd, "argv": list(argv or [exe]), "user": user,
         "maps": set(maps), "files": set(files), "env": dict(env or {}), "ports": dict(ports or {})}
    p["base"] = os.path.basename(exe)
    p["label"] = p["base"] + (":" + ",".join(p["ports"]) if p["ports"] else "")
    return p


def web(**kw):
    """Webserver-Kontext wie von collect_web geliefert (ohne Docker)."""
    w = {"docroots": {}, "backends": {}, "vhosts": {}, "upstreams": {}, "modphp": set(), "raw": [],
         "published": {}, "containers": {}, "via_proxy": {}, "problems": [], "host_network": False,
         "self": "app", "venvs": set()}
    w.update(kw)
    return w


def schreibe_jsonl(verzeichnis, oekosystem, records, datei="00.jsonl"):
    d = os.path.join(verzeichnis, oekosystem)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, datei), "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def eintrag(vid, oekosystem, name, events, typ="ECOSYSTEM", **extra):
    """OSV-Eintrag mit einem betroffenen Paket."""
    affected = {"package": {"ecosystem": oekosystem, "name": name},
                "ranges": [{"type": typ, "events": events}]}
    affected.update(extra.pop("affected_extra", {}))
    rec = {"id": vid, "published": "2026-10-01T00:00:00Z", "affected": [affected]}
    rec.update(extra)
    return rec
