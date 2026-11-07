"""Bericht (Markdown), SBOM (CycloneDX) und Gesamtlauf scan_container mit Rückgabewerten – ohne Docker."""
import argparse
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from _laden import scanner, proc, web, schreibe_jsonl, eintrag

DEBIAN = {"id": "debian", "version": "12.7", "pretty": "Debian GNU/Linux 12"}
INFO = {"Config": {"Image": "example/app:1"}, "Image": "sha256:" + "a" * 64, "Id": "c" * 64, "Name": "/app",
        "State": {"StartedAt": "2026-11-04T00:00:00Z", "Running": True}, "Mounts": [],
        "HostConfig": {}, "NetworkSettings": {"Ports": {}}}


def C(*a, **kw):
    return scanner.comp(*a, **kw)


class FakeContainer(object):
    def __init__(self, name="app"):
        self.name, self.id, self.info, self.user = name, "c" * 64, dict(INFO, Name="/" + name), "0"


def fake_run(cmd, *a, **kw):
    if cmd[:2] == ["docker", "top"]:
        return 0, "PID USER COMMAND\n1 root nginx\n"
    if cmd[:3] == ["docker", "image", "inspect"]:
        return 0, json.dumps([{"RepoDigests": ["example/app@sha256:" + "b" * 64]}])
    return 1, ""


class Hilfen(unittest.TestCase):
    def test_fix_text(self):
        self.assertEqual(scanner.fix_text("1.2.3", ""), "")
        self.assertEqual(scanner.fix_text("1.2.3", "1.2.4"), "1.2.4")
        self.assertEqual(scanner.fix_text("20.1.0", "22.3.0"), "22.3.0 (anderer Versionszweig: Upgrade nötig)")
        self.assertEqual(scanner.fix_text("1:2.0-1", "1:2.1-1"), "1:2.1-1")

    def test_md_und_aktiv(self):
        self.assertEqual(scanner.md("a|b\nc"), "a/b c")
        c = C("npm", "a", "1")
        c["aktiv"] = ["d1", "d2", "d3", "d4", "d5"]
        self.assertEqual(scanner.aktiv(c), "d1;d2;d3;… (+2)")


class Bericht(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.p1 = C("npm", "express", "4.0.0", "/app/node_modules/express")
        self.p1["aktiv"] = ["node:3000"]
        self.p2 = C("os-paket", "libssl3", "3.0", src="openssl")
        self.p2["aktiv"] = ["intern:9000"]
        self.p3 = C("pypi", "pip", "23.0", "/usr/lib")
        self.p3["aktiv_ohne_port"] = ["cron (ohne Port)"]
        self.findings = [
            {"comp": self.p1, "id": "CVE-1", "sev": "HIGH", "fix": "4.0.1", "title": "Fehler | mit Pipe"},
            {"comp": self.p1, "id": "CVE-2", "sev": "CRITICAL", "fix": "", "title": "ohne Fix"},
            {"comp": self.p2, "id": "CVE-3", "sev": "CRITICAL", "fix": "3.1", "title": "intern"},
            {"comp": self.p2, "id": "CVE-4", "sev": "HIGH", "fix": "3.1", "title": "intern, nicht relevant"},
            {"comp": self.p3, "id": "CVE-5", "sev": "MEDIUM", "fix": "", "title": "P3 MEDIUM"},
            {"comp": self.p1, "id": "GHSA-u", "sev": "UNKNOWN", "fix": "", "title": "ohne Bewertung"}]
        self.services = [{"label": "node:3000", "name": "node", "version": "20.1.0", "exposed": True,
                          "description": "Port 3000/tcp (alle) veröffentlicht als 0.0.0.0:3000"}]

    def bericht(self, nur_behebbare=False, known=None, problems=(), alle=False, warnungen=()):
        path = os.path.join(self.tmp, "b.md")
        how = {"pkgdb": "dpkg", "files": "find/tar", "procs": "im Container", "os_owned": 0, "warnungen": list(warnungen)}
        w = web(raw=["--- nginx -T (Auszug)\nserver {"])
        stale = proc(5, "/usr/sbin/nginx", maps={"/usr/lib/libssl.so.3 (deleted)", "/dev/zero (deleted)"})
        with mock.patch.object(scanner, "run", side_effect=fake_run):
            rows, relevant = scanner.write_report(
                path, FakeContainer(), DEBIAN, [self.p1, self.p2, self.p3], self.services, {"5": stale}, w, how,
                [dict(f) for f in self.findings], {"problems": list(problems), "text": "OSV, Stand heute"},
                alle, nur_behebbare, known)
        with open(path, encoding="utf-8") as f:
            return rows, relevant, f.read()

    def test_relevante_funde_und_prioritaeten(self):
        rows, relevant, text = self.bericht()
        self.assertEqual([(r["prio"], r["id"]) for r in rows],
                         [(1, "CVE-2"), (1, "CVE-1"), (1, "GHSA-u"), (2, "CVE-3"), (2, "CVE-4"), (3, "CVE-5")])
        self.assertEqual(sorted(r["id"] for r in relevant), ["CVE-1", "CVE-2", "CVE-3"])
        self.assertIn("**3 relevante Schwachstellen**", text)
        self.assertIn("Hinweis: 1 Befunde in P1 haben noch keinen Schweregrad", text)
        self.assertIn("Fehler / mit Pipe", text)
        self.assertIn("## Befunde (5 von 6;", text)          # P3 MEDIUM ohne --alle ausgeblendet
        self.assertIn("PID 5 (/usr/sbin/nginx): /usr/lib/libssl.so.3 (deleted)", text)
        self.assertNotIn("/dev/zero", text)
        self.assertIn("### Webserver-Konfiguration", text)
        self.assertIn("## Befunde (6 von 6", self.bericht(alle=True)[2])

    def test_nur_behebbare_und_neu(self):
        _, relevant, text = self.bericht(nur_behebbare=True, known={("express", "4.0.0", "CVE-1")})
        self.assertEqual([(r["id"], r["neu"]) for r in relevant], [("CVE-3", True), ("CVE-1", False)])
        self.assertIn("Davon **1 neu** seit dem letzten Lauf.", text)
        self.assertIn("- NEU: **CVE-3**", text)
        self.assertIn("; nur mit verfügbarem Fix", text)

    def test_probleme_und_warnungen_stehen_oben(self):
        _, _, text = self.bericht(problems=["Daten fehlen für: Ubuntu"], warnungen=["Supportende: vue 2.7.16"])
        ergebnis = text.split("## Ergebnis")[1].split("## Laufende Dienste")[0]
        self.assertIn("**PRÜFUNG UNVOLLSTÄNDIG (Rückgabewert 2):** Daten fehlen für: Ubuntu", ergebnis)
        self.assertIn("**Warnung:** Supportende: vue 2.7.16", ergebnis)


class Sbom(unittest.TestCase):
    def test_purls_und_struktur(self):
        comps = [C("os-paket", "libssl3", "1:3.0.15-1", arch="amd64", src="openssl", srcver="1:3.0.15-1"),
                 C("npm", "@scope/pkg", "1.0.0", dev=True), C("composer", "laravel/framework", "v10.0.0"),
                 C("pypi", "Foo_Bar", "1.0"), C("maven", "org.x:y", "2.0"), C("maven", "y", "2.0", maven_key="*:y"),
                 C("go", "golang.org/x/net", "v0.1.0"), C("js-lib", "jquery", "1.10.2"),
                 C("runtime", "php", "8.3.1"), C("php-ext", "redis", "6.0.2"), C("host", "linux-kernel", "6.1")]
        services = [{"label": "php-fpm:9000", "name": "php-fpm", "version": "8.3.1", "exe": "/usr/sbin/php-fpm",
                     "endpoints": ["tcp://0.0.0.0:9000"], "description": "Port 9000"}]
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "x.cdx.json")
        with mock.patch.object(scanner, "run", side_effect=fake_run):
            scanner.write_cdx(path, FakeContainer(), DEBIAN, comps, services)
        bom = scanner.json_datei(path)
        self.assertEqual((bom["bomFormat"], bom["specVersion"]), ("CycloneDX", "1.5"))
        entries = {c["bom-ref"]: c for c in bom["components"]}
        purls = [entries["c%d" % i].get("purl") for i in range(1, len(comps) + 1)]
        self.assertEqual(purls, [
            "pkg:deb/debian/libssl3@3.0.15-1?arch=amd64&epoch=1&upstream=openssl&distro=debian-12.7",
            "pkg:npm/%40scope/pkg@1.0.0", "pkg:composer/laravel/framework@v10.0.0", "pkg:pypi/foo-bar@1.0",
            "pkg:maven/org.x/y@2.0", None, "pkg:golang/golang.org/x/net@v0.1.0", "pkg:npm/jquery@1.10.2",
            "pkg:generic/php@8.3.1", "pkg:generic/php-ext-redis@6.0.2", None])
        self.assertEqual(entries["c2"]["scope"], "optional")
        self.assertEqual(entries["c9"]["cpe"], "cpe:2.3:a:php:php:8.3.1:*:*:*:*:*:*:*")
        self.assertEqual(entries["c11"]["type"], "platform")
        trivy = {p["name"]: p["value"] for p in entries["c1"]["properties"] if p["name"].startswith("aquasecurity")}
        self.assertEqual(trivy, {"aquasecurity:trivy:SrcName": "openssl", "aquasecurity:trivy:SrcVersion": "3.0.15",
                                 "aquasecurity:trivy:SrcRelease": "1", "aquasecurity:trivy:SrcEpoch": "1"})
        self.assertEqual(bom["dependencies"][1], {"ref": "os", "dependsOn": ["c1"]})
        self.assertEqual(bom["services"][0]["endpoints"], ["tcp://0.0.0.0:9000"])
        self.assertIn({"name": "container-security-scan:repo-digest", "value": "example/app@sha256:" + "b" * 64},
                      bom["metadata"]["component"]["properties"])


class Gesamtlauf(unittest.TestCase):
    """scan_container mit nachgebildetem Container: Rückgabewerte 0/1/2, Dateien, bekannte Funde."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = os.path.join(self.tmp, "db")
        schreibe_jsonl(self.db, "Debian", [eintrag("DEBIAN-CVE-2026-9", "Debian:12", "openssl",
                                                   [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u2"}],
                                                   upstream=["CVE-2026-9"], published="2026-11-01T00:00:00Z",
                                                   affected_extra={"ecosystem_specific": {"urgency": "high"}})])
        schreibe_jsonl(self.db, "npm", [])
        with open(os.path.join(self.db, "stand.json"), "w") as f:
            json.dump({k: {"stand": "x", "geprueft": "2026-11-04T00:00:00Z"} for k in ("Debian", "npm")}, f)
        self.a = argparse.Namespace(user="0", dbdirs=[self.db], ausgabe=os.path.join(self.tmp, "out"),
                                    alle=False, nur_behebbare=False)
        self.files = {"/etc/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"\n',
                      "/etc/debian_version": b"12.7\n",
                      "/var/lib/dpkg/status": b"Package: libssl3\nStatus: install ok installed\nSource: openssl\n"
                                              b"Version: 3.0.15-1~deb12u1\n",
                      "/var/lib/dpkg/info/libssl3.list": b"/usr/lib/x86_64-linux-gnu/libssl.so.3\n"}
        self.problems = []

    def lauf(self, ports=None, fremd=None, via=None, **web_kw):
        nginx = proc(1, "/usr/sbin/nginx", ports=ports or {"80": "alle"}, maps={"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
        w = web(**dict({"published": {"80": ["0.0.0.0:80"]}}, **web_kw))
        patches = [mock.patch.object(scanner, "Container", return_value=FakeContainer()),
                   mock.patch.object(scanner, "collect_files", return_value=(dict(self.files), [], "test", list(self.problems))),
                   mock.patch.object(scanner, "collect_procs", return_value=({"1": nginx}, "test", fremd or {})),
                   mock.patch.object(scanner, "probe_runtimes", return_value=[]),
                   mock.patch.object(scanner, "host_components", return_value=[]),
                   mock.patch.object(scanner, "collect_web", return_value=w),
                   mock.patch.object(scanner, "run", side_effect=fake_run),
                   mock.patch.object(scanner, "utcnow", return_value=scanner.datetime.datetime(2026, 11, 4, 12)),
                   mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO)]
        for p in patches:
            p.start()
        try:
            ergebnis = scanner.scan_container("app", self.a, via)
            self.konsole = scanner.sys.stdout.getvalue()
            return ergebnis
        finally:
            for p in reversed(patches):
                p.stop()

    def test_relevanter_fund_ergibt_1(self):
        code, backends, base = self.lauf()
        self.assertEqual((code, backends), (1, []))
        for ext in (".md", ".cdx.json", ".sha256"):
            self.assertTrue(os.path.exists(base + ext))
        with open(base + ".md", encoding="utf-8") as f:
            self.assertIn("**CVE-2026-9** (HIGH) in libssl3", f.read())
        with open(base + ".sha256") as f:
            self.assertEqual(f.read().split()[0], scanner.datei_sha256(base + ".md"))
        self.assertEqual(scanner.json_datei(os.path.join(self.a.ausgabe, "bekannt_app.json")),
                         [["libssl3", "3.0.15-1~deb12u1", "CVE-2026-9"]])

    def test_port_eines_mitnutzenden_containers(self):
        # vpn veröffentlicht 8080, darauf lauscht ein Prozess im Container "mit" (network_mode: service:vpn):
        # nicht "unbekannter Dienst", sondern dort bewertet
        with mock.patch.object(scanner, "socket_inodes", return_value={"999"}) as besitz:
            code, backends, base = self.lauf(fremd={"8080": ("alle", "999")}, netz_gruppe=["mit"],
                                             published={"80": ["0.0.0.0:80"], "8080": ["127.0.0.1:8080"]})
        besitz.assert_called_with(["mit"])
        with open(base + ".md", encoding="utf-8") as f:
            bericht = f.read()
        self.assertIn("Port 8080/tcp (alle): Prozess in einem Container mit demselben Netzwerk (mit)", bericht)
        self.assertNotIn("unbekannter Dienst", bericht)
        self.assertNotIn("nicht ermittelbar", self.konsole)
        # Besitzer in der Gruppe nicht nachweisbar (z.B. dort nicht lesbar): Rückfallregel, nicht "dort bewertet"
        with mock.patch.object(scanner, "socket_inodes", return_value=set()):
            self.lauf(fremd={"8080": ("alle", "999")}, netz_gruppe=["mit"],
                      published={"80": ["0.0.0.0:80"], "8080": ["127.0.0.1:8080"]})
        self.assertIn("WARNUNG: Prozess zu Port 8080 nicht ermittelbar", self.konsole)

    def test_socket_inodes(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        os.makedirs(os.path.join(tmp, "42", "fd"))
        os.symlink("socket:[999]", os.path.join(tmp, "42", "fd", "3"))
        os.symlink("/dev/null", os.path.join(tmp, "42", "fd", "1"))
        with mock.patch.object(scanner, "run", return_value=(0, "PID\n42\n4711\n")):
            self.assertEqual(scanner.socket_inodes(["mit"], proc=tmp), {"999"})

    def test_unbekannter_dienst_macht_nachbarn_erreichbar(self):
        # auf 8443 lauscht ein Prozess, der nicht lesbar ist: könnte ein Proxy sein
        code, backends, base = self.lauf(published={"80": ["0.0.0.0:80"], "8443": ["0.0.0.0:8443"]},
                                         nachbarn=["shop", "db"], fremd={"8443": ("alle", "7")})
        self.assertEqual(backends, [("shop", "*", "unbekannter Dienst:8443 in app"),
                                    ("db", "*", "unbekannter Dienst:8443 in app")])
        self.assertIn("WARNUNG: Prozess zu Port 8443 nicht ermittelbar", self.konsole)
        # auf 8443 lauscht nichts: alle Komponenten vorsichtshalber öffentlich, aber kein Proxy denkbar
        code, backends, base = self.lauf(published={"80": ["0.0.0.0:80"], "8443": ["0.0.0.0:8443"]},
                                         nachbarn=["shop", "db"])
        self.assertEqual(backends, [])
        self.assertIn("WARNUNG: Prozess zu Port 8443 nicht ermittelbar", self.konsole)

    def test_aufruf_ziel_ohne_lauschenden_prozess(self):
        # Ziel-URL auf einen Port, auf dem nichts lauscht (z.B. URL für eine andere Umgebung): kein "unbekannter Dienst"
        code, backends, base = self.lauf(via={"8080": ["node:3000 (Ziel-URL API_URL) in gw"]})
        self.assertNotIn("nicht ermittelbar", self.konsole)
        # lauscht dort ein nicht lesbarer Prozess, gilt die Rückfallregel
        self.lauf(via={"8080": ["node:3000 (Ziel-URL API_URL) in gw"]}, fremd={"8080": ("alle", "7")})
        self.assertIn("WARNUNG: Prozess zu Port 8080 nicht ermittelbar", self.konsole)
        # Proxy-Ziel ohne lauschenden Prozess: wie bisher vorsichtshalber alles öffentlich
        self.lauf(via={"8080": ["nginx:80 in proxy"]})
        self.assertIn("WARNUNG: Prozess zu Port 8080 nicht ermittelbar", self.konsole)

    def test_warnung_bei_unklaren_weiterleitungen(self):
        self.lauf(nachbarn=["shop"], backends={"/usr/sbin/nginx": ["http://$host"]})
        self.assertIn("app: WARNUNG: Weiterleitungen von nginx:80 nicht vollständig auswertbar (Ziel http://$host) – "
                      "Container in denselben Docker-Netzen gelten als möglicherweise öffentlich: shop", self.konsole)

    def test_relevante_funde_auf_der_konsole(self):
        # für Rundeck/Mail: nicht nur die Zusammenfassung, sondern jeder relevante Fund
        self.lauf()
        self.assertIn("app:   CVE-2026-9 (HIGH) in libssl3 3.0.15-1~deb12u1 – behoben in 3.0.15-1~deb12u2 – "
                      "genutzt von nginx:80\n", self.konsole)
        self.assertNotIn("NEU:", self.konsole)     # erster Lauf ohne Vergleich: keine Markierung
        with open(os.path.join(self.a.ausgabe, "bekannt_app.json"), "w") as f:
            json.dump([], f)                        # letzter Lauf ohne relevante Funde
        self.lauf()
        self.assertIn("app:   NEU: CVE-2026-9 (HIGH) in libssl3", self.konsole)
        self.lauf()     # danach bekannt: nicht mehr neu
        self.assertIn("app:   CVE-2026-9 (HIGH) in libssl3", self.konsole)
        self.assertNotIn("NEU:", self.konsole)

    def test_behoben_ergibt_0(self):
        self.files["/var/lib/dpkg/status"] = self.files["/var/lib/dpkg/status"].replace(b"deb12u1", b"deb12u2")
        self.assertEqual(self.lauf()[0], 0)

    def test_unvollstaendig_ergibt_2_und_ueberschreibt_bekannte_funde_nicht(self):
        self.problems = ["Dateien im Container nicht vollständig lesbar"]
        self.assertEqual(self.lauf()[0], 2)
        self.assertFalse(os.path.exists(os.path.join(self.a.ausgabe, "bekannt_app.json")))

    def test_veraltete_daten_ergeben_2(self):
        with open(os.path.join(self.db, "stand.json"), "w") as f:
            json.dump({k: {"stand": "x", "geprueft": "2026-10-01T00:00:00Z"} for k in ("Debian", "npm")}, f)
        self.assertEqual(self.lauf()[0], 2)

    def test_distribution_ohne_aktuelle_daten_ergibt_2(self):
        schreibe_jsonl(self.db, "Debian", [eintrag("DEBIAN-CVE-2020-1", "Debian:12", "openssl",
                                                   [{"introduced": "0"}, {"fixed": "1"}], published="2020-01-01T00:00:00Z")])
        self.assertEqual(self.lauf()[0], 2)

    def kev(self, cves):
        with open(os.path.join(self.db, "kev.json"), "w") as f:
            json.dump({"geprueft": "2026-11-04T00:00:00Z", "cves": cves}, f)

    def test_kev_macht_auch_p4_medium_relevant(self):
        # Fund in einem nicht genutzten Paket (P4) mit MEDIUM: normalerweise nicht relevant
        self.files["/var/lib/dpkg/status"] += b"\nPackage: libfreetype6\nStatus: install ok installed\nSource: freetype\n" \
                                              b"Version: 2.12.1+dfsg-5\n"
        schreibe_jsonl(self.db, "Debian", [
            eintrag("DEBIAN-CVE-2025-27363", "Debian:12", "freetype", [{"introduced": "0"}, {"fixed": "2.12.1+dfsg-5+deb12u4"}],
                    upstream=["CVE-2025-27363"], published="2026-11-01T00:00:00Z",
                    affected_extra={"ecosystem_specific": {"urgency": "medium"}})])
        self.assertEqual(self.lauf()[0], 0)
        self.kev({"CVE-2025-27363": "2025-05-06"})
        code, _, base = self.lauf()
        self.assertEqual(code, 1)
        with open(base + ".md", encoding="utf-8") as f:
            text = f.read()
        self.assertIn("**CVE-2025-27363** (MEDIUM KEV) in libfreetype6", text)
        self.assertIn("**aktiv ausgenutzt** (KEV seit 2025-05-06)", text)

    def test_ohne_kev_daten_nur_warnung(self):
        code, _, base = self.lauf()
        self.assertEqual(code, 1)
        with open(base + ".md", encoding="utf-8") as f:
            self.assertIn("**Warnung:** KEV-Daten fehlen", f.read())

    def test_ausnahme_unterdrueckt_fund(self):
        self.a.ausnahmen_liste = [{"id": "CVE-2026-9", "paket": "libssl3", "bis": scanner.datetime.date(2026, 12, 31),
                                   "grund": "nicht erreichbar laut Prüfung vom 2026-11-04", "zeile": 1}]
        code, _, base = self.lauf()
        self.assertEqual(code, 0)
        with open(base + ".md", encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Nicht gezählt (wären sonst relevant):\n- CVE-2026-9 (HIGH) in libssl3", text)
        self.assertIn("[nicht gezählt: Ausnahme bis 2026-12-31: nicht erreichbar", text)

    def test_kernel_pakete_im_bericht(self):
        self.files["/var/lib/dpkg/status"] += b"\nPackage: linux-libc-dev\nStatus: install ok installed\nSource: linux\n" \
                                              b"Version: 6.1.94-1\n"
        code, _, base = self.lauf()
        with open(base + ".md", encoding="utf-8") as f:
            self.assertIn("1 Kernel-Pakete nicht geprüft (Container nutzen den Kernel des Hosts)", f.read())

    def test_port_ohne_prozess_wird_als_oeffentlich_gewertet(self):
        code, _, base = self.lauf(ports={"8080": "alle"})
        with open(base + ".md", encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Prozess zu Port 80 nicht ermittelbar", text)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
