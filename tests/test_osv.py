"""OSV: Zuordnung zu Ökosystemen, Abgleich, Datenformat, inkrementelle Aktualisierung, Daten fürs Repository."""
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import zipfile
from unittest import mock

from _laden import scanner, schreibe_jsonl, eintrag

DEBIAN = {"id": "debian", "version": "12.7", "pretty": "Debian GNU/Linux 12"}


def C(*a, **kw):
    return scanner.comp(*a, **kw)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)


class Ziel(unittest.TestCase):
    def test_os_pakete(self):
        pkg = C("os-paket", "libssl3", "3.0.15-1", src="openssl", srcver="3.0.15-1")
        fname, eco_ok, names, version, cmp = scanner.osv_target(pkg, DEBIAN)
        self.assertEqual((fname, names, version, cmp), ("Debian", {"openssl"}, "3.0.15-1", scanner.cmp_dpkg))
        self.assertTrue(eco_ok("Debian:12") and not eco_ok("Debian:11"))
        t = scanner.osv_target(pkg, {"id": "alpine", "version": "3.20.3"})
        self.assertTrue(t[0] == "Alpine" and t[1]("Alpine:v3.20"))
        t = scanner.osv_target(pkg, {"id": "ubuntu", "version": "22.04"})
        self.assertTrue(t[0] == "Ubuntu" and t[1]("Ubuntu:22.04:LTS") and not t[1]("Ubuntu:24.04:LTS"))
        t = scanner.osv_target(C("os-paket", "openssl", "3.0"), {"id": "sles", "version": "15.6"})
        self.assertTrue(t[0] == "SUSE" and t[1]("SUSE:Linux Enterprise Server 15 SP6") and t[1]("SUSE:Linux Enterprise Server 15 SP6-LTSS"))
        t = scanner.osv_target(C("os-paket", "openssl", "3.0"), {"id": "opensuse-leap", "version": "15.6"})
        self.assertTrue(t[0] == "openSUSE" and t[1]("openSUSE:Leap 15.6"))
        self.assertIsNone(scanner.osv_target(pkg, {"id": "fedora", "version": "40"}))

    def test_anwendungspakete(self):
        self.assertEqual(scanner.osv_target(C("composer", "Laravel/Framework", "v10.0"), DEBIAN)[2], {"laravel/framework"})
        self.assertIsNone(scanner.osv_target(C("composer", "x/y", "dev-main"), DEBIAN))
        self.assertEqual(scanner.osv_target(C("pypi", "Django_REST.framework", "1"), DEBIAN)[2], {"django-rest-framework"})
        self.assertIsNone(scanner.osv_target(C("js-lib", "jquery", "unbekannt"), DEBIAN))
        self.assertEqual(scanner.osv_target(C("maven", "a", "1", maven_key="*:log4j-core"), DEBIAN)[2], {"*:log4j-core"})
        self.assertIsNone(scanner.osv_target(C("maven", "core", "1", maven_key="*:core"), DEBIAN))
        self.assertEqual(scanner.osv_target(C("go", "golang.org/x/net", "v0.1.0"), DEBIAN)[0], "Go")

    def test_laufzeiten_nur_ohne_os_paket(self):
        self.assertEqual(scanner.osv_target(C("runtime", "node", "20.1.0"), DEBIAN)[:1] + (
            scanner.osv_target(C("runtime", "node", "20.1.0"), DEBIAN)[2],), ("Bitnami", {"node"}))
        self.assertIsNone(scanner.osv_target(C("runtime", "node", "18", hinweise=["aus OS-Paket nodejs"]), DEBIAN))
        self.assertIsNone(scanner.osv_target(C("runtime-lib", "openssl", "3.0"), DEBIAN))


class Abgleich(Tmp):
    def debian_daten(self):
        schreibe_jsonl(self.tmp, "Debian", [
            eintrag("DEBIAN-CVE-2026-1", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u2"}],
                    upstream=["CVE-2026-1"], summary="TLS-Fehler", published="2026-10-20T00:00:00Z",
                    affected_extra={"ecosystem_specific": {"urgency": "high"}}),
            eintrag("DSA-6000-1", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u2"}],
                    upstream=["CVE-2026-1"]),                                         # Sammelmeldung mit CVE: übersprungen
            eintrag("DSA-6001-1", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u3"}]),
            eintrag("DEBIAN-CVE-2026-2", "Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u2"}],
                    withdrawn="2026-10-02T00:00:00Z"),
            eintrag("DEBIAN-CVE-2026-3", "Debian:11", "openssl", [{"introduced": "0"}, {"fixed": "9"}]),
            eintrag("DEBIAN-CVE-2026-4", "Debian:12", "curl", [{"introduced": "0"}, {"fixed": "1"}])])

    def test_debian_ueber_quellpaket(self):
        self.debian_daten()
        pkg = C("os-paket", "libssl3", "3.0.15-1~deb12u1", src="openssl", srcver="3.0.15-1~deb12u1")
        findings, date, missing, newest = scanner.osv_scan([pkg], DEBIAN, [self.tmp])
        self.assertEqual(sorted((f["id"], f["sev"], f["fix"]) for f in findings),
                         [("CVE-2026-1", "HIGH", "3.0.15-1~deb12u2"), ("DSA-6001-1", "UNKNOWN", "3.0.15-1~deb12u3")])
        self.assertEqual([f["title"] for f in findings if f["id"] == "CVE-2026-1"], ["TLS-Fehler"])
        self.assertEqual((missing, newest), ([], scanner.datetime.datetime(2026, 10, 20)))
        self.assertIsNotNone(date)

    def test_fehlende_daten_und_nicht_unterstuetztes_os(self):
        findings, _, missing, _ = scanner.osv_scan([C("npm", "a", "1.0.0")], DEBIAN, [self.tmp])
        self.assertEqual(missing, ["npm"])
        _, _, missing, _ = scanner.osv_scan([C("os-paket", "bash", "5")], {"id": "fedora", "version": "40"}, [self.tmp])
        self.assertEqual(missing, ["(OS fedora wird nicht unterstützt)"])

    def test_mehrere_ecosysteme_mehrere_verzeichnisse(self):
        zweit = os.path.join(self.tmp, "lokal")
        schreibe_jsonl(self.tmp, "npm", [eintrag("GHSA-1", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}],
                                                 aliases=["CVE-2021-23337"], database_specific={"severity": "HIGH"})])
        schreibe_jsonl(zweit, "PyPI", [eintrag("PYSEC-1", "PyPI", "django", [{"introduced": "4.0"}, {"fixed": "4.2.2"}])])
        comps = [C("npm", "lodash", "4.17.20"), C("js-lib", "lodash", "4.17.15"), C("pypi", "Django", "4.2.1"),
                 C("npm", "lodash", "4.17.21")]
        findings, _, missing, _ = scanner.osv_scan(comps, DEBIAN, [self.tmp, zweit])
        self.assertEqual(missing, [])
        self.assertEqual(sorted((f["comp"]["typ"], f["comp"]["version"], f["id"]) for f in findings),
                         [("js-lib", "4.17.15", "CVE-2021-23337"), ("npm", "4.17.20", "CVE-2021-23337"),
                          ("pypi", "4.2.1", "PYSEC-1")])

    def test_maven_ohne_gruppe_und_php_fpm_nicht_doppelt(self):
        schreibe_jsonl(self.tmp, "Maven", [eintrag("GHSA-m", "Maven", "org.apache.logging.log4j:log4j-core",
                                                   [{"introduced": "2.0"}, {"fixed": "2.17.1"}])])
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-php", "Bitnami", "php", [{"introduced": "8.0.0"}, {"fixed": "8.3.5"}],
                                                     typ="SEMVER")])
        comps = [C("maven", "log4j-core", "2.14.1", maven_key="*:log4j-core"), C("runtime", "php", "8.3.1"),
                 C("runtime", "php-fpm", "8.3.1")]
        findings, _, _, _ = scanner.osv_scan(comps, DEBIAN, [self.tmp])
        self.assertEqual(sorted((f["comp"]["name"], f["id"]) for f in findings), [("log4j-core", "GHSA-m"), ("php", "BIT-php")])

    def test_fremdquelle_ueber_bitnami(self):
        self.debian_daten()
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-nginx", "Bitnami", "nginx", [{"introduced": "1.0.0"}, {"fixed": "1.27.4"}],
                                                     typ="SEMVER")])
        nginx_pkg = C("os-paket", "nginx", "1.27.3-1~bookworm", maint="NGINX Packaging <nginx-packaging@f5.com>")
        nginx = C("server", "nginx", "1.27.3", "/usr/sbin/nginx", hinweise=["aus OS-Paket nginx"])
        findings, _, _, _ = scanner.osv_scan([nginx_pkg, nginx], DEBIAN, [self.tmp])
        self.assertEqual([(f["comp"]["typ"], f["id"]) for f in findings], [("server", "BIT-nginx")])
        self.assertTrue(any(h.startswith(scanner.FREMDQUELLE) for h in nginx["hinweise"]))

    def test_paket_der_distribution_nicht_ueber_bitnami(self):
        self.debian_daten()
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-x", "Bitnami", "php", [{"introduced": "0"}, {"fixed": "99"}], typ="SEMVER")])
        # curl hat Einträge im Debian-Export -> Paket der Distribution
        php = C("runtime", "php", "8.2.20", "/usr/bin/php8.2", hinweise=["aus OS-Paket curl"])
        findings, _, _, _ = scanner.osv_scan([C("os-paket", "curl", "7.88"), php], DEBIAN, [self.tmp])
        self.assertEqual([f["id"] for f in findings if f["comp"] is php], [])

    def test_ubuntu_aus_lokalen_daten(self):
        pkg = C("os-paket", "libexample1", "1.0-1", src="example", srcver="1.0-1")
        osinfo = {"id": "ubuntu", "version": "22.04", "pretty": "Ubuntu 22.04"}
        self.assertEqual(scanner.osv_scan([pkg], osinfo, [self.tmp])[2], ["Ubuntu"])
        schreibe_jsonl(self.tmp, "Ubuntu", [
            eintrag("CVE-2026-1000", "Ubuntu:22.04:LTS", "example", [{"introduced": "0"}, {"fixed": "1.0-2"}]),
            eintrag("CVE-2026-1001", "Ubuntu:24.04:LTS", "example", [{"introduced": "0"}])])
        findings, _, missing, _ = scanner.osv_scan([pkg], osinfo, [self.tmp])
        self.assertEqual((missing, [(x["id"], x["fix"]) for x in findings]), ([], [("CVE-2026-1000", "1.0-2")]))


class Datenformat(Tmp):
    def test_osv_compact(self):
        rec = {"id": "GHSA-x", "aliases": ["CVE-1"], "summary": "", "details": "Erste Zeile\nZweite", "modified": "x",
               "references": [{"url": "u"}], "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
               "affected": [{"package": {"ecosystem": "npm", "name": "a", "purl": "pkg:npm/a"},
                             "ranges": [{"type": "GIT", "events": []}, {"type": "SEMVER", "events": [{"introduced": "0"}]}],
                             "versions": ["1.0"], "ecosystem_specific": {"urgency": "low", "other": 1},
                             "database_specific": {"source": "x"}}]}
        self.assertEqual(scanner.osv_compact(rec), {
            "id": "GHSA-x", "aliases": ["CVE-1"], "summary": "Erste Zeile", "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "a"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                          "ecosystem_specific": {"urgency": "low"}}]})
        nur_versionen = scanner.osv_compact({"id": "X", "affected": [{"package": {}, "versions": ["1"]}]})
        self.assertEqual(nur_versionen["affected"][0]["versions"], ["1"])
        self.assertEqual(len(scanner.osv_compact({"id": "X", "summary": "a" * 500, "affected": []})["summary"]), 200)

    def test_osv_records_zip_mit_ueberlagerung(self):
        with zipfile.ZipFile(os.path.join(self.tmp, "npm.zip"), "w") as z:
            z.writestr("A.json", '{"id": "A", "v": 1}')
            z.writestr("B.json", '{"id": "B", "v": 1}')
        os.makedirs(os.path.join(self.tmp, "npm.neu"))
        for name, data in (("B.json", '{"id": "B", "v": 2}'), ("C.json", '{"id": "C", "v": 1}')):
            with open(os.path.join(self.tmp, "npm.neu", name), "w") as f:
                f.write(data)
        recs = sorted((r["id"], r["v"]) for r in map(json.loads, scanner.osv_records(self.tmp, "npm")))
        self.assertEqual(recs, [("A", 1), ("B", 2), ("C", 1)])

    def test_db_state(self):
        with open(os.path.join(self.tmp, "stand.json"), "w") as f:
            json.dump({"_format": "osv-kompakt-1", "Go": {"stand": "a", "geprueft": "b"}}, f)
        self.assertEqual(scanner.db_state(self.tmp), {"Go": {"stand": "a", "geprueft": "b"}})
        self.assertEqual(scanner.db_state(os.path.join(self.tmp, "fehlt")), {})


class Aktualisierung(Tmp):
    @staticmethod
    def inhalt(d):
        result = {}
        for n in sorted(os.listdir(d)):
            with open(os.path.join(d, n), "rb") as f:
                result[n] = f.read()
        return result

    def antworten(self, urls):
        def urlopen(url, timeout=None):
            antwort = urls[url]
            if isinstance(antwort, Exception):
                raise antwort
            return io.BytesIO(antwort)
        return urlopen

    def test_inkrementell_mit_entferntem_eintrag(self):
        with zipfile.ZipFile(os.path.join(self.tmp, "npm.zip"), "w") as z:
            z.writestr("GHSA-1.json", '{"id": "GHSA-1", "v": 1}')
        with open(os.path.join(self.tmp, "stand.json"), "w") as f:
            json.dump({"npm": {"stand": "2026-11-03T12:00:00Z", "geprueft": "2026-11-03T12:05:00Z"}}, f)
        base = scanner.OSV_BASE + "npm/"
        urls = {base + "modified_id.csv": b"2026-11-04T10:00:00Z,GHSA-1\n2026-11-04T09:00:00Z,GHSA-2\n"
                                          b"2026-11-03T00:00:00Z,GHSA-alt\n",
                base + "GHSA-1.json": b'{"id": "GHSA-1", "v": 2}',
                base + "GHSA-2.json": urllib.error.HTTPError(base + "GHSA-2.json", 404, "nf", {}, None)}
        with mock.patch.object(scanner.urllib.request, "urlopen", side_effect=self.antworten(urls)), \
                mock.patch.object(scanner, "log"):
            scanner.osv_update(self.tmp, ["npm"])
        recs = {r["id"]: r for r in map(json.loads, scanner.osv_records(self.tmp, "npm"))}
        self.assertEqual(recs["GHSA-1"]["v"], 2)
        self.assertEqual(recs["GHSA-2"]["withdrawn"], "entfernt")
        self.assertEqual(scanner.db_state(self.tmp)["npm"]["stand"], "2026-11-04T10:00:00Z")

    def test_ungueltige_kennung_wird_kein_pfad(self):
        ziel = os.path.join(self.tmp, "db")
        os.makedirs(os.path.join(ziel, "npm.neu"))
        with zipfile.ZipFile(os.path.join(ziel, "npm.zip"), "w") as z:
            z.writestr("GHSA-1.json", '{"id": "GHSA-1"}')
        with open(os.path.join(ziel, "stand.json"), "w") as f:
            json.dump({"npm": {"stand": "2026-11-03T12:00:00Z", "geprueft": "2026-11-03T12:05:00Z"}}, f)
        base = scanner.OSV_BASE + "npm/"
        for vid in ("../../boese", "/etc/x", "..", "", "a/b"):
            urls = {base + "modified_id.csv": ("2026-11-04T10:00:00Z,%s\n" % vid).encode()}
            with mock.patch.object(scanner.urllib.request, "urlopen", side_effect=self.antworten(urls)), \
                    mock.patch.object(scanner, "log"):
                with self.assertRaisesRegex(scanner.ScanError, "Ungültige Kennung"):
                    scanner.osv_update(ziel, ["npm"])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["db"])
        self.assertEqual(os.listdir(os.path.join(ziel, "npm.neu")), [])
        for vid in ("GHSA-abcd-1234-wxyz", "DEBIAN-CVE-2024-1", "SUSE-SU-2024:1234-1", "BIT-php-2024-1", "PYSEC-2021-1"):
            self.assertTrue(scanner.OSV_ID.fullmatch(vid), vid)

    def test_erster_lauf_laedt_gesamtexport(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("GHSA-9.json", '{"id": "GHSA-9"}')
        urls = {scanner.OSV_BASE + "Go/modified_id.csv": b"2026-11-04T10:00:00Z,GO-1\n",
                scanner.OSV_URL % "Go": buf.getvalue()}
        with mock.patch.object(scanner.urllib.request, "urlopen", side_effect=self.antworten(urls)), \
                mock.patch.object(scanner, "log"):
            scanner.osv_update(self.tmp, ["Go"])
        self.assertTrue(zipfile.is_zipfile(os.path.join(self.tmp, "Go.zip")))
        self.assertEqual(scanner.db_state(self.tmp)["Go"]["stand"], "2026-11-04T10:00:00Z")

    def test_daten_erzeugen_deterministisch(self):
        def osv_update(tmp, ecos, full=False):
            with zipfile.ZipFile(os.path.join(tmp, "npm.zip"), "w") as z:
                for vid in ("GHSA-b", "GHSA-a", "MAL-1"):
                    z.writestr(vid + ".json", json.dumps({"id": vid, "details": "x" * 300, "references": [1],
                                                          "affected": [{"package": {"ecosystem": "npm", "name": vid}}]}))
            with open(os.path.join(tmp, "stand.json"), "w") as f:
                json.dump({"npm": {"stand": "s", "geprueft": "g"}}, f)
        ziel = os.path.join(self.tmp, "daten")
        os.makedirs(os.path.join(ziel, "npm"))
        open(os.path.join(ziel, "npm", "99.jsonl"), "w").close()
        with mock.patch.object(scanner, "osv_update", side_effect=osv_update), mock.patch.object(scanner, "log"):
            scanner.daten_erzeugen(ziel, ["npm"])
            erster = self.inhalt(os.path.join(ziel, "npm"))
            scanner.daten_erzeugen(ziel, ["npm"])
            zweiter = self.inhalt(os.path.join(ziel, "npm"))
        self.assertEqual(erster, zweiter)
        self.assertEqual(sorted(erster), ["%02d.jsonl" % i for i in range(scanner.DATEN_TEILE["npm"])])
        zeilen = [json.loads(l) for data in erster.values() for l in data.splitlines()]
        self.assertEqual(sorted(r["id"] for r in zeilen), ["GHSA-a", "GHSA-b", "MAL-1"])
        self.assertTrue(all("references" not in r and len(r["summary"]) == 200 for r in zeilen))
        stand = scanner.json_datei(os.path.join(ziel, "stand.json"))
        self.assertEqual(stand, {"_format": "osv-kompakt-1", "npm": {"stand": "s", "geprueft": "g"}})
        # geladene Daten liefern dieselben Einträge
        self.assertEqual(len(list(scanner.osv_records(ziel, "npm"))), 3)


if __name__ == "__main__":
    unittest.main()
