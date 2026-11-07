"""Bewertung der Funde: widersprüchliche Bereiche, Kernel-Pakete, Schweregrad über die CVE, KEV, Ausnahmeliste,
Lücken nur unter Windows, gefährliche Einstellungen des Containers, öffentliche Dienste als root."""
import datetime
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from _laden import scanner, schreibe_jsonl, eintrag, proc

ALPINE = {"id": "alpine", "version": "3.21.3", "pretty": "Alpine Linux v3.21"}
DEBIAN = {"id": "debian", "version": "12.7", "pretty": "Debian GNU/Linux 12"}


def C(*a, **kw):
    return scanner.comp(*a, **kw)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.clock = mock.patch.object(scanner, "utcnow", return_value=datetime.datetime(2026, 11, 5, 12))
        self.clock.start()
        self.addCleanup(self.clock.stop)


class WiderspruechlicheBereiche(Tmp):
    """Alpine-Daten (über OSV): "introduced" stammt teils aus einem anderen Versionszweig als der Fix."""

    def test_fix_vor_introduced_heisst_betroffen(self):
        aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.4.0"}, {"fixed": "3.3.7-r1"}]}]}
        self.assertEqual(scanner.affected_by("3.3.3-r0", aff, scanner.cmp_apk, True), (True, "3.3.7-r1"))
        self.assertEqual(scanner.affected_by("3.3.7-r1", aff, scanner.cmp_apk, True), (False, ""))
        # ohne Distributionsdaten gilt die Angabe wörtlich (OSV-Spezifikation)
        self.assertFalse(scanner.affected_by("3.3.3-r0", aff, scanner.cmp_apk)[0])

    def test_gueltiges_introduced_bleibt_wirksam(self):
        # curl: Lücke laut Hersteller ab 8.13.0 -> 8.12.1 nicht betroffen (Grype/Trivy melden das fälschlich)
        aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "8.13.0"}, {"fixed": "8.14.1-r2"}]}]}
        self.assertFalse(scanner.affected_by("8.12.1-r1", aff, scanner.cmp_apk, True)[0])
        self.assertTrue(scanner.affected_by("8.14.0-r0", aff, scanner.cmp_apk, True)[0])

    def test_abgleich_mit_alpine_daten(self):
        schreibe_jsonl(self.tmp, "Alpine", [
            eintrag("ALPINE-CVE-2026-1", "Alpine:v3.21", "openssl", [{"introduced": "3.4.0"}, {"fixed": "3.3.7-r1"}],
                    upstream=["CVE-2026-1"], severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]),
            eintrag("ALPINE-CVE-2026-2", "Alpine:v3.21", "curl", [{"introduced": "8.13.0"}, {"fixed": "8.14.1-r2"}],
                    upstream=["CVE-2026-2"])])
        comps = [C("os-paket", "libssl3", "3.3.3-r0", src="openssl"), C("os-paket", "curl", "8.12.1-r1", src="curl")]
        findings = scanner.osv_scan(comps, ALPINE, [self.tmp])[0]
        self.assertEqual([(f["id"], f["comp"]["name"], f["fix"]) for f in findings], [("CVE-2026-1", "libssl3", "3.3.7-r1")])

    def test_pypi_bleibt_wortlich(self):
        # GHSA mit "introduced 1.1.5.post1, fixed 1.1.5" (kompromittierte Version): ältere Versionen nicht betroffen
        schreibe_jsonl(self.tmp, "PyPI", [eintrag("GHSA-x", "PyPI", "dydx-v4-client",
                                                  [{"introduced": "1.1.5.post1"}, {"fixed": "1.1.5"}])])
        self.assertEqual(scanner.osv_scan([C("pypi", "dydx-v4-client", "1.1.4")], DEBIAN, [self.tmp])[0], [])


class KernelPakete(unittest.TestCase):
    def test_kernel_pakete_werden_nicht_geprueft(self):
        for c in (C("os-paket", "linux-libc-dev", "6.1.94-1", src="linux"),
                  C("os-paket", "linux-headers", "6.6-r0", src="linux-headers"),
                  C("os-paket", "linux-image-6.1.0-26-amd64", "6.1.112-1", src="linux-signed-amd64"),
                  C("os-paket", "kernel-default", "6.4.0-150600.23.25.1")):
            self.assertTrue(scanner.kernel_paket(c), c["name"])
            self.assertIsNone(scanner.osv_target(c, DEBIAN))

    def test_aehnliche_namen_sind_keine_kernel_pakete(self):
        for c in (C("os-paket", "libpam-modules", "1.5", src="pam"), C("os-paket", "util-linux", "2.38", src="util-linux"),
                  C("os-paket", "linux-pam", "1.6-r0", src="linux-pam"), C("npm", "linux-headers", "1.0")):
            self.assertFalse(scanner.kernel_paket(c), c["name"])


class SchweregradUeberCve(Tmp):
    def test_go_ohne_schweregrad_uebernimmt_bewertung(self):
        schreibe_jsonl(self.tmp, "Go", [eintrag("GO-2026-1", "Go", "stdlib", [{"introduced": "0"}, {"fixed": "1.22.7"}],
                                                typ="SEMVER", aliases=["CVE-2026-10", "GHSA-a"]),
                                        eintrag("GO-2026-2", "Go", "stdlib", [{"introduced": "0"}, {"fixed": "1.22.7"}],
                                                typ="SEMVER", aliases=["CVE-2026-11"])])
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-golang-2026-10", "Bitnami", "golang", [{"introduced": "0"}, {"fixed": "1"}],
                                                     typ="SEMVER", aliases=["CVE-2026-10"],
                                                     database_specific={"severity": "Medium"})])
        schreibe_jsonl(self.tmp, "Alpine", [eintrag("ALPINE-CVE-2026-10", "Alpine:v3.21", "go", [{"introduced": "0"}, {"fixed": "1"}],
                                                    upstream=["CVE-2026-10"],
                                                    severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}])])
        findings = {f["id"]: f for f in scanner.osv_scan([C("go", "stdlib", "1.21.0")], DEBIAN, [self.tmp])[0]}
        # höchste Angabe (Alpine/NVD: HIGH vor Bitnami: MEDIUM), Quelle vermerkt
        self.assertEqual((findings["CVE-2026-10"]["sev"], findings["CVE-2026-10"]["sev_quelle"]), ("HIGH", "ALPINE-CVE-2026-10"))
        self.assertEqual(findings["CVE-2026-11"]["sev"], "UNKNOWN")
        self.assertNotIn("sev_quelle", findings["CVE-2026-11"])

    def test_eigene_bewertung_bleibt(self):
        schreibe_jsonl(self.tmp, "npm", [eintrag("GHSA-b", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}],
                                                 typ="SEMVER", aliases=["CVE-2026-20"], database_specific={"severity": "LOW"})])
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-lodash-2026-20", "Bitnami", "lodash", [{"introduced": "0"}, {"fixed": "1"}],
                                                     typ="SEMVER", aliases=["CVE-2026-20"], database_specific={"severity": "Critical"})])
        f = scanner.osv_scan([C("npm", "lodash", "4.17.15")], DEBIAN, [self.tmp])[0][0]
        self.assertEqual((f["sev"], f.get("sev_quelle")), ("LOW", None))


class NurWindows(Tmp):
    def test_titel(self):
        for t in ("On Windows a directory returned by tempfile.mkdtemp() would not always have permissions set",
                  "Out-of-bounds write in Windows asyncio.ProacterEventLoop.sock_recvfrom_into()",
                  "In Python before 3.10.3 on Windows, local users can gain privileges",
                  "WordPress core < 6.5.5 - Auth. Arbitrary .html File Read (Windows Only) vulnerability",
                  "pnpm has Windows-specific tarball Path Traversal",
                  "Apache Tomcat installer for Windows has an untrusted search path vulnerability",
                  "Code injection in Stripe CLI on windows"):
            self.assertTrue(scanner.nur_windows(t), t)
        for t in ("Apache HTTP Server: DoS in HTTP/2 with initial windows size 0",
                  "Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows in os in syscall",
                  "Certificate validation issue in MongoDB Server running on Windows or macOS",
                  "Electron: Windows opened from a sandboxed top-level document do not inherit its sandbox restrictions",
                  "n8n: computer-use Shell Sandbox Not Enforced on Linux and Windows",
                  "PHP CGI Parameter Injection Vulnerability (CVE-2024-4577 bypass)", ""):
            self.assertFalse(scanner.nur_windows(t), t)

    def test_nur_ausserhalb_der_distributionsdaten(self):
        titel = "Privilege escalation on Windows"
        schreibe_jsonl(self.tmp, "Bitnami", [eintrag("BIT-python-2026-1", "Bitnami", "python", [{"introduced": "0"}, {"fixed": "3.11.9"}],
                                                     typ="SEMVER", aliases=["CVE-2026-30"], summary=titel)])
        schreibe_jsonl(self.tmp, "Debian", [eintrag("DEBIAN-CVE-2026-31", "Debian:12", "python3.11",
                                                    [{"introduced": "0"}, {"fixed": "3.11.9-1"}], upstream=["CVE-2026-31"],
                                                    summary=titel, published="2026-11-01T00:00:00Z")])
        comps = [C("runtime", "python", "3.11.4"), C("os-paket", "libpython3.11", "3.11.2-6", src="python3.11")]
        findings = {f["id"]: f for f in scanner.osv_scan(comps, DEBIAN, [self.tmp])[0]}
        self.assertEqual(findings["CVE-2026-30"]["ausgenommen"], "betrifft laut Titel nur Windows")
        self.assertNotIn("ausgenommen", findings["CVE-2026-31"])


class Kev(Tmp):
    def schreibe(self, geprueft="2026-11-05T00:00:00Z", cves=None):
        path = os.path.join(self.tmp, "kev.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"geprueft": geprueft, "katalog": "2026.11.05", "cves": cves or {"CVE-2023-4911": "2023-11-21"}}, f)
        return path

    def test_markieren(self):
        findings = [{"id": "CVE-2023-4911"}, {"id": "CVE-2026-1"}, {"id": "GHSA-x"}]
        self.assertEqual(scanner.kev_markieren(findings, [self.schreibe()]), [])
        self.assertEqual([f.get("kev") for f in findings], ["2023-11-21", None, None])

    def test_fehlend_ungueltig_veraltet_sind_warnungen(self):
        self.assertIn("KEV-Daten fehlen", scanner.kev_markieren([], [os.path.join(self.tmp, "fehlt.json")])[0])
        self.assertIn("ungültig", scanner.kev_markieren([], [self.schreibe(cves={"kein-cve": "x"})])[0])
        self.assertIn("veraltet", scanner.kev_markieren([], [self.schreibe(geprueft="2026-10-01T00:00:00Z")])[0])

    def test_juengste_datei_gilt(self):
        alt = self.schreibe(geprueft="2026-11-01T00:00:00Z", cves={"CVE-2020-0001": "2020-01-01"})
        os.rename(alt, alt + ".alt")
        neu = self.schreibe(cves={"CVE-2026-1234": "2026-11-04"})
        self.assertEqual(scanner.kev_laden([alt + ".alt", neu])[1], {"CVE-2026-1234": "2026-11-04"})

    def test_erzeugen(self):
        antwort = {"catalogVersion": "2026.11.05", "count": 2, "vulnerabilities": [
            {"cveID": "CVE-2023-4911", "dateAdded": "2023-11-21", "vendorProject": "GNU"},
            {"cveID": "CVE-2025-27363", "dateAdded": "2025-05-06"}]}
        path = os.path.join(self.tmp, "kev.json")
        with mock.patch.object(scanner.urllib.request, "urlopen",
                               return_value=io.BytesIO(json.dumps(antwort).encode())):
            scanner.kev_daten_erzeugen(path)
        data = scanner.json_datei(path)
        self.assertEqual(data["cves"], {"CVE-2023-4911": "2023-11-21", "CVE-2025-27363": "2025-05-06"})
        self.assertEqual((data["geprueft"], data["katalog"]), ("2026-11-05T12:00:00Z", "2026.11.05"))

    def test_erzeugen_lehnt_unvollstaendige_daten_ab(self):
        for antwort in ({"count": 2, "vulnerabilities": [{"cveID": "CVE-2023-4911", "dateAdded": "2023-11-21"}]},
                        {"count": 1, "vulnerabilities": [{"cveID": "../etc", "dateAdded": "2023-11-21"}]}):
            with mock.patch.object(scanner.urllib.request, "urlopen",
                                   return_value=io.BytesIO(json.dumps(antwort).encode())):
                with self.assertRaises(scanner.ScanError):
                    scanner.kev_daten_erzeugen(os.path.join(self.tmp, "kev.json"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "kev.json")))


class Ausnahmen(Tmp):
    def liste(self, text, mode=0o644):
        path = os.path.join(self.tmp, "ausnahmen.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, mode)
        return path

    def test_laden(self):
        a = scanner.ausnahmen_laden(self.liste(
            "# Kennung      Paket  gültig bis  Begründung\n\n"
            "CVE-2024-8926  php    2027-06-30  betrifft nur PHP-CGI unter Windows\n"
            "CVE-2026-107814 *     2026-12-31  nur RPM-Pakete von MariaDB\n"))
        self.assertEqual([(x["id"], x["paket"], x["bis"], x["grund"], x["zeile"]) for x in a], [
            ("CVE-2024-8926", "php", datetime.date(2027, 6, 30), "betrifft nur PHP-CGI unter Windows", 3),
            ("CVE-2026-107814", "*", datetime.date(2026, 12, 31), "nur RPM-Pakete von MariaDB", 4)])

    def test_fehler_brechen_ab(self):
        for text in ("CVE-2024-8926 php 2027-06-30\n",                 # Begründung fehlt
                     "CVE-2024-8926 php 30.06.2027 Grund\n",           # Datumsformat
                     "CVE-2024-8926 php 2027-02-30 Grund\n",           # ungültiges Datum
                     "../x php 2027-06-30 Grund\n"):
            with self.assertRaises(scanner.ScanError) as e:
                scanner.ausnahmen_laden(self.liste(text))
            self.assertIn("Zeile 1", str(e.exception))
        with self.assertRaises(scanner.ScanError):
            scanner.ausnahmen_laden(os.path.join(self.tmp, "fehlt.txt"))

    def test_fuer_andere_beschreibbar_wird_abgelehnt(self):
        with self.assertRaises(scanner.ScanError) as e:
            scanner.ausnahmen_laden(self.liste("CVE-1 * 2027-01-01 Grund\n", mode=0o666))
        self.assertIn("ändern können", str(e.exception))

    def test_anwenden_und_ablauf(self):
        rows = [{"id": "CVE-1", "pkg": "php"}, {"id": "CVE-1", "pkg": "node"}, {"id": "CVE-2", "pkg": "x"},
                {"id": "CVE-3", "pkg": "y"}]
        ausnahmen = [{"id": "CVE-1", "paket": "php", "bis": datetime.date(2026, 12, 31), "grund": "nur Windows", "zeile": 1},
                     {"id": "CVE-2", "paket": "*", "bis": datetime.date(2026, 11, 5), "grund": "heute noch", "zeile": 2},
                     {"id": "CVE-3", "paket": "*", "bis": datetime.date(2026, 11, 4), "grund": "abgelaufen", "zeile": 3}]
        warnings = []
        scanner.ausnahmen_anwenden(rows, ausnahmen, warnings)
        self.assertEqual([r.get("ausgenommen") for r in rows],
                         ["Ausnahme bis 2026-12-31: nur Windows", None, "Ausnahme bis 2026-11-05: heute noch", None])
        self.assertEqual(len(warnings), 1)
        self.assertIn("Ausnahme für CVE-3 (*) abgelaufen am 2026-11-04", warnings[0])


class Relevanz(unittest.TestCase):
    def row(self, **kw):
        r = {"prio": 4, "sev": "MEDIUM", "fix": "1.1"}
        r.update(kw)
        return r

    def test_kev_unabhaengig_von_prioritaet_und_schweregrad(self):
        self.assertFalse(scanner.ist_relevant(self.row(), False))
        self.assertTrue(scanner.ist_relevant(self.row(kev="2025-05-06"), False))
        self.assertFalse(scanner.ist_relevant(self.row(kev="2025-05-06", fix=""), True))     # --nur-behebbare gilt

    def test_ausgenommen_ist_nie_relevant(self):
        self.assertTrue(scanner.ist_relevant(self.row(prio=1, sev="HIGH"), False))
        self.assertFalse(scanner.ist_relevant(self.row(prio=1, sev="HIGH", ausgenommen="x"), False))
        self.assertFalse(scanner.ist_relevant(self.row(kev="2025-05-06", ausgenommen="x"), False))

    def test_schwere_text(self):
        self.assertEqual(scanner.schwere_text(self.row(sev="HIGH", sev_quelle="BIT-1", kev="2025")), "HIGH* KEV")
        self.assertEqual(scanner.schwere_text(self.row()), "MEDIUM")


class Konfiguration(unittest.TestCase):
    """Gefährliche Einstellungen aus docker inspect (CONF-…)."""

    def pruefen(self, host=None, mounts=()):
        c = mock.Mock(info={"HostConfig": host or {}, "Mounts": list(mounts)})
        c.name = "app"
        return [(k["id"], k["pkg"]) for k in scanner.konfiguration_pruefen(c)]

    def test_unauffaellig(self):
        self.assertEqual(self.pruefen(), [])
        self.assertEqual(self.pruefen({"Privileged": False, "PidMode": "", "CapAdd": ["NET_BIND_SERVICE", "CHOWN"],
                                       "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true",
                                                                           "seccomp=/etc/docker/profil.json"]},
                                      [{"Type": "volume", "Source": "/var/lib/docker/volumes/daten/_data", "RW": True},
                                       {"Type": "bind", "Source": "/srv/app", "RW": True},
                                       {"Type": "bind", "Source": "/etc/letsencrypt", "RW": True},
                                       {"Type": "bind", "Source": "/etc/localtime", "RW": False},
                                       {"Type": "bind", "Source": "/var/lib/docker/containers", "RW": False},
                                       {"Type": "bind", "Source": "/run/udev", "RW": False},
                                       {"Type": "bind", "Source": "/usr/share/zoneinfo", "RW": True}]), [])

    def test_privileged_umfasst_capabilities_und_profile(self):
        self.assertEqual(self.pruefen({"Privileged": True, "CapAdd": ["SYS_ADMIN"],
                                       "SecurityOpt": ["seccomp=unconfined"]}), [("CONF-PRIVILEGED", "app")])

    def test_capabilities_profile_pid(self):
        self.assertEqual(self.pruefen({"CapAdd": ["CAP_SYS_ADMIN", "sys_module", "NET_ADMIN", "ALL", "SYS_ADMIN"],
                                       "SecurityOpt": ["seccomp:unconfined", "apparmor=unconfined", "label=disable"],
                                       "PidMode": "host"}),
                         [("CONF-CAP-SYS-ADMIN", "app"), ("CONF-CAP-SYS-MODULE", "app"), ("CONF-CAP-ALL", "app"),
                          ("CONF-SECCOMP-UNCONFINED", "app"), ("CONF-APPARMOR-UNCONFINED", "app"),
                          ("CONF-PID-HOST", "app")])

    def test_socket_auch_schreibgeschuetzt(self):
        for src in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                    "/run/user/1000/podman/podman.sock", "/var/run", "/run/"):
            self.assertEqual(self.pruefen(mounts=[{"Type": "bind", "Source": src, "Destination": "/x", "RW": False}]),
                             [("CONF-SOCKET", "app")], src)

    def test_host_pfade_nur_beschreibbar(self):
        for src in ("/", "/etc", "/etc/shadow", "/etc/cron.d", "/root/.ssh", "/boot", "/usr", "/usr/local/bin",
                    "/lib64", "/sys/fs/cgroup", "/proc/sys", "/dev", "/home", "/var/lib/docker",
                    "/var/lib/docker/containers"):
            m = {"Type": "bind", "Source": src, "Destination": "/host", "RW": True}
            self.assertEqual(self.pruefen(mounts=[m]), [("CONF-HOST-PFAD", "app")], src)
            self.assertEqual(self.pruefen(mounts=[dict(m, RW=False)]), [], src)

    def test_ausnahme_nach_containername(self):
        konf = [{"id": "CONF-SOCKET", "pkg": "traefik"}, {"id": "CONF-SOCKET", "pkg": "app"}]
        scanner.ausnahmen_anwenden(konf, [{"id": "CONF-SOCKET", "paket": "traefik", "bis": datetime.date(2099, 1, 1),
                                           "grund": "nur über Socket-Proxy", "zeile": 1}], [])
        self.assertEqual([bool(k.get("ausgenommen")) for k in konf], [True, False])


class RootDienste(unittest.TestCase):
    """Warnung für öffentliche Dienste, die vollständig als root laufen."""

    def warnungen(self, procs, exposed=True, info=None, docker_info=(0, '["name=apparmor","name=seccomp"]')):
        c = mock.Mock(info=info or {"HostConfig": {}})
        services = [{"label": p["label"], "exposed": exposed} for p in procs if p["ports"]]
        with mock.patch.object(scanner, "run", return_value=docker_info):
            return scanner.root_dienste(c, services, {p["pid"]: p for p in procs})

    def test_node_als_root(self):
        w = self.warnungen([proc(1, "/usr/local/bin/node", ports={"3000": "alle"}, user="0:0")])
        self.assertEqual(len(w), 1)
        self.assertIn("Öffentlicher Dienst node:3000 läuft als root", w[0])

    def test_unkritisch(self):
        # nginx: Master root, Worker unprivilegiert am selben Port
        self.assertEqual(self.warnungen([proc(1, "/usr/sbin/nginx", ports={"80": "alle"}, user="0:0"),
                                         proc(7, "/usr/sbin/nginx", ports={"80": "alle"}, user="101:101")]), [])
        self.assertEqual(self.warnungen([proc(1, "/usr/local/bin/node", ports={"3000": "alle"}, user="1000:1000")]), [])
        self.assertEqual(self.warnungen([proc(1, "/usr/local/bin/node", ports={"3000": "alle"}, user="")]), [])
        self.assertEqual(self.warnungen([proc(1, "/usr/local/bin/node", ports={"3000": "alle"})], exposed=False), [])

    def test_userns_remap_und_rootless(self):
        node = [proc(1, "/usr/local/bin/node", ports={"3000": "alle"}, user="0:0")]
        for opts in ('["name=seccomp","name=userns"]', '["name=seccomp","name=rootless"]'):
            self.assertEqual(self.warnungen(node, docker_info=(0, opts)), [])
        # userns=host schaltet userns-remap für den Container ab
        self.assertEqual(len(self.warnungen(node, info={"HostConfig": {"UsernsMode": "host"}},
                                            docker_info=(0, '["name=userns"]'))), 1)
        # docker info nicht auswertbar: lieber warnen
        self.assertEqual(len(self.warnungen(node, docker_info=(1, ""))), 1)


if __name__ == "__main__":
    unittest.main()
