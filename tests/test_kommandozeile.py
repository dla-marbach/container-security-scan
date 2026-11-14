"""Aufruf als Programm: Optionen und Rückgabewerte, mit einem nachgebildeten docker-Befehl."""
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from unittest import mock

from _laden import SKRIPT, scanner


class Kommandozeile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.db = os.path.join(self.tmp, "leere-db")   # Daten liegen nicht im Code-Branch
        os.mkdir(self.db)

    def docker(self, script):
        """docker-Ersatz im PATH: POSIX-sh-Skript, das die Argumente auswertet."""
        path = os.path.join(self.bin, "docker")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + script)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)

    def aufruf(self, *args, **env):
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""))
        e.update(env)
        p = subprocess.run([sys.executable, SKRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=e, cwd=self.tmp, timeout=120)
        return p.returncode, p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")

    def test_meldungen_sofort_auf_stderr(self):
        # Python < 3.9 puffert stderr in einer Pipe (Wrapper: 2>&1 | tee) bis zum Ende: Fortschrittsmeldungen
        # stünden sonst gesammelt hinter den Ergebnissen
        err = mock.Mock()
        with mock.patch.object(scanner.sys, "stderr", err):
            scanner.log("Erfasse Container 'app' ...")
        self.assertEqual(err.method_calls, [mock.call.write("Erfasse Container 'app' ...\n"), mock.call.flush()])

    def test_hilfe(self):
        rc, out = self.aufruf("--help")
        self.assertEqual(rc, 0)
        self.assertIn("--oeffentliche", out)
        self.assertIn("--alle-container", out)
        self.assertIn("--host", out)
        self.assertIn("--ausnahmen", out)
        self.assertNotIn("--eol-daten-erzeugen", out)      # nur für die GitHub Action
        self.assertNotIn("--kev-daten-erzeugen", out)
        self.assertNotIn("--suse-schweregrad-erzeugen", out)

    def test_fehlerhafte_ausnahmeliste_ergibt_2(self):
        os.mkdir(os.path.join(self.tmp, "db"))
        liste = os.path.join(self.tmp, "ausnahmen.txt")
        with open(liste, "w") as f:
            f.write("CVE-2024-8926 php 2027-06-30\n")
        rc, out = self.aufruf("--db", os.path.join(self.tmp, "db"), "--ausnahmen", liste, "web")
        self.assertEqual(rc, 2)
        self.assertIn("Ausnahmeliste", out)
        self.assertIn("Zeile 1", out)

    def test_ohne_container(self):
        rc, out = self.aufruf()
        self.assertEqual(rc, 2)
        self.assertIn("Container fehlt", out)

    def test_docker_nicht_erreichbar(self):
        self.docker("echo 'Cannot connect to the Docker daemon' >&2; exit 1\n")
        rc, out = self.aufruf("--db", self.db, "--oeffentliche", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("docker nicht erreichbar", out)
        rc, out = self.aufruf("--db", self.db, "web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("nicht gefunden", out)

    def test_keine_oeffentlichen_container(self):
        self.docker('[ "$1" = ps ] && exit 0\nexit 1\n')
        rc, out = self.aufruf("--db", self.db, "--oeffentliche", "berichte", LANG="C", LC_ALL="C")
        self.assertEqual(rc, 0)
        self.assertIn("Keine Container mit veröffentlichten Ports gefunden.", out)

    def test_fehlende_daten(self):
        rc, out = self.aufruf("--db", os.path.join(self.tmp, "fehlt"), "web")
        self.assertEqual(rc, 2)
        self.assertIn("keine OSV-Daten gefunden", out)

    def test_mehrere_db(self):
        da, db = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b")
        os.mkdir(da)
        rc, out = self.aufruf("--db", da, "--db", db, "web")
        self.assertEqual(rc, 2)
        self.assertIn("keine OSV-Daten gefunden (%s, %s)" % (da, db), out)
        rc, out = self.aufruf("--db", da, "--db", db, "--db-aktualisieren")
        self.assertEqual(rc, 2)
        self.assertIn("nur ein --db", out)

    def git_checkout(self, euid, daten="clone"):
        """Kopie des Skripts in einem (scheinbaren) Git-Checkout, --db-aktualisieren mit vorgetäuschter UID.
        daten: "clone" = daten/ ist ein Clone des Branches daten, "fehlt" = noch nicht geholt,
        "ohne-git" = daten/ ohne Git. Der git-Ersatz im PATH protokolliert seine Aufrufe."""
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        if daten == "clone":
            os.makedirs(os.path.join(repo, "daten", ".git"))
        elif daten == "ohne-git":
            os.makedirs(os.path.join(repo, "daten"))
        shutil.copy(SKRIPT, os.path.join(repo, "container-security-scan.py"))
        protokoll = os.path.join(self.tmp, "git-aufrufe")
        path = os.path.join(self.bin, "git")
        with open(path, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> %s\n'
                    'case "$*" in *"remote get-url origin"*) echo https://example.invalid/css.git ;; esac\n' % protokoll)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        code = ("import os, runpy, sys; os.geteuid = lambda: %d; sys.argv = [sys.argv[1], '--db-aktualisieren']; "
                "runpy.run_path(sys.argv[0], run_name='__main__')" % euid)
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""))
        p = subprocess.run([sys.executable, "-c", code, os.path.join(repo, "container-security-scan.py")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, cwd=self.tmp, timeout=120)
        aufrufe = []
        if os.path.exists(protokoll):
            with open(protokoll) as f:
                aufrufe = f.read().splitlines()
        return p.returncode, p.stderr.decode("utf-8", "replace"), aufrufe, repo

    def test_daten_nicht_als_root_aktualisieren(self):
        rc, out, aufrufe, _ = self.git_checkout(0)
        self.assertEqual(rc, 2)
        self.assertIn("als root abgelehnt", out)
        self.assertEqual(aufrufe, [])

    def test_git_pull_nur_im_daten_clone(self):
        rc, out, aufrufe, repo = self.git_checkout(1000)
        self.assertEqual(rc, 0, out)
        self.assertIn("per git pull aktualisiert", out)
        # nur die Daten, nie der Code-Checkout
        self.assertEqual(aufrufe, ["-C %s pull --ff-only --quiet" % os.path.join(repo, "daten")])

    def test_daten_branch_wird_geholt(self):
        rc, out, aufrufe, repo = self.git_checkout(1000, daten="fehlt")
        self.assertEqual(rc, 0, out)
        self.assertEqual(aufrufe, ["-C %s remote get-url origin" % repo,
                                   "clone --quiet --single-branch --branch daten https://example.invalid/css.git %s"
                                   % os.path.join(repo, "daten")])

    def test_daten_ohne_git_bricht_ab(self):
        rc, out, aufrufe, _ = self.git_checkout(1000, daten="ohne-git")
        self.assertEqual(rc, 2)
        self.assertIn("kein Git-Checkout des Branches daten", out)
        self.assertEqual(aufrufe, [])

    def als_root(self, *args):
        """Skript (kein Git-Checkout) mit vorgetäuschter UID 0 aufrufen."""
        code = ("import os, runpy, sys; os.geteuid = lambda: 0; sys.argv = sys.argv[1:]; "
                "runpy.run_path(sys.argv[0], run_name='__main__')")
        p = subprocess.run([sys.executable, "-c", code, SKRIPT] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, cwd=self.tmp, timeout=120)
        return p.returncode, p.stderr.decode("utf-8", "replace")

    def test_daten_nicht_als_root_laden(self):
        # Daten aus dem Netz nie als root schreiben (Zielverzeichnis kann einem anderen Benutzer gehören)
        ziel = os.path.join(self.tmp, "db")
        rc, out = self.als_root("--db", ziel, "--db-aktualisieren", "--oekosysteme", "Ubuntu")
        self.assertEqual(rc, 2)
        self.assertIn("als root abgelehnt", out)
        self.assertFalse(os.path.exists(ziel))

    def test_berichte_nur_fuer_den_aufrufer_lesbar(self):
        db = os.path.join(self.tmp, "db")
        os.mkdir(db)
        gesehen = []

        def scan(name, a, via=None, urls=None):
            alt = os.umask(0)
            os.umask(alt)
            gesehen.append(alt)
            return 0, [], None, {}
        alt = os.umask(0o022)
        try:
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(scanner, "docker_lage", side_effect=scanner.ScanError("x")), \
                    mock.patch.object(sys, "argv", ["x", "--db", db, "web", self.tmp]):
                self.assertEqual(scanner.main(), 0)
        finally:
            os.umask(alt)
        self.assertEqual(gesehen, [0o077])

    def mehrere(self, option, public, rest, gruppen, backends, weg=(), host=([], [], [], [])):
        """main() mit --oeffentliche/--alle-container; liefert (Rückgabewert, [(Container, via)], Ausgabe)."""
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        gesehen = []

        def scan(name, a, via=None, urls=None):
            if name in weg:
                raise scanner.ScanError("Container '%s' nicht gefunden" % name)
            gesehen.append((name, via))
            return 0, backends.get(name, []), None, {}

        def run(cmd, *a, **kw):
            return (1, "") if cmd[:2] == ["docker", "inspect"] and cmd[-1] in weg else (0, "")
        with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                mock.patch.object(scanner, "docker_lage", return_value=([], {})), \
                mock.patch.object(scanner, "container_liste", return_value=(public, rest, gruppen)), \
                mock.patch.object(scanner, "host_proxys", return_value=host), \
                mock.patch.object(scanner, "run", side_effect=run), \
                mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch.object(sys, "argv", ["x", "--db", db, option, self.tmp]):
            rc = scanner.main()
        return rc, gesehen, out.getvalue()

    def test_erneute_pruefung_ersetzt_bericht(self):
        """app wird als Backend von proxy erneut geprüft: der erste Bericht entfällt, der neue bleibt –
        auch wenn beide Prüfungen in derselben Sekunde liefen (gleicher Dateiname)."""
        for namen in (["app-1", "app-2"], ["app-1", "app-1"]):
            namen_iter = iter(namen)

            def scan(name, a, via=None, urls=None):
                base = os.path.join(self.tmp, next(namen_iter) if name == "app" else name)
                for ext in (".md", ".cdx.json", ".sha256"):
                    with open(base + ext, "w") as f:
                        f.write(name)
                return 0, [("app", "3000", "nginx:80 in proxy")] if name == "proxy" else [], base, {}
            db = os.path.join(self.tmp, "db")
            os.makedirs(db, exist_ok=True)
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(scanner, "docker_lage", return_value=([], {})), \
                    mock.patch.object(scanner, "container_liste", return_value=(["app", "proxy"], [], {})), \
                    mock.patch.object(scanner, "host_proxys", return_value=([], [], [], [])), \
                    mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO), \
                    mock.patch.object(sys, "argv", ["x", "--db", db, "--oeffentliche", self.tmp]):
                self.assertEqual(scanner.main(), 0)
            for ext in (".md", ".cdx.json", ".sha256"):
                self.assertTrue(os.path.exists(os.path.join(self.tmp, namen[1] + ext)), (namen, ext))
                self.assertEqual(os.path.exists(os.path.join(self.tmp, namen[0] + ext)), namen[0] == namen[1])

    def test_alle_container(self):
        # proxy erreichbar -> Backend app (mit dem Port) und, da Traefik nicht auswertbar, alle Nachbarn ("*");
        # Backends vor den übrigen Containern; vpn nutzt das Netzwerk von "mit" -> Ziel geht an beide
        backends = {"proxy": [("app", "3000", "nginx:80 in proxy"), ("db", "*", "traefik:443 in proxy"),
                              ("vpn", "8080", "nginx:80 in proxy")]}
        rc, gesehen, _ = self.mehrere("--alle-container", ["proxy"], ["app", "cron", "db", "mit", "vpn"],
                                      {"vpn": ["mit"], "mit": ["vpn"]}, backends)
        self.assertEqual(rc, 0)
        self.assertEqual(gesehen, [("proxy", {}), ("mit", {"8080": ["nginx:80 in proxy"]}),
                                   ("vpn", {"8080": ["nginx:80 in proxy"]}), ("db", {"*": ["traefik:443 in proxy"]}),
                                   ("app", {"3000": ["nginx:80 in proxy"]}), ("cron", {})])
        # --oeffentliche: nur erreichbare Container und ihre Backends
        rc, gesehen, _ = self.mehrere("--oeffentliche", ["proxy"], ["app", "cron", "db"], {}, backends)
        self.assertEqual(sorted(n for n, _ in gesehen), ["app", "db", "proxy", "vpn"])

    def test_ziele_eines_proxys_auf_dem_host(self):
        # nginx auf dem Host vor app (Container-IP, kein veröffentlichter Port): app zuerst, als erreichbar
        svc = {"label": "nginx:443 auf dem Host", "exposed": True, "backends": [("app", "3000", "nginx:443")]}
        host = ([("app", "3000", "nginx:443 auf dem Host")], [svc], [], [])
        rc, gesehen, out = self.mehrere("--alle-container", ["proxy"], ["app", "db"], {}, {}, host=host)
        self.assertEqual((rc, gesehen[0]), (0, ("app", {"3000": ["nginx:443 auf dem Host"]})))
        self.assertEqual([n for n, _ in gesehen], ["app", "proxy", "db"])
        self.assertIn("Host: nginx:443 auf dem Host – erreichbar; Ziele in Containern: app (3000)", out)
        # Konfiguration auf dem Host nicht lesbar: unvollständig
        rc, _, out = self.mehrere("--alle-container", ["proxy"], [], {}, {},
                                  host=([], [], [], ["/usr/sbin/nginx -T fehlgeschlagen"]))
        self.assertEqual(rc, 2)
        self.assertIn("Host: UNVOLLSTÄNDIG: /usr/sbin/nginx -T fehlgeschlagen", out)

    def test_webadressen_der_ziele(self):
        # Webadressen eines Proxys auf dem Host gehen an den Scan des Ziels (auch an den Container mit demselben
        # Netzwerk-Namespace); die eines Proxys in einem Container an seine Ziele, schon geprüfte erneut
        e_host = {"url": "https://www.example.org/app/", "erreichbar": True, "weg": "nginx:443 auf dem Host"}
        e_proxy = {"url": "https://shop.example.org/", "erreichbar": True, "weg": "nginx:80 in proxy"}
        gesehen = []

        def scan(name, a, via=None, urls=None):
            gesehen.append((name, urls))
            if name == "proxy":
                return 0, [("app", "3000", "nginx:80 in proxy")], None, {("app", "3000"): [e_proxy]}
            return 0, [], None, {}
        a = mock.Mock(alle_container=True, host=True)
        with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = scanner.container_lauf(a, ["app", "proxy"], [], {"app": ["mit"]},
                                        [("app", "3000", "nginx:443 auf dem Host")], 0, {("app", "3000"): [e_host]})
        self.assertEqual(rc, 0)
        self.assertEqual(gesehen, [("mit", {"3000": [e_host]}), ("app", {"3000": [e_host]}), ("proxy", None),
                                   ("mit", {"3000": [e_host, e_proxy]}), ("app", {"3000": [e_host, e_proxy]})])

    def test_einzelscan_kennt_proxys_auf_dem_host(self):
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        infos = [{"Id": "abc123", "Name": "/app", "HostConfig": {}, "NetworkSettings": {"Networks": {"n": {}}}}]
        host = ([("app", "3000", "nginx:443 auf dem Host"), ("db", "*", "nginx:443 auf dem Host")], [], [], [])
        for ref in ("app", "abc"):
            with mock.patch.object(scanner, "scan_container", return_value=(0, [], None, {})) as scan, \
                    mock.patch.object(scanner, "docker_lage", return_value=(infos, {})), \
                    mock.patch.object(scanner, "host_proxys", return_value=host), \
                    mock.patch("sys.stdout", new_callable=io.StringIO), \
                    mock.patch.object(sys, "argv", ["x", "--db", db, ref, self.tmp]):
                self.assertEqual(scanner.main(), 0)
            self.assertEqual(scan.call_args[0][2], {"3000": ["nginx:443 auf dem Host"]})

    def host_lauf(self, args, docker=True, infos=([], {}), host=(1, [], None, {}), docker_fehler=False, public=()):
        """main() mit --host; liefert (Rückgabewert, gescannte Container, Ausgabe, Mock von scan_host)."""
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        gesehen = []

        def scan(name, a, via=None, urls=None):
            gesehen.append((name, via))
            return 0, [], None, {}
        lage = mock.Mock(side_effect=scanner.ScanError("docker nicht erreichbar")) if docker_fehler else \
            mock.Mock(return_value=infos)
        with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                mock.patch.object(scanner, "docker_vorhanden", return_value=docker), \
                mock.patch.object(scanner, "docker_lage", lage), \
                mock.patch.object(scanner, "container_liste", return_value=(list(public), ["db"], {})), \
                mock.patch.object(scanner, "host_proxys") as host_proxys, \
                mock.patch.object(scanner, "scan_host", return_value=host) as scan_host, \
                mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch.object(sys, "argv", ["x", "--db", db] + args + [self.tmp]):
            rc = scanner.main()
        host_proxys.assert_not_called()        # mit --host bewertet scan_host die Proxys auf dem Host
        return rc, gesehen, out.getvalue(), scan_host, lage

    def test_host_ohne_docker(self):
        # reiner Webserver: nur der Host, auch mit --alle-container (so im Wrapper); Docker wird nicht befragt
        for args in (["--host"], ["--host", "--alle-container"]):
            rc, gesehen, out, scan_host, lage = self.host_lauf(args, docker=False)
            self.assertEqual((rc, gesehen), (1, []))
            self.assertEqual(scan_host.call_args[0][0].ausgabe, self.tmp)       # erstes Argument: Ausgabeverzeichnis
            self.assertEqual(scan_host.call_args[0][1], [])
            lage.assert_not_called()
        self.assertIn("Docker nicht vorhanden – nur der Host wird geprüft.", out)

    def test_host_und_container(self):
        # Ziele eines Proxys auf dem Host zuerst und als erreichbar; Ergebnis des Hosts zählt mit
        infos = ([{"Id": "abc", "Name": "/app"}], {})
        rc, gesehen, out, scan_host, _ = self.host_lauf(
            ["--host", "--alle-container"], infos=infos, host=(1, [("app", "3000", "nginx:443 auf dem Host")], None, {}),
            public=["proxy"])
        self.assertEqual(rc, 1)
        self.assertEqual(scan_host.call_args[0][1], infos[0])
        self.assertEqual(gesehen, [("app", {"3000": ["nginx:443 auf dem Host"]}), ("proxy", {}), ("db", {})])
        self.assertIn("Gesamt: Host und 3 Container geprüft – RELEVANTE FUNDE", out)
        rc, gesehen, out, _, _ = self.host_lauf(["--host", "--alle-container"], infos=infos, host=(2, [], None, {}))
        self.assertEqual(rc, 2)

    def test_host_docker_nicht_erreichbar(self):
        # Docker eingerichtet, aber nicht erreichbar: mit Containern unvollständig, nur der Host: Warnung
        rc, gesehen, out, scan_host, _ = self.host_lauf(["--host", "--alle-container"], docker_fehler=True,
                                                         host=(0, [], None, {}))
        self.assertEqual((rc, gesehen), (2, []))
        scan_host.assert_called_once()
        rc, gesehen, out, _, _ = self.host_lauf(["--host"], docker_fehler=True, host=(0, [], None, {}))
        self.assertEqual(rc, 0)
        self.assertIn("Host: WARNUNG: Container nicht ermittelbar", out)

    def test_alle_container_ohne_container(self):
        rc, gesehen, out = self.mehrere("--alle-container", [], [], {}, {})
        self.assertEqual((rc, gesehen), (0, []))
        self.assertIn("Keine laufenden Container gefunden.", out)

    def test_verschwundener_container_wird_uebersprungen(self):
        # z.B. docker run --rm, zwischen Auflistung und Scan beendet: nicht mehr vorhanden -> kein Fehler
        rc, gesehen, out = self.mehrere("--alle-container", ["proxy"], ["einmalig"], {}, {}, weg=("einmalig",))
        self.assertEqual((rc, [n for n, _ in gesehen]), (0, ["proxy"]))
        self.assertIn("einmalig: übersprungen – Container nicht mehr vorhanden", out)

    def test_unerwarteter_fehler_ergibt_2(self):
        # docker inspect liefert Unsinn -> Ausnahme im Skript, darf nie als 0 oder 1 enden
        self.docker('[ "$1" = inspect ] && echo "[{}]" && exit 0\nexit 1\n')
        rc, out = self.aufruf("--db", self.db, "web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
