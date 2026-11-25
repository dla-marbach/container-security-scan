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
        # main() mit nachgebildetem docker_lage: auch die gestoppten Container nicht beim echten docker abfragen
        p = mock.patch.object(scanner, "gestoppte_container", return_value=3)
        p.start()
        self.addCleanup(p.stop)

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
        self.assertIn("--ausnahmen", out)
        self.assertNotIn("--eol-daten-erzeugen", out)      # nur für die GitHub Action
        self.assertNotIn("--kev-daten-erzeugen", out)

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
        self.assertIn("docker nicht erreichbar", out)

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

        def scan(name, a, via=None, urls=None, anlass=None):
            alt = os.umask(0)
            os.umask(alt)
            gesehen.append(alt)
            return 0, [], None, {}
        alt = os.umask(0o022)
        try:
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(scanner, "erreichbarkeit_pruefen", return_value=(None, [], None, {})), \
                    mock.patch.object(scanner, "docker_lage", return_value=([{"Id": "abc", "Name": "/web"}], {})), \
                    mock.patch.object(scanner, "container_liste", return_value=([], ["web"], {})), \
                    mock.patch.object(scanner, "host_proxys", return_value=([], [], [], [], {})), \
                    mock.patch("sys.stdout", new_callable=io.StringIO), \
                    mock.patch.object(sys, "argv", ["x", "--db", db, "web", self.tmp]):
                self.assertEqual(scanner.main(), 0)
        finally:
            os.umask(alt)
        self.assertEqual(gesehen, [0o077])

    def test_bericht_und_sbom_nur_auf_wunsch(self):
        db = os.path.join(self.tmp, "db")
        os.mkdir(db)
        gesehen = []

        def scan(name, a, via=None, urls=None, anlass=None):
            gesehen.append((a.bericht, a.sbom))
            return 0, [], None, {}
        for optionen in ([], ["--bericht"], ["--sbom"], ["--bericht", "--sbom"]):
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(scanner, "erreichbarkeit_pruefen", return_value=(None, [], None, {})), \
                    mock.patch.object(scanner, "docker_lage", return_value=([{"Id": "abc", "Name": "/web"}], {})), \
                    mock.patch.object(scanner, "container_liste", return_value=([], ["web"], {})), \
                    mock.patch.object(scanner, "host_proxys", return_value=([], [], [], [], {})), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                    mock.patch.object(sys, "argv", ["x", "--db", db] + optionen + ["web", self.tmp]):
                self.assertEqual(scanner.main(), 0)
        self.assertEqual(gesehen, [(False, False), (True, False), (False, True), (True, True)])
        # Kopf: Version, Zeitpunkt, Stand der Daten, Host mit den laufenden Containern (bei einer Auswahl die geprüften)
        kopf = out.getvalue().splitlines()
        self.assertEqual(kopf[0], "container-security-scan " + scanner.VERSION)
        self.assertRegex(kopf[1], r"^Scan: \d{4}-\d\d-\d\d \d\d:\d\d UTC$")
        self.assertEqual(kopf[2:5], ["Daten: Stand unbekannt", "Host: %s mit 1 laufenden und 3 gestoppten Containern, "
                                     "davon geprüft:" % os.uname().nodename, "- web  erstellt ?, läuft"])

    def test_pausierte_nur_kontext(self):
        # vpn ist pausiert (docker exec nicht möglich): nicht geprüft, auch nicht als Ziel eines Proxys; der laufende
        # Container mit seinem Netzwerk-Namespace bleibt über dessen veröffentlichten Port erreichbar
        db = os.path.join(self.tmp, "db")
        os.mkdir(db)
        vpn = {"Id": "v" * 64, "Name": "/vpn", "State": {"Paused": True}, "HostConfig": {"NetworkMode": "bridge"},
               "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
                                   "Networks": {"back": {}}}}
        mit = {"Id": "m" * 64, "Name": "/mit", "State": {"Running": True},
               "HostConfig": {"NetworkMode": "container:" + "v" * 64}, "NetworkSettings": {"Ports": {}, "Networks": {}}}
        gesehen = []

        def scan(name, a, via=None, urls=None, anlass=None):
            gesehen.append(name)
            return 0, [("vpn", "*", "traefik:80 in proxy")], None, {}
        for argv in (["--alle-container"], ["--container", "*"]):
            gesehen[:] = []
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(scanner, "erreichbarkeit_pruefen",
                                      side_effect=lambda n, *a, **kw: gesehen.append("erreichbarkeit " + n)
                                      or (None, [], None, {})), \
                    mock.patch.object(scanner, "docker_lage", return_value=([vpn, mit], {})), \
                    mock.patch.object(scanner, "host_proxys", return_value=([], [], [], [], {})), \
                    mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                    mock.patch.object(sys, "argv", ["x", "--db", db] + argv + [self.tmp]):
                self.assertEqual(scanner.main(), 0)
            self.assertNotIn("vpn", gesehen, argv)
            self.assertIn("mit", gesehen, argv)
            self.assertIn(" mit 1 laufenden, 1 pausierten und 3 gestoppten Containern%s\n- mit "
                          % (":" if argv[0] == "--alle-container" else ", davon geprüft:"), out.getvalue())
        # Kontext: der Spender liefert die Veröffentlichung -> mit ist direkt erreichbar
        public, rest, _ = scanner.container_liste([vpn, mit], {})
        self.assertIn("mit", public)

    def mehrere(self, option, public, rest, gruppen, backends, weg=(), host=([], [], [], [], {})):
        """main() mit --oeffentliche/--alle-container; liefert (Rückgabewert, [(Container, via)], Ausgabe)."""
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        gesehen = []

        def scan(name, a, via=None, urls=None, anlass=None):
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

            def scan(name, a, via=None, urls=None, anlass=None):
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
                    mock.patch.object(scanner, "host_proxys", return_value=([], [], [], [], {})), \
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
        host = ([("app", "3000", "nginx:443 auf dem Host")], [svc], [], [], {})
        rc, gesehen, out = self.mehrere("--alle-container", ["proxy"], ["app", "db"], {}, {}, host=host)
        self.assertEqual((rc, gesehen[0]), (0, ("app", {"3000": ["nginx:443 auf dem Host"]})))
        self.assertEqual([n for n, _ in gesehen], ["app", "proxy", "db"])
        self.assertIn("Host: nginx:443 auf dem Host – erreichbar; Ziele in Containern: app (3000)", out)
        # Konfiguration auf dem Host nicht lesbar: unvollständig
        rc, _, out = self.mehrere("--alle-container", ["proxy"], [], {}, {},
                                  host=([], [], [], ["/usr/sbin/nginx -T fehlgeschlagen"], {}))
        self.assertEqual(rc, 2)
        self.assertIn("Host: UNVOLLSTÄNDIG: /usr/sbin/nginx -T fehlgeschlagen", out)

    def test_loopback_zweifel_aus_den_prozessen_des_hosts(self):
        # an 127.0.0.1 veröffentlichte Ports zählen nur mit einem Proxy auf dem Host davor – außer die Prozesse des
        # Hosts sind nicht vollständig lesbar (ein Proxy dort bliebe unerkannt): dann im Zweifel erreichbar
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        gesehen = []

        def scan(name, a, via=None, urls=None, bekannt=None, anlass=None):
            gesehen.append(a.loopback_zweifel)
            return 0, [], None, {}
        gesperrt = scanner.HOST_NICHT_LESBAR + " (3; Skript nicht als root?) – Reverse Proxys auf dem Host ggf. " \
                                               "nicht erkannt"
        # fehlgeschlagene Abfrage der Proxys auf dem Host: Problem (Rückgabewert 2) und ebenfalls im Zweifel erreichbar
        fehler = scanner.HOST_NICHT_LESBAR + ": Abfrage der Proxys auf dem Host über /proc fehlgeschlagen " \
                                             "(Rückgabewert 1) – Reverse Proxys auf dem Host nicht ausgewertet"
        for warnungen, probleme, erwartet, code in (([], [], "", 0), ([gesperrt], [], scanner.HOST_NICHT_LESBAR, 0),
                                                    ([], [fehler], scanner.HOST_NICHT_LESBAR, 2),
                                                    ([], ["/usr/sbin/nginx -T fehlgeschlagen"], "", 2)):
            # Gesamtlauf; Auswahl: Erreichbarkeit über alle Container, dann der Scan
            for argv, anzahl in ((["--alle-container"], 1), (["--container", "web"], 2)):
                gesehen[:] = []
                with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                        mock.patch.object(scanner, "erreichbarkeit_pruefen",
                                          side_effect=lambda n, a, *x: gesehen.append(a.loopback_zweifel)
                                          or (None, [], None, {})), \
                        mock.patch.object(scanner, "docker_lage", return_value=([{"Id": "abc", "Name": "/web"}], {})), \
                        mock.patch.object(scanner, "container_liste", return_value=(["web"], [], {})), \
                        mock.patch.object(scanner, "host_proxys", return_value=([], [], warnungen, probleme, {})), \
                        mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO), \
                        mock.patch.object(sys, "argv", ["x", "--db", db] + argv + [self.tmp]):
                    self.assertEqual(scanner.main(), code, (warnungen, probleme, argv))
                self.assertEqual(gesehen, [erwartet] * anzahl, (warnungen, probleme, argv))

    def auswahl(self, args, infos, public, rest, gruppen, backends, host=([], [], [], [], {}), fehler=(),
                ziel_urls=None):
        """main() mit Einzelscan bzw. --container: Erreichbarkeit über alle Container (erreichbarkeit_pruefen),
        vollständig nur die Auswahl (scan_container). Liefert (Rückgabewert, [Erreichbarkeit (Container, via)],
        [Scan (Container, via)], Ausgabe); an scan_container übergebene Webadressen in self.voll_urls."""
        db = os.path.join(self.tmp, "db")
        os.makedirs(db, exist_ok=True)
        leicht, voll = [], []

        def erreichbarkeit(name, a, via=None, urls=None):
            if name in fehler:
                raise scanner.ScanError("Prozesse in %s nicht ermittelbar" % name)
            leicht.append((name, via))
            return None, backends.get(name, []), None, (ziel_urls or {}).get(name, {})

        self.voll_urls = {}

        def scan(name, a, via=None, urls=None, anlass=None):
            voll.append((name, via))
            self.voll_urls[name] = urls
            return 1 if name.startswith("surveyor") else 0, backends.get(name, []), None, {}
        with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                mock.patch.object(scanner, "erreichbarkeit_pruefen", side_effect=erreichbarkeit), \
                mock.patch.object(scanner, "docker_lage", return_value=(infos, {})), \
                mock.patch.object(scanner, "container_liste", return_value=(public, rest, gruppen)), \
                mock.patch.object(scanner, "host_proxys", return_value=host), \
                mock.patch.object(scanner, "run", return_value=(0, "")), \
                mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch.object(sys, "argv", ["x", "--db", db] + args + [self.tmp]):
            rc = scanner.main()
        return rc, leicht, voll, out.getvalue()

    def test_einzelscan_kennt_proxys_auf_dem_host(self):
        infos = [{"Id": "abc123", "Name": "/app"}, {"Id": "def456", "Name": "/db"}]
        host = ([("app", "3000", "nginx:443 auf dem Host"), ("db", "*", "nginx:443 auf dem Host")], [], [], [], {})
        for ref in ("app", "abc"):
            rc, _, voll, _ = self.auswahl([ref], infos, [], ["app", "db"], {}, {}, host=host)
            self.assertEqual((rc, voll), (0, [("app", {"3000": ["nginx:443 auf dem Host"]})]))

    def test_einzelscan_wie_im_gesamtlauf(self):
        # app ist nur über nginx in proxy erreichbar, db nur über einen Aufruf von app: im Einzelscan dieselbe
        # Erreichbarkeit wie im Gesamtlauf, vollständig geprüft wird nur der gewählte Container
        infos = [{"Id": "a1", "Name": "/app"}, {"Id": "d1", "Name": "/db"}, {"Id": "p1", "Name": "/proxy"}]
        backends = {"proxy": [("app", "3000", "nginx:80 in proxy")],
                    "app": [("db", "8080", "node:3000 (Ziel-URL) in app")]}
        _, gesamt, _ = self.mehrere("--alle-container", ["proxy"], ["app", "db"], {}, backends)
        for name in ("app", "db"):
            rc, leicht, voll, out = self.auswahl([name], infos, ["proxy"], ["app", "db"], {}, backends)
            self.assertEqual(rc, 0)
            self.assertEqual(leicht, gesamt)                    # gleiche Reihenfolge und Weitergabe
            self.assertEqual(voll, [x for x in gesamt if x[0] == name])
            self.assertIn("Gesamt: 1 von 3 Containern geprüft (%s) – OK" % name, out)

    def test_durchlauf_gibt_webadressen_weiter(self):
        # Webadressen des Proxys auf dem Host an proxy, dessen weitergeleitete an app (mit dem Port im Ziel)
        e_host = {"url": "https://www.example.org/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False}
        e_proxy = dict(e_host, url="https://www.example.org/app/", weg="nginx:443 auf dem Host → nginx:80 in proxy")
        gesehen = []

        def pruefen(name, via, urls, anlass):
            gesehen.append((name, urls))
            if name == "proxy":
                return 0, [("app", "3000", "nginx:80 in proxy")], None, {("app", "3000"): [e_proxy]}
            return 0, [], None, {}
        _, urls, fehler = scanner.durchlauf([], ["app"], [("proxy", "80", "nginx:443 auf dem Host")], {}, pruefen,
                                            ziel_urls={("proxy", "80"): [e_host]})
        self.assertEqual(gesehen, [("proxy", {"80": [e_host]}), ("app", {"3000": [e_proxy]})])
        self.assertEqual((urls, fehler), ({"proxy": {"80": [e_host]}, "app": {"3000": [e_proxy]}}, []))
        # app schon geprüft, danach kommen nur neue Webadressen hinzu (kein neuer Grund): erneut geprüft
        gesehen[:] = []

        def pruefen2(name, via, urls, anlass):
            gesehen.append((name, urls, anlass))
            return 0, [], None, {("app", "3000"): [e_proxy]} if name == "proxy" else {}
        scanner.durchlauf(["app", "proxy"], [], [], {}, pruefen2)
        self.assertEqual(gesehen, [("app", None, None), ("proxy", None, None),
                                   ("app", {"3000": [e_proxy]}, "neuer Webadressen von proxy")])
        # neuer Weg zu einem schon geprüften Container (zweiter Proxy): Anlass für die Überschrift
        gesehen[:] = []

        def pruefen3(name, via, urls, anlass):
            gesehen.append((name, anlass))
            return 0, [("app", "3000", "traefik:80 in traefik")] if name == "traefik" else [], None, {}
        scanner.durchlauf(["app", "traefik"], [], [], {}, pruefen3)
        self.assertEqual(gesehen, [("app", None), ("traefik", None),
                                   ("app", "eines neuen Wegs über traefik:80 in traefik")])

    def test_auswahl_mit_webadressen_wie_im_gesamtlauf(self):
        infos = [{"Id": "a1", "Name": "/app"}, {"Id": "p1", "Name": "/proxy"}]
        e_host = {"url": "https://www.example.org/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False}
        e_proxy = dict(e_host, url="https://www.example.org/app/", weg="nginx:443 auf dem Host → nginx:80 in proxy")
        host = ([("proxy", "80", "nginx:443 auf dem Host")], [], [], [], {("proxy", "80"): [e_host]})
        rc, _, voll, _ = self.auswahl(["app"], infos, [], ["app", "proxy"], {},
                                      {"proxy": [("app", "3000", "nginx:80 in proxy")]}, host=host,
                                      ziel_urls={"proxy": {("app", "3000"): [e_proxy]}})
        self.assertEqual((rc, voll), (0, [("app", {"3000": ["nginx:80 in proxy"]})]))
        self.assertEqual(self.voll_urls, {"app": {"3000": [e_proxy]}})

    def test_auswahl_mit_muster(self):
        infos = [{"Id": "s1", "Name": "/surveyor_app"}, {"Id": "s2", "Name": "/surveyor_db"},
                 {"Id": "x1", "Name": "/surveyorx"}, {"Id": "p1", "Name": "/proxy"}]
        backends = {"proxy": [("surveyor_app", "8080", "nginx:80 in proxy")]}
        rc, _, voll, out = self.auswahl(["--container", "surveyor_*"], infos, ["proxy"],
                                        ["surveyor_app", "surveyor_db", "surveyorx"], {}, backends)
        self.assertEqual(rc, 1)
        self.assertEqual(voll, [("surveyor_app", {"8080": ["nginx:80 in proxy"]}), ("surveyor_db", {})])
        self.assertIn("Gesamt: 2 von 4 Containern geprüft (surveyor_*) – RELEVANTE FUNDE", out)
        # Kopf: Zahl aller laufenden, aufgeführt nur die geprüften
        self.assertIn(" mit 4 laufenden und 3 gestoppten Containern, davon geprüft:\n- surveyor_app  erstellt ?, läuft\n"
                      "- surveyor_db   erstellt ?, läuft\n", out)
        self.assertNotIn("- proxy", out)
        # mehrere Muster, ID-Anfang; [..] wie in der Shell
        rc, _, voll, _ = self.auswahl(["--container", "prox?", "--container", "x1", "surveyor_[d]*"], infos,
                                      ["proxy"], [], {}, {})
        self.assertEqual(sorted(n for n, _ in voll), ["proxy", "surveyor_db", "surveyorx"])

    def test_auswahl_ohne_treffer_oder_mit_fehler_ergibt_2(self):
        infos = [{"Id": "a1", "Name": "/app"}, {"Id": "p1", "Name": "/proxy"}]
        rc, leicht, voll, out = self.auswahl(["--container", "surveyor_*"], infos, ["proxy"], ["app"], {}, {})
        self.assertEqual((rc, leicht, voll), (2, [], []))
        self.assertIn(" mit 2 laufenden und 3 gestoppten Containern, davon geprüft: keiner\n", out)
        self.assertNotIn("- app", out)
        # Erreichbarkeit über einen anderen Container nicht ermittelbar: Ergebnis der Auswahl ggf. unvollständig
        rc, _, voll, out = self.auswahl(["app"], infos, ["proxy"], ["app"], {}, {}, fehler=("proxy",))
        self.assertEqual((rc, voll), (2, [("app", {})]))
        self.assertIn("UNVOLLSTÄNDIG: Erreichbarkeit über proxy nicht ermittelbar", out)
        # mit --alle-container bzw. --oeffentliche nicht kombinierbar
        with self.assertRaises(SystemExit):
            self.auswahl(["--alle-container", "--container", "app"], infos, [], [], {}, {})

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
        self.docker('case "$1" in ps) echo abc ;; inspect) echo \'[{"Name": "/web", "Id": "abc"}]\' ;; esac\nexit 0\n')
        rc, out = self.aufruf("--db", self.db, "web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
