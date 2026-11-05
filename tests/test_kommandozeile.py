"""Aufruf als Programm: Optionen und Rückgabewerte, mit einem nachgebildeten docker-Befehl."""
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

    def test_hilfe(self):
        rc, out = self.aufruf("--help")
        self.assertEqual(rc, 0)
        self.assertIn("--oeffentliche", out)
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
        daten: "clone" = osv-daten ist ein Clone des Branches daten, "fehlt" = noch nicht geholt,
        "alt" = osv-daten ohne Git (altes Layout). Der git-Ersatz im PATH protokolliert seine Aufrufe."""
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        if daten == "clone":
            os.makedirs(os.path.join(repo, "osv-daten", ".git"))
        elif daten == "alt":
            os.makedirs(os.path.join(repo, "osv-daten"))
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
        self.assertEqual(aufrufe, ["-C %s pull --ff-only --quiet" % os.path.join(repo, "osv-daten")])

    def test_daten_branch_wird_geholt(self):
        rc, out, aufrufe, repo = self.git_checkout(1000, daten="fehlt")
        self.assertEqual(rc, 0, out)
        self.assertEqual(aufrufe, ["-C %s remote get-url origin" % repo,
                                   "clone --quiet --single-branch --branch daten https://example.invalid/css.git %s"
                                   % os.path.join(repo, "osv-daten")])

    def test_altes_layout_bricht_ab(self):
        rc, out, aufrufe, _ = self.git_checkout(1000, daten="alt")
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

        def scan(name, a, via=None):
            alt = os.umask(0)
            os.umask(alt)
            gesehen.append(alt)
            return 0, [], None
        alt = os.umask(0o022)
        try:
            with mock.patch.object(scanner, "scan_container", side_effect=scan), \
                    mock.patch.object(sys, "argv", ["x", "--db", db, "web", self.tmp]):
                self.assertEqual(scanner.main(), 0)
        finally:
            os.umask(alt)
        self.assertEqual(gesehen, [0o077])

    def test_unerwarteter_fehler_ergibt_2(self):
        # docker inspect liefert Unsinn -> Ausnahme im Skript, darf nie als 0 oder 1 enden
        self.docker('[ "$1" = inspect ] && echo "[{}]" && exit 0\nexit 1\n')
        rc, out = self.aufruf("--db", self.db, "web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
