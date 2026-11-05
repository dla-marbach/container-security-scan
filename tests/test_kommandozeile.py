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
        rc, out = self.aufruf("--oeffentliche", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("docker nicht erreichbar", out)
        rc, out = self.aufruf("web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("nicht gefunden", out)

    def test_keine_oeffentlichen_container(self):
        self.docker('[ "$1" = ps ] && exit 0\nexit 1\n')
        rc, out = self.aufruf("--oeffentliche", "berichte", LANG="C", LC_ALL="C")
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

    def git_checkout(self, euid):
        """Kopie des Skripts in einem (scheinbaren) Git-Checkout, --db-aktualisieren mit vorgetäuschter UID;
        git-Ersatz im PATH vermerkt, ob git pull aufgerufen wurde."""
        repo = os.path.join(self.tmp, "repo")
        for d in (".git", "osv-daten"):
            os.makedirs(os.path.join(repo, d))
        shutil.copy(SKRIPT, os.path.join(repo, "container-security-scan.py"))
        marke = os.path.join(self.tmp, "git-aufgerufen")
        path = os.path.join(self.bin, "git")
        with open(path, "w") as f:
            f.write('#!/bin/sh\necho "$@" > %s\n' % marke)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        code = ("import os, runpy, sys; os.geteuid = lambda: %d; sys.argv = [sys.argv[1], '--db-aktualisieren']; "
                "runpy.run_path(sys.argv[0], run_name='__main__')" % euid)
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""))
        p = subprocess.run([sys.executable, "-c", code, os.path.join(repo, "container-security-scan.py")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, cwd=self.tmp, timeout=120)
        return p.returncode, p.stderr.decode("utf-8", "replace"), os.path.exists(marke)

    def test_git_pull_nicht_als_root(self):
        rc, out, git = self.git_checkout(0)
        self.assertEqual(rc, 2)
        self.assertIn("als root abgelehnt", out)
        self.assertFalse(git)

    def test_git_pull_als_benutzer(self):
        rc, out, git = self.git_checkout(1000)
        self.assertEqual(rc, 0, out)
        self.assertIn("per git pull aktualisiert", out)
        self.assertTrue(git)

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
        rc, out = self.aufruf("web", "berichte")
        self.assertEqual(rc, 2)
        self.assertIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
