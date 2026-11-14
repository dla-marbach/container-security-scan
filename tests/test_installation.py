"""Version, Installscript, Wrapper, Vorlage der Ausnahmeliste und Beispiele passen zusammen."""
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
import unittest

from _laden import ROOT, SKRIPT, scanner

INSTALLATION = os.path.join(ROOT, "installation")
INSTALLSCRIPT = os.path.join(INSTALLATION, "installieren.sh")
WRAPPER = os.path.join(INSTALLATION, "container-security-scan-lauf")
AUSNAHMEN = os.path.join(INSTALLATION, "ausnahmen.txt")
BEISPIELE = os.path.join(ROOT, "beispiele")


def lesen(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_format(self):
        self.assertRegex(scanner.VERSION, r"^\d+\.\d+\.\d+$")

    def test_genau_eine_zeile_fuer_das_installscript(self):
        # installieren.sh prüft die Version im Skript mit grep -x 'VERSION = "X.Y.Z"'
        self.assertEqual(re.findall(r"(?m)^VERSION = .*$", lesen(SKRIPT)), ['VERSION = "%s"' % scanner.VERSION])

    def test_kommandozeile(self):
        out = subprocess.run([sys.executable, "-I", SKRIPT, "--version"], stdout=subprocess.PIPE,
                             universal_newlines=True, check=True).stdout
        self.assertEqual(out.strip(), "container-security-scan " + scanner.VERSION)

    def test_tag_entspricht_version(self):
        if os.environ.get("GITHUB_REF_TYPE") != "tag":
            self.skipTest("kein Push eines Tags")
        self.assertEqual(os.environ.get("GITHUB_REF_NAME"), "v" + scanner.VERSION,
                         "Tag und VERSION in container-security-scan.py stimmen nicht überein")


class InstallationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_syntax(self):
        for path in (INSTALLSCRIPT, WRAPPER):
            self.assertTrue(lesen(path).startswith("#!/bin/bash\n"), path)
            r = subprocess.run(["bash", "-n", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True)
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_installscript_nutzt_vorhandene_dateien(self):
        dateien = set(re.findall(r'"\$S/([^"]+)"', lesen(INSTALLSCRIPT)))
        self.assertEqual(dateien, {"container-security-scan.py", "installation/container-security-scan-lauf",
                                   "installation/ausnahmen.txt"})
        for d in dateien:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, d)), d)

    def test_wrapper_isoliert(self):
        wrapper = lesen(WRAPPER)
        aufrufe = re.findall(r'(\S+) "\$CODE"', wrapper)
        self.assertTrue(aufrufe)
        self.assertEqual(set(aufrufe), {"-I"}, "Code nur über python3 -I starten")
        self.assertNotRegex(wrapper, r"(?m)^\s*\"\$CODE\"", "Code nicht direkt über die Shebang-Zeile starten")

    def liste(self, text):
        path = os.path.join(self.tmp, "ausnahmen.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o644)
        return scanner.ausnahmen_laden(path)

    def test_ausnahmen_vorlage(self):
        vorlage = lesen(AUSNAHMEN)
        self.assertEqual(self.liste(vorlage), [], "die Vorlage darf nichts ausblenden")
        beispiele = re.findall(r"^# ((?:CVE|CONF)-\S+ .*)$", vorlage, re.M)
        self.assertGreaterEqual(len(beispiele), 2)
        aktiviert = re.sub(r"^# ((?:CVE|CONF)-\S+ )", r"\1", vorlage, flags=re.M)
        eintraege = self.liste(aktiviert)
        self.assertEqual(len(eintraege), len(beispiele), "jedes Beispiel muss gültig sein")
        self.assertTrue(any(e["id"].startswith("CONF-") for e in eintraege))
        for e in eintraege:     # die CONF-Kennung gibt es im Skript wirklich
            if e["id"].startswith("CONF-"):
                self.assertIn('"%s"' % e["id"], lesen(SKRIPT))


class BeispieleTest(unittest.TestCase):
    """Die Beispiele sind mit der aktuellen Version erzeugt (README: Releases); Links darauf gelten."""

    def test_berichte_mit_aktueller_version(self):
        berichte = [n for n in os.listdir(BEISPIELE) if n.endswith(".md")]
        self.assertTrue(berichte)
        for n in berichte:
            self.assertIn("- Scanner: container-security-scan %s  \n" % scanner.VERSION,
                          lesen(os.path.join(BEISPIELE, n)), "%s: Beispiele neu erzeugen (beispiele/erzeugen.sh)" % n)

    def test_sbom_und_ausgabe_mit_aktueller_version(self):
        sboms = [n for n in os.listdir(BEISPIELE) if n.endswith(".cdx.json")]
        self.assertTrue(sboms)
        for n in sboms:
            tools = json.loads(lesen(os.path.join(BEISPIELE, n)))["metadata"]["tools"]["components"]
            self.assertEqual([t.get("version") for t in tools], [scanner.VERSION], n)
        self.assertTrue(lesen(os.path.join(BEISPIELE, "ausgabe.txt")).startswith(
            "container-security-scan %s\n" % scanner.VERSION))
        # Einzelscan wie über den Wrapper mit Containername: aktuelle Version, keine Zeilen für den Host
        einzeln = lesen(os.path.join(BEISPIELE, "ausgabe-einzeln.txt"))
        self.assertIn("\ncontainer-security-scan %s\n" % scanner.VERSION, einzeln)
        self.assertNotRegex(einzeln, r"(?m)^Host:")
        self.assertRegex(einzeln, r"(?m)^app-proxy: .* – Bericht: /var/log/container-security-scan/berichte/scan_app-proxy\.md$")

    def test_links_im_readme(self):
        for md in ("README.md", os.path.join("tests", "README.md")):
            basis = os.path.dirname(os.path.join(ROOT, md))
            for ziel in re.findall(r"\]\(((?:\.\./)?(?:beispiele|installation)/[^)#\s]*)\)", lesen(os.path.join(ROOT, md))):
                self.assertTrue(os.path.exists(os.path.join(basis, ziel)), "%s: Link %s" % (md, ziel))


if __name__ == "__main__":
    unittest.main()
