"""Versionsvergleiche je Ökosystem und Auswertung der OSV-Versionsbereiche."""
import unittest

from _laden import scanner


class Vergleich(unittest.TestCase):
    def kleiner(self, cmp, *versionen):
        """Prüft, dass die Versionen streng aufsteigend sortiert sind (paarweise, beide Richtungen)."""
        for a, b in zip(versionen, versionen[1:]):
            self.assertEqual(cmp(a, b), -1, "%s < %s" % (a, b))
            self.assertEqual(cmp(b, a), 1, "%s > %s" % (b, a))

    def gleich(self, cmp, a, b):
        self.assertEqual(cmp(a, b), 0, "%s == %s" % (a, b))


class Dpkg(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_dpkg, "1.0~rc1-1", "1.0-1", "1.0-1+deb12u1", "1.0-2", "1.0a-1", "1.0+dfsg-1",
                     "1.0.1-1", "1.10-1", "1:0.5-1")

    def test_epoche_und_tilde(self):
        self.kleiner(scanner.cmp_dpkg, "2:1.0", "3:0.1")
        self.kleiner(scanner.cmp_dpkg, "1.0~~", "1.0~", "1.0")
        self.gleich(scanner.cmp_dpkg, "0:1.0-1", "1.0-1")

    def test_revision_mit_bindestrich_in_upstream(self):
        self.kleiner(scanner.cmp_dpkg, "1.2-beta-1", "1.2-beta-2")


class Rpm(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_rpm, "1.0~rc1-1", "1.0-1", "1.0^git1-1", "1.0.1-1", "1.10-1")
        self.kleiner(scanner.cmp_rpm, "1.0-1.el9", "1.0-2.el9")
        self.kleiner(scanner.cmp_rpm, "1.0a", "1.0.1")

    def test_epoche_nur_wenn_beide_eine_haben(self):
        self.kleiner(scanner.cmp_rpm, "1:1.0-1", "2:0.5-1")
        self.kleiner(scanner.cmp_rpm, "0.5-1", "1:1.0-1")  # ohne Epoche: nur Version vergleichen

    def test_release_fehlt_auf_einer_seite(self):
        self.gleich(scanner.cmp_rpm, "1.0", "1.0-3")


class Apk(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_apk, "1.2.3_alpha1", "1.2.3_beta2", "1.2.3_rc1", "1.2.3", "1.2.3-r1",
                     "1.2.3_p1", "1.2.3a", "1.2.4", "1.10.0")

    def test_unbekanntes_format(self):
        self.kleiner(scanner.cmp_apk, "abc", "abd")


class Semver(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_semver, "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11",
                     "1.0.0-rc.1", "1.0.0", "1.0.1", "1.9.0", "1.10.0", "2.0.0")

    def test_kurzformen_und_praefix(self):
        self.gleich(scanner.cmp_semver, "v2.0.0", "2.0.0")
        self.gleich(scanner.cmp_semver, "2", "2.0.0")
        self.gleich(scanner.cmp_semver, "1.2.3+build5", "1.2.3")


class Pep440(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_pep440, "1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1",
                     "1.10", "1!0.1")

    def test_normalisierung(self):
        self.gleich(scanner.cmp_pep440, "1.0", "1.0.0")
        self.gleich(scanner.cmp_pep440, "1.0-alpha-1", "1.0a1")
        self.gleich(scanner.cmp_pep440, "1.0+local.7", "1.0")


class Maven(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_maven, "1.0-alpha-1", "1.0-beta", "1.0-M1", "1.0-RC1", "1.0-SNAPSHOT", "1.0",
                     "1.0-sp1", "1.0.1", "1.10")

    def test_gleichwertige_schreibweisen(self):
        self.gleich(scanner.cmp_maven, "1.0.0", "1")
        self.gleich(scanner.cmp_maven, "1.0-final", "1.0")
        self.gleich(scanner.cmp_maven, "2.0.GA", "2.0")


class Php(Vergleich):
    def test_reihenfolge(self):
        self.kleiner(scanner.cmp_php, "1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0",
                     "1.0.0-pl1", "1.0.1", "1.10.0")

    def test_praefix(self):
        self.gleich(scanner.cmp_php, "v2.1.0", "2.1.0")


class Betroffen(unittest.TestCase):
    def aff(self, *ranges, **kw):
        a = {"ranges": [{"type": t, "events": e} for t, e in ranges]}
        a.update(kw)
        return a

    def test_einfacher_bereich(self):
        a = self.aff(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "1.2"}]))
        self.assertEqual(scanner.affected_by("1.1", a, scanner.cmp_semver), (True, "1.2"))
        self.assertEqual(scanner.affected_by("1.2", a, scanner.cmp_semver), (False, ""))
        self.assertEqual(scanner.affected_by("2.0", a, scanner.cmp_semver), (False, ""))

    def test_mehrere_zweige_kleinster_passender_fix(self):
        a = self.aff(("ECOSYSTEM", [{"introduced": "1.0"}, {"fixed": "1.5"},
                                    {"introduced": "2.0"}, {"fixed": "2.3"}]))
        self.assertEqual(scanner.affected_by("0.9", a, scanner.cmp_semver)[0], False)
        self.assertEqual(scanner.affected_by("1.4", a, scanner.cmp_semver), (True, "1.5"))
        self.assertEqual(scanner.affected_by("1.6", a, scanner.cmp_semver)[0], False)
        self.assertEqual(scanner.affected_by("2.1", a, scanner.cmp_semver), (True, "2.3"))

    def test_last_affected_und_unsortierte_ereignisse(self):
        a = self.aff(("ECOSYSTEM", [{"last_affected": "3.1"}, {"introduced": "3.0"}]))
        self.assertTrue(scanner.affected_by("3.1", a, scanner.cmp_semver)[0])
        self.assertFalse(scanner.affected_by("3.2", a, scanner.cmp_semver)[0])

    def test_explizite_versionsliste_und_git_bereiche(self):
        a = self.aff(("GIT", [{"introduced": "abc"}]), versions=["1.0.3"])
        self.assertEqual(scanner.affected_by("1.0.3", a, scanner.cmp_semver), (True, ""))
        self.assertFalse(scanner.affected_by("1.0.4", a, scanner.cmp_semver)[0])

    def test_limit_als_obere_grenze_ohne_fix(self):
        a = self.aff(("ECOSYSTEM", [{"introduced": "1.0.0"}, {"limit": "2.0.0"}]))
        self.assertEqual(scanner.affected_by("1.5.0", a, scanner.cmp_semver), (True, ""))
        self.assertFalse(scanner.affected_by("2.0.0", a, scanner.cmp_semver)[0])
        self.assertFalse(scanner.affected_by("2.1.0", a, scanner.cmp_semver)[0])
        # mehrere Grenzen: unter einer davon genügt; "*" = unbegrenzt; Fix-Angabe unabhängig von der Grenze
        a = self.aff(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "1.2"}, {"limit": "1.5"}, {"limit": "*"}]))
        self.assertEqual(scanner.affected_by("1.1", a, scanner.cmp_semver), (True, "1.2"))
        self.assertFalse(scanner.affected_by("3.0", a, scanner.cmp_semver)[0])
        a = self.aff(("SEMVER", [{"introduced": "0"}, {"limit": "1.0.0"}]), versions=["1.2.0"])
        self.assertFalse(scanner.affected_by("1.1.0", a, scanner.cmp_semver)[0])
        self.assertTrue(scanner.affected_by("1.2.0", a, scanner.cmp_semver)[0])   # explizit genannt

    def test_dpkg_bereich_mit_debian_revision(self):
        a = self.aff(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]))
        self.assertEqual(scanner.affected_by("3.0.11-1~deb12u1", a, scanner.cmp_dpkg), (True, "3.0.11-1~deb12u2"))
        self.assertFalse(scanner.affected_by("3.0.11-1", a, scanner.cmp_dpkg)[0])


if __name__ == "__main__":
    unittest.main()
