"""Schweregrad: CVSS 3 (exakt), CVSS 4 (Näherung) und Vorrang der Quellen."""
import unittest

from _laden import scanner


class Cvss(unittest.TestCase):
    def test_cvss3_stufen(self):
        for vektor, stufe in (
                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL"),   # 9.8
                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH"),       # 7.5
                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "MEDIUM"),     # 6.1, Scope changed
                ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM"),     # 5.3
                ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "LOW"),        # 1.6
                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL")):  # 10.0
            self.assertEqual(scanner.cvss3_severity(vektor), stufe, vektor)

    def test_cvss3_ohne_auswirkung_oder_unvollstaendig(self):
        self.assertIsNone(scanner.cvss3_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))
        self.assertIsNone(scanner.cvss3_severity("CVSS:3.1/AV:N/AC:L"))

    def test_cvss4_naeherung(self):
        self.assertEqual(scanner.cvss4_severity(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), "CRITICAL")
        self.assertEqual(scanner.cvss4_severity(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"), "LOW")
        self.assertIsNone(scanner.cvss4_severity("CVSS:4.0/AV:N"))


class Quellen(unittest.TestCase):
    def sev(self, rec, aff=None):
        rec.setdefault("id", "GHSA-test")
        return scanner.osv_severity(rec, aff or {})

    def test_schadsoftware_ist_kritisch(self):
        self.assertEqual(self.sev({"id": "MAL-2026-1"}), "CRITICAL")

    def test_angabe_der_quelle_hat_vorrang(self):
        cvss = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        self.assertEqual(self.sev({"database_specific": {"severity": "MODERATE"}, "severity": cvss}), "MEDIUM")
        self.assertEqual(self.sev({}, {"database_specific": {"severity": "low"}}), "LOW")

    def test_debian_dringlichkeit(self):
        cvss = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        self.assertEqual(self.sev({"severity": cvss}, {"ecosystem_specific": {"urgency": "low*"}}), "LOW")
        self.assertEqual(self.sev({}, {"ecosystem_specific": {"urgency": "unimportant"}}), "LOW")
        self.assertEqual(self.sev({}, {"ecosystem_specific": {"urgency": "not yet assigned"}}), "UNKNOWN")

    def test_ubuntu_prioritaet(self):
        self.assertEqual(self.sev({"severity": [{"type": "Ubuntu", "score": "negligible"}]}), "LOW")
        self.assertEqual(self.sev({"severity": [{"type": "Ubuntu", "score": "high"}]}), "HIGH")

    def test_cvss_als_rueckfall(self):
        self.assertEqual(self.sev({}, {"severity": [{"type": "CVSS_V4", "score":
                                                     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}),
                         "CRITICAL")
        self.assertEqual(self.sev({"severity": [{"type": "CVSS_V3", "score": "kaputt"}]}), "UNKNOWN")
        self.assertEqual(self.sev({}), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
