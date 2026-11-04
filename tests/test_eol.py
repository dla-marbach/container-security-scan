"""Supportende (EOL) aus endoflife.date: Erzeugen der Daten und Warnungen."""
import datetime
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from _laden import scanner


class Eol(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "eol.json")
        self.data = {
            "geprueft": "2026-11-04T00:00:00Z",
            "products": [{"name": "vue", "purls": ["pkg:npm/vue"], "cycles": [
                {"cycle": "2", "eol": True}, {"cycle": "2.7", "eol": "2023-12-31"},
                {"cycle": "3.5", "eol": False}, {"cycle": "3.4", "eol": "2024-09-03"}]},
                {"name": "laravel", "purls": ["pkg:composer/laravel/framework"],
                 "cycles": [{"cycle": "8", "eol": "2023-01-24"}, {"cycle": "12", "eol": "2027-02-24"}]}]}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        self.clock = mock.patch.object(scanner, "utcnow", return_value=datetime.datetime(2026, 11, 4))
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def test_expired_current_and_unknown_cycles(self):
        components = [scanner.comp("npm", "vue", "2.7.16", ort="/a"),
                      scanner.comp("js-lib", "vue", "3.5.2", ort="/b"),
                      scanner.comp("npm", "vue", "3.99.0", ort="/c"),
                      scanner.comp("composer", "laravel/framework", "8.83.0", ort="/d"),
                      scanner.comp("composer", "laravel/framework", "12.1.0", ort="/e")]
        warnings = scanner.eol_warnungen(components, self.path)
        self.assertEqual(len(warnings), 2)
        self.assertIn("2023-12-31", warnings[0])
        self.assertIn("2023-01-24", warnings[1])

    def test_missing_and_stale_data_are_warnings(self):
        self.assertIn("fehlen", scanner.eol_warnungen([], self.path + "-missing")[0])
        self.data["geprueft"] = "2026-09-01T00:00:00Z"
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        self.assertIn("veraltet", scanner.eol_warnungen([], self.path)[0])

    def write(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)

    def test_end_date_is_still_supported_on_that_day(self):
        self.data["products"][0]["cycles"][1]["eol"] = "2026-11-04"
        self.write()
        warnings = scanner.eol_warnungen([scanner.comp("npm", "vue", "2.7.16")], self.path)
        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("Supportende bald:"))

    def test_upcoming_end_only_within_notice_period(self):
        self.data["products"][1]["cycles"].append({"cycle": "11", "eol": "2026-12-31"})
        self.write()
        warnings = scanner.eol_warnungen([scanner.comp("composer", "laravel/framework", "11.2.0", ort="/x"),
                                          scanner.comp("composer", "laravel/framework", "12.1.0", ort="/y")], self.path)
        self.assertEqual(warnings, ["Supportende bald: laravel/framework 11.2.0 (laravel 11, am 2026-12-31; /x)"])

    def test_runtimes_only_outside_os_packages(self):
        self.data["products"].append({"name": "php", "purls": [], "cycles": [
            {"cycle": "8.1", "eol": "2025-12-31"}, {"cycle": "8.4", "eol": "2028-12-31"}]})
        self.write()
        official = scanner.comp("runtime", "php", "8.1.31", ort="/usr/local/bin/php")
        fpm = scanner.comp("runtime", "php-fpm", "8.1.31", ort="/usr/local/sbin/php-fpm")
        debian = scanner.comp("runtime", "php", "8.1.2", ort="/usr/bin/php8.1", hinweise=["aus OS-Paket php8.1-cli"])
        current = scanner.comp("runtime", "php", "8.4.1", ort="/usr/local/bin/php")
        sury = scanner.comp("runtime", "php", "8.1.33", ort="/usr/bin/php8.1",
                            hinweise=["aus OS-Paket php8.1-cli", scanner.FREMDQUELLE + " – über Bitnami geprüft"])
        warnings = scanner.eol_warnungen([official, fpm, debian, current, sury], self.path)
        self.assertEqual(len(warnings), 3)
        self.assertIn("php 8.1.33", warnings[2])
        self.assertIn("php 8.1.31 (php 8.1, seit 2025-12-31; /usr/local/bin/php)", warnings[0])
        self.assertIn("php-fpm 8.1.31", warnings[1])

    def test_same_component_in_many_places_is_one_warning(self):
        comps = [scanner.comp("npm", "vue", "2.7.16", ort="/app%d" % i) for i in range(5)]
        warnings = scanner.eol_warnungen(comps, self.path)
        self.assertEqual(len(warnings), 1)
        self.assertIn("/app0, /app1, /app2 und 2 weitere", warnings[0])

    def test_newest_of_several_files_is_used(self):
        other = os.path.join(self.tmp.name, "alt.json")
        old = dict(self.data, geprueft="2026-01-01T00:00:00Z")
        with open(other, "w", encoding="utf-8") as f:
            json.dump(old, f)
        self.assertEqual(scanner.eol_warnungen([], [other, self.path, self.path + "-fehlt"]), [])
        self.assertIn("veraltet", scanner.eol_warnungen([], [other, self.path + "-fehlt"])[0])

    def test_invalid_cycle_data_is_a_warning(self):
        self.data["products"][0]["cycles"][0]["eol"] = None
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        self.assertIn("ungültig", scanner.eol_warnungen([], self.path)[0])

    def test_update_validates_api_and_preserves_old_file_on_error(self):
        result = {"total": 1, "result": [{"name": "vue", "identifiers": [
            {"type": "purl", "id": "pkg:npm/vue"}], "releases": [
            {"name": "2.7", "eolFrom": "2023-12-31", "isEol": True},
            {"name": "3.5", "eolFrom": None, "isEol": False},
            {"name": "4", "eolFrom": None, "isEol": None}]},
            {"name": "symfony", "identifiers": [], "releases": [{"name": "6.4", "eolFrom": "2027-11-30", "isEol": False}]},
            {"name": "php", "identifiers": [{"type": "purl", "id": "pkg:generic/php"}],
             "releases": [{"name": "8.1", "eolFrom": "2025-12-31", "isEol": True}]},
            {"name": "redis", "identifiers": [], "releases": [{"name": "7.2", "eolFrom": "2026-01-01", "isEol": True}]}]}
        result["total"] = len(result["result"])
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(result).encode())):
            scanner.eol_daten_erzeugen(self.path)
        with open(self.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["products"][0]["cycles"][0]["eol"], "2023-12-31")
        self.assertEqual(len(saved["products"][0]["cycles"]), 2)
        self.assertEqual([p["name"] for p in saved["products"]], ["vue", "symfony", "php"])
        self.assertIn("pkg:composer/symfony/http-kernel", saved["products"][1]["purls"])
        self.assertEqual(saved["products"][2]["purls"], [])
        result["total"] += 1
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(result).encode())):
            with self.assertRaises(scanner.ScanError):
                scanner.eol_daten_erzeugen(self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), saved)

    def test_paketkennungen_maven_pypi_scoped_npm(self):
        self.data["products"] += [
            {"name": "log4j", "purls": ["pkg:maven/org.apache.logging.log4j/log4j-core"],
             "cycles": [{"cycle": "2", "eol": False}, {"cycle": "2.12", "eol": "2021-12-14"}]},
            {"name": "django", "purls": ["pkg:pypi/django"], "cycles": [{"cycle": "4.2", "eol": "2026-04-07"}]},
            {"name": "angular", "purls": ["pkg:npm/%40angular/core"], "cycles": [{"cycle": "15", "eol": "2024-05-18"}]}]
        self.write()
        warnings = scanner.eol_warnungen([
            scanner.comp("maven", "org.apache.logging.log4j:log4j-core", "2.12.4", ort="/a.jar"),
            scanner.comp("maven", "org.apache.logging.log4j:log4j-core", "2.17.1", ort="/b.jar"),
            scanner.comp("pypi", "Django", "4.2.11", ort="/venv"),
            scanner.comp("npm", "@angular/core", "15.2.0", ort="/app"),
            scanner.comp("npm", "vue", "unbekannt", ort="/x")], self.path)
        self.assertEqual([w.split(" (")[0] for w in warnings], [
            "Supportende: org.apache.logging.log4j:log4j-core 2.12.4", "Supportende: Django 4.2.11",
            "Supportende: @angular/core 15.2.0"])

    def test_ohne_datum_beendet(self):
        self.data["products"][0]["cycles"].append({"cycle": "1", "eol": True})
        self.write()
        warnings = scanner.eol_warnungen([scanner.comp("js-lib", "vue", "1.0.28", ort="/v.js")], self.path)
        self.assertEqual(warnings, ["Supportende: vue 1.0.28 (vue 1, Datum unbekannt; /v.js)"])


if __name__ == "__main__":
    unittest.main()
