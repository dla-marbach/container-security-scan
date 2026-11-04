import datetime
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("scanner", os.path.join(ROOT, "container-security-scan.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class EolTests(unittest.TestCase):
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

    def test_end_date_is_still_supported_on_that_day(self):
        self.data["products"][0]["cycles"][1]["eol"] = "2026-11-04"
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        self.assertEqual(scanner.eol_warnungen([scanner.comp("npm", "vue", "2.7.16")], self.path), [])

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
            {"name": "4", "eolFrom": None, "isEol": None}]}]}
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(result).encode())):
            scanner.eol_daten_erzeugen(self.path)
        with open(self.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["products"][0]["cycles"][0]["eol"], "2023-12-31")
        self.assertEqual(len(saved["products"][0]["cycles"]), 2)
        result["total"] = 2
        with mock.patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(result).encode())):
            with self.assertRaises(scanner.ScanError):
                scanner.eol_daten_erzeugen(self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), saved)


class ProxyTests(unittest.TestCase):
    def test_custom_nginx_configuration_is_incomplete(self):
        container = mock.Mock()
        container.info = {"HostConfig": {}, "NetworkSettings": {"Ports": {}}}
        container.exec.return_value = (0, "events {} http {}")
        proc = {"base": "nginx", "exe": "/usr/sbin/nginx",
                "argv": ["nginx: master process nginx -c /tmp/nginx.conf -g daemon off;"]}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            web = scanner.collect_web(container, {1: proc})
            self.assertIn("nginx mit -c oder -p", web["problems"][0])
            proc["argv"] = ["nginx: master process nginx -g daemon off;"]
            self.assertEqual(scanner.collect_web(container, {1: proc})["problems"], [])

    def test_public_unresolved_backend_is_flagged(self):
        p = {"base": "nginx", "exe": "/usr/sbin/nginx", "label": "nginx:80",
             "ports": {"80": "0.0.0.0"}, "argv": ["nginx"], "cwd": "/",
             "maps": set(), "files": set()}
        web = {"backends": {p["exe"]: ["http://unknown.example:8080"]}, "upstreams": {},
               "containers": {}, "self": "proxy", "published": {"80": ["0.0.0.0:80"]},
               "host_network": False, "via_proxy": {}, "docroots": {}, "modphp": set(),
               "vhosts": {}, "venvs": set()}
        services = scanner.mark_usage([], {1: p}, {}, web)
        self.assertEqual(services[0]["unresolved"], ["http://unknown.example:8080"])
        web["published"] = {}
        self.assertEqual(scanner.mark_usage([], {1: p}, {}, web)[0]["unresolved"], [])


class UbuntuTests(unittest.TestCase):
    def test_local_ubuntu_data_and_missing_database(self):
        package = scanner.comp("os-paket", "libexample1", "1.0-1", src="example", srcver="1.0-1")
        osinfo = {"id": "ubuntu", "version": "22.04", "pretty": "Ubuntu 22.04"}
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scanner.osv_scan([package], osinfo, [tmp])[2], ["Ubuntu"])
            os.mkdir(os.path.join(tmp, "Ubuntu"))
            records = [
                {"id": "CVE-2026-1000", "published": "2026-10-01T00:00:00Z",
                 "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "example"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [
                                   {"introduced": "0"}, {"fixed": "1.0-2"}]}]}]},
                {"id": "CVE-2026-1001", "published": "2026-10-01T00:00:00Z",
                 "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "example"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}]
            with open(os.path.join(tmp, "Ubuntu", "00.jsonl"), "w", encoding="utf-8") as f:
                for record in records:
                    f.write(json.dumps(record) + "\n")
            findings, _, missing, _ = scanner.osv_scan([package], osinfo, [tmp])
            self.assertEqual(missing, [])
            self.assertEqual([(x["id"], x["fix"]) for x in findings], [("CVE-2026-1000", "1.0-2")])


if __name__ == "__main__":
    unittest.main()
