"""Integrationstest mit echten Containern (nur mit CSS_DOCKER_TESTS=1 und erreichbarem Docker).

Szenario: nginx (eigene Konfiguration per -c) als öffentlicher Reverse Proxy vor Node.js in einem
Nachbarcontainer ohne veröffentlichten Port. Geprüft werden Rückgabewert, Proxy-Erkennung, Berichte,
EOL-Warnungen und dass der Scan im Container nichts verändert (docker diff).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from _laden import SKRIPT

AKTIV = os.environ.get("CSS_DOCKER_TESTS") == "1"
NGINX_IMAGE = os.environ.get("CSS_NGINX_IMAGE", "nginx:1.27-alpine")
NODE_IMAGE = os.environ.get("CSS_NODE_IMAGE", "node:20-alpine")


def docker(*args, **kw):
    return subprocess.run(["docker"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=kw.get("timeout", 300)).stdout.decode("utf-8", "replace")


@unittest.skipUnless(AKTIV, "Docker-Integrationstest: CSS_DOCKER_TESTS=1 setzen")
class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.id = "csstest-" + uuid.uuid4().hex[:8]
        cls.net, cls.node, cls.proxy = cls.id, cls.id + "-node", cls.id + "-proxy"
        conf = os.path.join(cls.tmp, "proxy.conf")
        with open(conf, "w") as f:
            f.write("events {}\nhttp { server { listen 8080; location / { proxy_pass http://%s:3000; } } }\n" % cls.node)
        os.chmod(cls.tmp, 0o755)
        os.chmod(conf, 0o644)
        docker("network", "create", cls.net)
        docker("run", "-d", "--name", cls.node, "--network", cls.net, NODE_IMAGE, "node", "-e",
               "require('http').createServer((q, r) => r.end('ok')).listen(3000)")
        docker("run", "-d", "--name", cls.proxy, "--network", cls.net, "-p", "127.0.0.1::8080",
               "-v", conf + ":/etc/nginx/eigen/proxy.conf:ro", NGINX_IMAGE,
               "nginx", "-c", "/etc/nginx/eigen/proxy.conf", "-g", "daemon off;")
        cls.bereit()
        cls.diff_vorher = {c: cls.diff(c) for c in (cls.node, cls.proxy)}
        cls.out = os.path.join(cls.tmp, "berichte")
        p = subprocess.run([sys.executable, SKRIPT, "--oeffentliche", cls.out, "--nur-behebbare"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200)
        cls.rc, cls.ausgabe = p.returncode, p.stdout.decode("utf-8", "replace")

    @staticmethod
    def diff(container):
        """docker diff, sortiert (die Reihenfolge der Ausgabe ist nicht festgelegt)."""
        return sorted(docker("diff", container).splitlines())

    @classmethod
    def bereit(cls):
        """Warten, bis der Proxy das Backend erreicht und sich die Container-Dateisysteme nicht mehr ändern."""
        letzte = None
        for _ in range(60):
            antwort = docker("exec", cls.proxy, "wget", "-qO-", "http://127.0.0.1:8080/", timeout=30)
            diff = [cls.diff(c) for c in (cls.node, cls.proxy)]
            if antwort.strip() == "ok" and diff == letzte:
                return
            letzte = diff
            time.sleep(1)
        raise AssertionError("Testcontainer nicht bereit: " + docker("logs", cls.proxy))

    @classmethod
    def tearDownClass(cls):
        docker("rm", "-f", cls.node, cls.proxy)
        docker("network", "rm", cls.net)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def bericht(self, container):
        namen = [n for n in os.listdir(self.out) if n.startswith("scan_%s_" % container) and n.endswith(".md")]
        self.assertEqual(len(namen), 1, self.ausgabe)
        with open(os.path.join(self.out, namen[0]), encoding="utf-8") as f:
            return f.read()

    def test_rueckgabewert_vollstaendig(self):
        self.assertIn(self.rc, (0, 1), self.ausgabe)

    def test_backend_hinter_proxy_ist_oeffentlich(self):
        self.assertIn("-> Container %s" % self.node, self.bericht(self.proxy))
        self.assertIn("öffentlich über", self.bericht(self.node))

    def test_eol_warnungen(self):
        self.assertIn("%s: WARNUNG: Supportende: node 20." % self.node, self.ausgabe)
        self.assertIn("%s: WARNUNG: Supportende: nginx 1.27." % self.proxy, self.ausgabe)

    def test_berichte_vollstaendig(self):
        for c in (self.node, self.proxy):
            namen = sorted(os.path.splitext(n)[1] for n in os.listdir(self.out) if n.startswith("scan_%s_" % c))
            self.assertEqual(namen, [".json", ".md", ".sha256"])

    def test_container_unveraendert(self):
        for c, vorher in self.diff_vorher.items():
            self.assertEqual(self.diff(c), vorher, c)

    def test_gestoppter_container_ergibt_2(self):
        name = self.id + "-stop"
        docker("create", "--name", name, NODE_IMAGE)
        try:
            rc = subprocess.run([sys.executable, SKRIPT, name, self.tmp], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=120).returncode
        finally:
            docker("rm", "-f", name)
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
