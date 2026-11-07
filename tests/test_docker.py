"""Integrationstest mit echten Containern (nur mit CSS_DOCKER_TESTS=1 und erreichbarem Docker).

Szenario (Lauf mit --alle-container):
- nginx (eigene Konfiguration per -c) als öffentlicher Reverse Proxy vor Node.js in einem Nachbarcontainer ohne
  veröffentlichten Port, einmal direkt, einmal über eine Variable (set $backend; proxy_pass $backend)
- Traefik (Konfiguration wird nicht ausgewertet) mit einem Ziel aus Docker-Labels und einem Nachbarn ohne Labels:
  im Zweifel erreichbar
- Node.js im Netzwerk-Namespace eines anderen Containers (network_mode: container:), der den Port veröffentlicht
- Node.js in einem eigenen Netz ohne veröffentlichten Port: wird mitgeprüft, gilt als intern
Geprüft werden Rückgabewert, Erreichbarkeit, Berichte, EOL-Warnungen und dass der Scan im Container nichts
verändert (docker diff).
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
TRAEFIK_IMAGE = os.environ.get("CSS_TRAEFIK_IMAGE", "traefik:v3.3")
NODE_SERVER = "require('http').createServer((q, r) => r.end('ok')).listen(%d)"


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
        cls.varnode = cls.id + "-varnode"
        cls.tnet, cls.traefik, cls.label, cls.nachbar = cls.id + "-t", cls.id + "-traefik", cls.id + "-label", cls.id + "-nachbar"
        cls.vpn, cls.mit = cls.id + "-vpn", cls.id + "-mit"
        cls.inet, cls.intern = cls.id + "-i", cls.id + "-intern"
        conf = os.path.join(cls.tmp, "proxy.conf")
        with open(conf, "w") as f:
            f.write("events {}\nhttp { server { listen 8080; resolver 127.0.0.11 valid=10s;\n"
                    "  location / { proxy_pass http://%s:3000; }\n"
                    "  location /v/ { set $backend http://%s:3001; proxy_pass $backend; } } }\n" % (cls.node, cls.varnode))
        os.chmod(cls.tmp, 0o755)
        os.chmod(conf, 0o644)
        for net in (cls.net, cls.tnet, cls.inet):
            docker("network", "create", net)
        docker("run", "-d", "--name", cls.node, "--network", cls.net, NODE_IMAGE, "node", "-e", NODE_SERVER % 3000)
        docker("run", "-d", "--name", cls.varnode, "--network", cls.net, NODE_IMAGE, "node", "-e", NODE_SERVER % 3001)
        docker("run", "-d", "--name", cls.proxy, "--network", cls.net, "-p", "127.0.0.1::8080",
               "-v", conf + ":/etc/nginx/eigen/proxy.conf:ro", NGINX_IMAGE,
               "nginx", "-c", "/etc/nginx/eigen/proxy.conf", "-g", "daemon off;")
        docker("run", "-d", "--name", cls.label, "--network", cls.tnet, "--label", "traefik.enable=true",
               "--label", "traefik.http.services.l.loadbalancer.server.port=3002", NODE_IMAGE, "node", "-e", NODE_SERVER % 3002)
        docker("run", "-d", "--name", cls.nachbar, "--network", cls.tnet, NODE_IMAGE, "node", "-e", NODE_SERVER % 3003)
        docker("run", "-d", "--name", cls.traefik, "--network", cls.tnet, "-p", "127.0.0.1::80", TRAEFIK_IMAGE,
               "--entrypoints.web.address=:80")
        docker("run", "-d", "--name", cls.vpn, "--network", cls.net, "-p", "127.0.0.1::3004", NODE_IMAGE,
               "sleep", "3600")
        docker("run", "-d", "--name", cls.mit, "--network", "container:" + cls.vpn, NODE_IMAGE, "node", "-e",
               NODE_SERVER % 3004)
        docker("run", "-d", "--name", cls.intern, "--network", cls.inet, NODE_IMAGE, "node", "-e", NODE_SERVER % 3005)
        cls.alle = (cls.node, cls.varnode, cls.proxy, cls.label, cls.nachbar, cls.traefik, cls.vpn, cls.mit, cls.intern)
        cls.bereit()
        cls.diff_vorher = {c: cls.diff(c) for c in cls.alle}
        cls.out = os.path.join(cls.tmp, "berichte")
        p = subprocess.run([sys.executable, SKRIPT, "--alle-container", cls.out, "--nur-behebbare"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=2400)
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
            antwort = [docker("exec", cls.proxy, "wget", "-qO-", "http://127.0.0.1:8080" + pfad, timeout=30).strip()
                       for pfad in ("/", "/v/")]
            antwort.append(docker("exec", cls.vpn, "wget", "-qO-", "http://127.0.0.1:3004/", timeout=30).strip())
            diff = [cls.diff(c) for c in cls.alle]
            if antwort == ["ok"] * 3 and diff == letzte:
                return
            letzte = diff
            time.sleep(1)
        raise AssertionError("Testcontainer nicht bereit: " + docker("logs", cls.proxy))

    @classmethod
    def tearDownClass(cls):
        docker("rm", "-f", cls.mit)
        docker("rm", "-f", *cls.alle)
        docker("network", "rm", cls.net, cls.tnet, cls.inet)
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

    def test_backend_ueber_nginx_variable(self):
        self.assertIn("Backend http://%s:3001 -> Container %s" % (self.varnode, self.varnode), self.bericht(self.proxy))
        self.assertIn("Port 3001/tcp (alle) öffentlich über", self.bericht(self.varnode))

    def test_traefik_label_und_nachbar(self):
        self.assertIn("Ziel aus Docker-Labels: Container %s, Port 3002" % self.label, self.bericht(self.traefik))
        self.assertIn("Port 3002/tcp (alle) öffentlich über traefik", self.bericht(self.label))
        self.assertIn("Port 3003/tcp (alle) möglicherweise öffentlich über traefik", self.bericht(self.nachbar))
        self.assertIn("%s: WARNUNG: Weiterleitungen von traefik" % self.traefik, self.ausgabe)

    def test_gemeinsamer_netzwerk_namespace(self):
        self.assertIn("Port 3004/tcp (alle) veröffentlicht als 127.0.0.1:", self.bericht(self.mit))
        self.assertIn("(über Container %s)" % self.vpn, self.bericht(self.mit))
        self.assertIn("Prozess in einem Container mit demselben Netzwerk (%s)" % self.mit, self.bericht(self.vpn))
        self.assertNotIn("unbekannter Dienst", self.bericht(self.vpn))

    def test_interner_container_wird_mitgeprueft(self):
        self.assertIn("Port 3005/tcp (alle) nicht veröffentlicht", self.bericht(self.intern))

    def test_eol_warnungen(self):
        self.assertIn("%s: WARNUNG: Supportende: node 20." % self.node, self.ausgabe)
        self.assertIn("%s: WARNUNG: Supportende: nginx 1.27." % self.proxy, self.ausgabe)

    def test_berichte_vollstaendig(self):
        for c in self.alle:
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
