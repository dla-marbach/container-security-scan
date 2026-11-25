"""Integrationstest mit echten Containern (nur mit CSS_DOCKER_TESTS=1 und erreichbarem Docker).

Szenario (Lauf mit --alle-container):
- nginx (eigene Konfiguration per -c) als öffentlicher Reverse Proxy vor Node.js in einem Nachbarcontainer ohne
  veröffentlichten Port, einmal direkt, einmal über eine Variable (set $backend; proxy_pass $backend), dazu ein
  nicht auswertbares Ziel (proxy_pass http://$host:…): ein weiterer Nachbar gilt im Zweifel als erreichbar (dieselbe
  Rückfallregel wie bei Traefik, HAProxy u.a.)
- Dienst im Netzwerk-Namespace eines anderen Containers (network_mode: container:), der den Port an 127.0.0.1
  veröffentlicht: ohne Proxy auf dem Host davor nicht erreichbar (als root; ohne root sind die Prozesse des Hosts
  nicht vollständig lesbar: im Zweifel erreichbar)
- Dienst in einem eigenen Netz ohne veröffentlichten Port: wird mitgeprüft, gilt als intern
- Gateway in Node.js (veröffentlichter Port, mit nginx auf dem Host an 127.0.0.1): Ziel-URL in der Umgebung
  (API_URL), offene Verbindungen zu einem weiteren Dienst und zu Redis – die Ziele gelten als öffentlich, Redis
  nicht (Datenbank/Cache)
- nur wenn nginx auf dem Host installiert ist: nginx direkt auf dem Host (eigene Konfiguration, ohne root)
  vor einem Dienst über die Container-IP, ohne veröffentlichten Port, und über 127.0.0.1 vor Diensten in zwei
  Containern im Host-Netzwerk (einer nur auf Loopback) und vor dem Gateway (Port auf 127.0.0.1 veröffentlicht,
  erreichbar über diesen Proxy): jeder Port nur beim Container, der dort lauscht
- gehärteter Node.js-Container (read_only, cap_drop: ALL, no-new-privileges, Benutzer node) mit npm-Paketen in
  Verzeichnissen, die nur node lesen darf (im Image und in einem Bind-Mount): root im Container darf dort nicht
  hinein, der Scanner liest dann passiv von außen (docker export, docker cp) und ist trotzdem vollständig
Geprüft werden Rückgabewert, Erreichbarkeit, Webadressen, Berichte, EOL-Warnungen und dass der Scan im Container nichts
verändert (docker diff) und keine Prozesse zurücklässt (Zombies).
Dienste, bei denen es nur um die Erreichbarkeit geht, laufen in einem kleinen Alpine-Image mit dem httpd aus
busybox-extras statt in Node.js: dessen Inventar (Programm, npm) kostet je Container einige Sekunden.
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import uuid

from _laden import SKRIPT

AKTIV = os.environ.get("CSS_DOCKER_TESTS") == "1"
NGINX_IMAGE = os.environ.get("CSS_NGINX_IMAGE", "nginx:1.27-alpine")
NODE_IMAGE = os.environ.get("CSS_NODE_IMAGE", "node:20-alpine")
ALPINE_IMAGE = os.environ.get("CSS_ALPINE_IMAGE", "alpine:3.22")
REDIS_IMAGE = os.environ.get("CSS_REDIS_IMAGE", "redis:7-alpine")
# Gateway: HTTP-Server, dazu dauerhafte Verbindungen zu Zielen (bei Abbruch neu)
GATEWAY = ("require('http').createServer((q, r) => r.end('ok')).listen(3007);"
           "const verbinde = (port, host) => { const s = require('net').connect(port, host);"
           " s.on('error', () => {}); s.on('close', () => setTimeout(() => verbinde(port, host), 500)); };"
           "verbinde(3009, '%s'); verbinde(6379, '%s');")
NODE_SERVER = "require('http').createServer((q, r) => r.end('ok')).listen(%d)"
# kleiner HTTP-Dienst: antwortet unter /, /lo/ und /hn/ (Pfade des nginx auf dem Host) mit "ok"
KLEIN_DOCKERFILE = ("FROM %s\nRUN apk add --no-cache busybox-extras && mkdir -p /w/lo /w/hn "
                    "&& for d in /w /w/lo /w/hn; do printf ok > $d/index.html; done\n" % ALPINE_IMAGE)


def klein_server(port, adresse=""):
    return ["busybox-extras", "httpd", "-f", "-h", "/w", "-p", "%s%d" % (adresse + ":" if adresse else "", port)]
LOOPBACK_PORT = 18100       # Node im Host-Netzwerk, nur auf 127.0.0.1 (Port des Hosts, daher nicht < 10000)
HOSTNETZ_PORT = 18101       # zweiter Node im Host-Netzwerk, auf allen Adressen
HOST_NGINX = shutil.which("nginx") or next((p for p in ("/usr/sbin/nginx", "/usr/local/sbin/nginx") if os.path.exists(p)), None)


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
        cls.nachbar, cls.klein = cls.id + "-nachbar", cls.id + "-klein"
        cls.vpn, cls.mit = cls.id + "-vpn", cls.id + "-mit"
        cls.inet, cls.intern = cls.id + "-i", cls.id + "-intern"
        cls.hnet, cls.hinterhost = cls.id + "-h", cls.id + "-hinterhost"
        cls.hostlo, cls.hostnetz = cls.id + "-hostlo", cls.id + "-hostnetz"
        cls.gnet, cls.gw, cls.api, cls.ziel, cls.redis = (cls.id + x for x in ("-g", "-gw", "-api", "-ziel", "-redis"))
        cls.hart = cls.id + "-hart"
        conf = os.path.join(cls.tmp, "proxy.conf")
        with open(conf, "w") as f:
            f.write("events {}\nhttp { server { listen 8080; server_name shop.test; resolver 127.0.0.11 valid=10s;\n"
                    "  location / { proxy_pass http://%s:3000; }\n"
                    "  location /v/ { set $backend http://%s:3001; proxy_pass $backend; }\n"
                    "  location /h/ { proxy_pass http://$host:3003; } } }\n" % (cls.node, cls.varnode))
        os.chmod(cls.tmp, 0o755)
        os.chmod(conf, 0o644)
        for net in (cls.net, cls.inet, cls.hnet, cls.gnet):
            docker("network", "create", net)
        bau = os.path.join(cls.tmp, "klein")
        os.makedirs(bau)
        with open(os.path.join(bau, "Dockerfile"), "w") as f:
            f.write(KLEIN_DOCKERFILE)
        docker("build", "-q", "-t", cls.klein, bau, timeout=600)
        docker("run", "-d", "--name", cls.node, "--network", cls.net, NODE_IMAGE, "node", "-e", NODE_SERVER % 3000)
        docker("run", "-d", "--name", cls.varnode, "--network", cls.net, NODE_IMAGE, "node", "-e", NODE_SERVER % 3001)
        # Proxy auf allen Adressen veröffentlicht (Port zufällig): an 127.0.0.1 nur mit Proxy auf dem Host erreichbar
        docker("run", "-d", "--name", cls.proxy, "--network", cls.net, "-p", "8080",
               "-v", conf + ":/etc/nginx/eigen/proxy.conf:ro", NGINX_IMAGE,
               "nginx", "-c", "/etc/nginx/eigen/proxy.conf", "-g", "daemon off;")
        docker("run", "-d", "--name", cls.nachbar, "--network", cls.net, cls.klein, *klein_server(3003))
        docker("run", "-d", "--name", cls.vpn, "--network", cls.net, "-p", "127.0.0.1::3004", cls.klein,
               "sleep", "3600")
        docker("run", "-d", "--name", cls.mit, "--network", "container:" + cls.vpn, cls.klein, *klein_server(3004))
        docker("run", "-d", "--name", cls.intern, "--network", cls.inet, cls.klein, *klein_server(3005))
        docker("run", "-d", "--name", cls.hinterhost, "--network", cls.hnet, cls.klein, *klein_server(3006))
        docker("run", "-d", "--name", cls.api, "--network", cls.gnet, cls.klein, *klein_server(3008))
        docker("run", "-d", "--name", cls.ziel, "--network", cls.gnet, NODE_IMAGE, "node", "-e",
               "require('net').createServer(s => s.on('error', () => {})).listen(3009)")
        docker("run", "-d", "--name", cls.redis, "--network", cls.gnet, REDIS_IMAGE)
        # gehärtet: Paket im Image unter /home/node (nur für node lesbar) und im Bind-Mount (0700, Besitzer ist der
        # Aufrufer): root im Container darf ohne Capabilities in keines der beiden Verzeichnisse
        bau = os.path.join(cls.tmp, "hart")
        os.makedirs(bau)
        with open(os.path.join(bau, "Dockerfile"), "w") as f:
            f.write("FROM %s\nRUN mkdir -p /home/node/app/node_modules/lodash && printf '%%s' "
                    "'{\"name\": \"lodash\", \"version\": \"4.17.20\"}' "
                    "> /home/node/app/node_modules/lodash/package.json && chown -R node:node /home/node "
                    "&& chmod 700 /home/node\n" % NODE_IMAGE)
        docker("build", "-q", "-t", cls.hart, bau, timeout=600)
        geheim = os.path.join(cls.tmp, "geheim")
        os.makedirs(os.path.join(geheim, "node_modules", "minimist"))
        with open(os.path.join(geheim, "node_modules", "minimist", "package.json"), "w") as f:
            f.write('{"name": "minimist", "version": "1.2.5"}')
        os.chmod(geheim, 0o700)
        if os.geteuid() == 0:     # sonst gehörte es root und root im Container dürfte hinein
            os.chown(geheim, 1000, 1000)
        docker("run", "-d", "--name", cls.hart, "--network", cls.inet, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--user", "node", "-v", geheim + ":/app/geheim:ro",
               cls.hart, "node", "-e", NODE_SERVER % 3010)
        # Gateway an 127.0.0.1 nur mit nginx auf dem Host davor (sonst als root nicht erreichbar, seine Ziele auch nicht)
        docker("run", "-d", "--name", cls.gw, "--network", cls.gnet, "-p", "127.0.0.1::3007" if HOST_NGINX else "3007",
               "-e", "API_URL=http://%s:3008/v1" % cls.api, NODE_IMAGE, "node", "-e", GATEWAY % (cls.ziel, cls.redis))
        cls.alle = (cls.node, cls.varnode, cls.proxy, cls.nachbar, cls.vpn, cls.mit, cls.intern,
                    cls.hinterhost, cls.api, cls.ziel, cls.redis, cls.gw, cls.hart)
        cls.host_nginx = None
        if HOST_NGINX:      # nginx auf dem Host vor hinterhost, über dessen IP (wie ein Proxy außerhalb von Docker),
            # und über 127.0.0.1 vor hostlo (Host-Netzwerk, nur Loopback), hostnetz (Host-Netzwerk) und gw
            # (veröffentlichter Port)
            docker("run", "-d", "--name", cls.hostlo, "--network", "host", cls.klein,
                   *klein_server(LOOPBACK_PORT, "127.0.0.1"))
            docker("run", "-d", "--name", cls.hostnetz, "--network", "host", cls.klein, *klein_server(HOSTNETZ_PORT))
            cls.alle += (cls.hostlo, cls.hostnetz)
            gw_port = docker("port", cls.gw, "3007/tcp").split(":")[-1].strip()
            ip = docker("inspect", "-f", "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % cls.hnet,
                        cls.hinterhost).strip()
            hconf = os.path.join(cls.tmp, "host-nginx.conf")
            with open(hconf, "w") as f:
                f.write("pid {t}/host-nginx.pid; error_log {t}/host-nginx.log; events {{}}\n"
                        "http {{ access_log off; client_body_temp_path {t}/cb; proxy_temp_path {t}/pt;\n"
                        "  fastcgi_temp_path {t}/ft; uwsgi_temp_path {t}/ut; scgi_temp_path {t}/st;\n"
                        "  server {{ listen 18099; location / {{ proxy_pass http://{ip}:3006; }}\n"
                        "    location /lo/ {{ proxy_pass http://127.0.0.1:{lo}; }}\n"
                        "    location /hn/ {{ proxy_pass http://localhost:{hn}; }}\n"
                        "    location /gw/ {{ proxy_pass http://127.0.0.1:{gw}; }} }} }}\n"
                        .format(t=cls.tmp, ip=ip, lo=LOOPBACK_PORT, hn=HOSTNETZ_PORT, gw=gw_port))
            cls.host_nginx = subprocess.Popen([HOST_NGINX, "-c", hconf, "-e", os.path.join(cls.tmp, "host-nginx.log"),
                                               "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.bereit()
        cls.diff_vorher = {c: cls.diff(c) for c in cls.alle}
        cls.out = os.path.join(cls.tmp, "berichte")
        p = subprocess.run([sys.executable, SKRIPT, "--alle-container", cls.out, "--nur-behebbare", "--bericht", "--sbom"],
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
            # Gateway mit beiden Verbindungen (Zustand 01 in /proc/net/tcp zu Port 3009 = 0BC1 und 6379 = 18EB)
            tcp = docker("exec", cls.gw, "cat", "/proc/net/tcp", timeout=30)
            antwort.append("ok" if all(re.search(r":%s 01 " % p, tcp) for p in ("0BC1", "18EB")) else tcp)
            if cls.host_nginx:
                try:
                    antwort += [urllib.request.urlopen("http://127.0.0.1:18099" + pfad, timeout=5).read().decode()
                                for pfad in ("/", "/lo/", "/hn/", "/gw/")]
                except OSError:
                    antwort.append("")
            diff = [cls.diff(c) for c in cls.alle]
            if antwort == ["ok"] * len(antwort) and diff == letzte:
                return
            letzte = diff
            time.sleep(1)
        raise AssertionError("Testcontainer nicht bereit: " + docker("logs", cls.proxy))

    @classmethod
    def tearDownClass(cls):
        if cls.host_nginx:
            cls.host_nginx.send_signal(signal.SIGTERM)
            cls.host_nginx.wait(30)
        docker("rm", "-f", cls.mit)
        docker("rm", "-f", *cls.alle)
        docker("rmi", "-f", cls.hart, cls.klein)
        docker("network", "rm", cls.net, cls.inet, cls.hnet, cls.gnet)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def bericht(self, container):
        namen = [n for n in os.listdir(self.out) if n.startswith("scan_%s_" % container) and n.endswith(".md")]
        self.assertEqual(len(namen), 1, self.ausgabe)
        with open(os.path.join(self.out, namen[0]), encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def abschnitt(ausgabe, container):
        """Konsolenausgabe eines Containers: Zeilen unter "=== Name ===" bis zur nächsten Leerzeile (bei erneuter
        Prüfung im selben Lauf der letzte Abschnitt)."""
        teile = re.split(r"\n=== %s(?: \(erneute Prüfung wegen .+\))? ===\n" % re.escape(container), ausgabe)
        return teile[-1].split("\n\n")[0].splitlines() if len(teile) > 1 else []

    def ergebnis(self, ausgabe, container):
        """Ergebniszeile eines Containers auf der Konsole (ohne den Hinweis auf den Bericht)."""
        zeile = [l for l in self.abschnitt(ausgabe, container) if " Befunde, davon " in l]
        self.assertEqual(len(zeile), 1, (container, ausgabe))
        return zeile[0].split(" – Bericht:")[0]

    def test_rueckgabewert_vollstaendig(self):
        self.assertIn(self.rc, (0, 1), self.ausgabe)

    def test_backend_hinter_proxy_ist_oeffentlich(self):
        self.assertIn("-> Container %s" % self.node, self.bericht(self.proxy))
        self.assertIn("öffentlich über", self.bericht(self.node))

    def test_backend_ueber_nginx_variable(self):
        self.assertIn("Backend http://%s:3001 -> Container %s" % (self.varnode, self.varnode), self.bericht(self.proxy))
        self.assertIn("Port 3001/tcp (alle) öffentlich über", self.bericht(self.varnode))

    def test_nicht_auswertbares_ziel_und_nachbar(self):
        # proxy_pass http://$host:3003: Ziele nicht vollständig bekannt -> Container in denselben Docker-Netzen
        # gelten als möglicherweise öffentlich; bekannte Ziele bleiben öffentlich über den Proxy
        self.assertIn("Port 3003/tcp (alle) möglicherweise öffentlich über nginx:8080 in %s" % self.proxy,
                      self.bericht(self.nachbar))
        self.assertIn("Port 3000/tcp (alle) öffentlich über nginx:8080 in %s" % self.proxy, self.bericht(self.node))
        self.assertTrue(any(l.startswith("WARNUNG: Weiterleitungen von nginx:8080 nicht vollständig auswertbar "
                                         "(Ziel http://$host:3003)")
                            for l in self.abschnitt(self.ausgabe, self.proxy)), self.ausgabe)

    def test_gemeinsamer_netzwerk_namespace(self):
        self.assertIn("Port 3004/tcp (alle) veröffentlicht als 127.0.0.1:", self.bericht(self.mit))
        # nur an 127.0.0.1, kein Proxy auf dem Host davor: als root nicht erreichbar, sonst im Zweifel erreichbar
        self.assertRegex(self.bericht(self.mit), r"Port 3004/tcp \(alle\) veröffentlicht als 127\.0\.0\.1:\d+ \(über "
                         r"Container %s, nur lokal, %s\)" % (re.escape(self.vpn), "kein Proxy auf dem Host davor erkannt"
                                                            if os.geteuid() == 0 else "im Zweifel erreichbar: Prozesse "
                                                            "auf dem Host nicht vollständig lesbar"))
        self.assertIn("Prozess in einem Container mit demselben Netzwerk (%s)" % self.mit, self.bericht(self.vpn))
        self.assertNotIn("unbekannter Dienst", self.bericht(self.vpn))

    @unittest.skipUnless(HOST_NGINX, "nginx auf dem Host nicht installiert")
    def test_proxy_auf_dem_host(self):
        host = [l for l in self.ausgabe.splitlines() if l.startswith("Host: nginx:18099 auf dem Host – erreichbar")]
        self.assertEqual(len(host), 1, self.ausgabe)
        self.assertIn("Ziele in Containern: %s (3006)" % self.hinterhost, host[0])
        # Ziele über 127.0.0.1: veröffentlichter Port beim Container, der ihn veröffentlicht; im Host-Netzwerk als
        # root (wie im Betrieb) jeder Port nur bei dem Container, der dort lauscht – ohne root sind die Sockets
        # fremder Prozesse nicht lesbar, dann gilt die Rückfallregel (alle Container im Host-Netzwerk)
        self.assertIn("%s (3007)" % self.gw, host[0])
        if os.geteuid() == 0:
            self.assertIn("%s (%d)," % (self.hostlo, LOOPBACK_PORT), host[0] + ",")
            self.assertIn("%s (%d)," % (self.hostnetz, HOSTNETZ_PORT), host[0] + ",")
        else:
            for ct in (self.hostlo, self.hostnetz):
                self.assertIn("%s (%d, %d)" % (ct, LOOPBACK_PORT, HOSTNETZ_PORT), host[0])
        self.assertIn("Port 3007/tcp (alle) veröffentlicht als 127.0.0.1:", self.bericht(self.gw))
        if os.geteuid() == 0:   # an 127.0.0.1 veröffentlicht: erreichbar über nginx auf dem Host
            self.assertRegex(self.bericht(self.gw), r"Port 3007/tcp \(alle\) veröffentlicht als 127\.0\.0\.1:\d+ "
                                                    r"\(nur lokal\), öffentlich über nginx:18099 auf dem Host")
        self.assertIn("Port %d/tcp (alle) direkt im Host-Netzwerk erreichbar" % HOSTNETZ_PORT, self.bericht(self.hostnetz))
        self.assertIn("Port 3006/tcp (alle) öffentlich über nginx:18099 auf dem Host", self.bericht(self.hinterhost))
        # Container im Host-Netzwerk, nur auf Loopback: über proxy_pass http://127.0.0.1:… trotzdem erreichbar
        self.assertIn("Port %d/tcp (localhost) lauscht nur auf Loopback, öffentlich über nginx:18099 auf dem Host "
                      "(über Loopback)" % LOOPBACK_PORT, self.bericht(self.hostlo))

    def test_aufrufe_eines_gateways(self):
        gw = self.bericht(self.gw)
        self.assertIn("Aufruf: Container %s, Port 3008 (Ziel-URL API_URL)" % self.api, gw)
        self.assertIn("Aufruf: Container %s, Port 3009 (offene Verbindung)" % self.ziel, gw)
        self.assertIn("Port 3008/tcp (alle) öffentlich über node:3007 (Ziel-URL API_URL) in %s" % self.gw,
                      self.bericht(self.api))
        self.assertIn("Port 3009/tcp (alle) öffentlich über node:3007 (offene Verbindung) in %s" % self.gw,
                      self.bericht(self.ziel))
        self.assertIn("Datenbank/Cache/Message Broker: dadurch nicht erreichbar", self.bericht(self.redis))
        dienste = [l for l in self.abschnitt(self.ausgabe, self.redis) if l.startswith("Dienst ")]
        self.assertTrue(dienste, self.ausgabe)
        for l in dienste:       # kein Dienst von redis erreichbar
            self.assertIn("nicht veröffentlicht; aufgerufen von", l)

    def test_interner_container_wird_mitgeprueft(self):
        self.assertIn("Port 3005/tcp (alle) nicht veröffentlicht", self.bericht(self.intern))

    def test_gehaertet_ohne_leserechte_passiv_gelesen(self):
        self.assertNotIn("UNVOLLSTÄNDIG", self.ergebnis(self.ausgabe, self.hart))
        self.assertIn("docker export und docker cp (1 Volumes), da find/tar im Container ohne Leserechte",
                      self.bericht(self.hart))
        namen = [n for n in os.listdir(self.out) if n.startswith("scan_%s_" % self.hart) and n.endswith(".json")]
        with open(os.path.join(self.out, namen[0]), encoding="utf-8") as f:
            sbom = f.read()
        self.assertIn("pkg:npm/lodash@4.17.20", sbom)       # im Image, nur für node lesbar
        self.assertIn("pkg:npm/minimist@1.2.5", sbom)       # im Bind-Mount, für root im Container nicht lesbar

    def test_eol_warnungen(self):
        for c, text in ((self.node, "WARNUNG: Supportende: node 20."), (self.proxy, "WARNUNG: Supportende: nginx 1.27.")):
            self.assertTrue(any(l.startswith(text) for l in self.abschnitt(self.ausgabe, c)), (c, self.ausgabe))

    def test_berichte_vollstaendig(self):
        for c in self.alle:
            namen = sorted(os.path.splitext(n)[1] for n in os.listdir(self.out) if n.startswith("scan_%s_" % c))
            self.assertEqual(namen, [".json", ".md", ".sha256"])

    def test_container_unveraendert(self):
        for c, vorher in self.diff_vorher.items():
            self.assertEqual(self.diff(c), vorher, c)

    def test_keine_prozesse_zurueckgelassen(self):
        # Versionsabfragen hinterlassen nichts: keine Wächter von timeout, die an PID 1 fallen und dort Zombies
        # werden (node als PID 1 räumt nicht auf), kein von "httpd -v" gestarteter Webserver
        for c in self.alle:
            zeilen = docker("top", c, "-eo", "pid,stat,args").splitlines()[1:]
            self.assertEqual([z for z in zeilen if (z.split() + ["", ""])[1].startswith("Z")
                              or "timeout" in z or "httpd -v" in z], [], c)

    @staticmethod
    def dienste(text):
        """Tabellen "Laufende Dienste" und "Webadressen" eines Berichts (Erreichbarkeit je Port, Weg dorthin)."""
        return text.split("## Laufende Dienste", 1)[1].split("\n## Übersicht", 1)[0]

    def test_webadressen(self):
        # Website des Proxys (server_name, veröffentlichter Port) mit Pfad beim Ziel, auch über die nginx-Variable
        port = docker("port", self.proxy, "8080/tcp").split(":")[-1].strip()
        self.assertIn("| http://shop.test:%s/ | ja | node:3000 | nginx:8080 in %s → node:3000 |" % (port, self.proxy),
                      self.bericht(self.node))
        self.assertIn("| http://shop.test:%s/v/ | ja | node:3001 | nginx:8080 in %s → node:3001 |" % (port, self.proxy),
                      self.bericht(self.varnode))
        # auf der Konsole: Dienst mit dem Proxy davor, darunter die Webadressen mit dem Weg
        zeilen = self.abschnitt(self.ausgabe, self.node)
        dienst = [i for i, l in enumerate(zeilen) if l.startswith("Dienst node ") and ", Port 3000: " in l]
        self.assertEqual(len(dienst), 1, self.ausgabe)
        self.assertIn("Port 3000: öffentlich über nginx:8080 in %s" % self.proxy, zeilen[dienst[0]])
        # der Weg steht schon in der Dienstzeile
        self.assertTrue(zeilen[dienst[0] + 1].startswith("  Webadressen: http://shop.test:%s/" % port),
                        zeilen[dienst[0] + 1])
        self.assertNotIn(" über nginx:8080", zeilen[dienst[0] + 1])
        if self.host_nginx:      # nginx direkt auf dem Host, ohne server_name
            self.assertIn("| http://*:18099/ | ja | busybox-extras:3006 | nginx:18099 auf dem Host → busybox-extras:3006 |",
                          self.bericht(self.hinterhost))

    def test_auswahl_wie_im_gesamtlauf(self):
        # nur über einen anderen Container erreichbar (nginx, nginx-Variable, nicht auswertbares Ziel, Aufruf eines
        # Gateways): ausgewählt bzw. einzeln geprüft dieselbe Erreichbarkeit wie im Gesamtlauf
        for args, erwartet in ((["--container", self.id + "-*node", "--container", self.nachbar],
                                [self.node, self.varnode, self.nachbar]),
                               ([self.api], [self.api])):
            out = os.path.join(self.tmp, "auswahl-" + erwartet[0])
            p = subprocess.run([sys.executable, SKRIPT] + args + [out, "--nur-behebbare", "--bericht"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=2400)
            ausgabe = p.stdout.decode("utf-8", "replace")
            self.assertIn(p.returncode, (0, 1), ausgabe)
            berichte = sorted(n for n in os.listdir(out) if n.endswith(".md"))
            self.assertEqual(len(berichte), len(erwartet), berichte)
            for c in erwartet:
                name = [n for n in berichte if n.startswith("scan_%s_" % c)]
                self.assertEqual(len(name), 1, (c, berichte))
                with open(os.path.join(out, name[0]), encoding="utf-8") as f:
                    self.assertEqual(self.dienste(f.read()), self.dienste(self.bericht(c)), c)
                self.assertEqual(self.ergebnis(ausgabe, c), self.ergebnis(self.ausgabe, c))
                # Dienste und Webadressen auf der Konsole wie im Gesamtlauf
                self.assertEqual([l for l in self.abschnitt(ausgabe, c) if l.startswith(("Dienst", "  Web"))],
                                 [l for l in self.abschnitt(self.ausgabe, c) if l.startswith(("Dienst", "  Web"))])
            self.assertIn("Gesamt: %d von " % len(erwartet), ausgabe)

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
