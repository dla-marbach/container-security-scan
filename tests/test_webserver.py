"""Webserver-Konfiguration (nginx, Apache), veröffentlichte Ports, Backends in anderen Containern."""
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from _laden import scanner, proc, web

NGINX_T = """
# configuration file /etc/nginx/nginx.conf:
events {}
http {
    upstream api { server app-api:8000; server 10.0.0.5:8000; }
    server {
        listen 80; listen [::]:80;
        server_name example.org www.example.org;   # Kommentar mit ; und {
        root /var/www/public;
        location / { try_files $uri /index.php; }
        location ~ \\.php$ {
            fastcgi_pass php:9000;
            fastcgi_param SCRIPT_FILENAME /srv/app/public$fastcgi_script_name;
        }
        location /api/ { proxy_pass http://api; }
    }
    server { listen 8080; server_name _; location / { proxy_pass http://127.0.0.1:3000; } }
}
"""


def dateien(tmp, inhalt):
    """Dateien {relativer Pfad: Text} unter tmp anlegen."""
    for pfad, text in inhalt.items():
        os.makedirs(os.path.dirname(os.path.join(tmp, pfad)), exist_ok=True)
        with open(os.path.join(tmp, pfad), "w") as f:
            f.write(text)


def sh_echt(antworten=None):
    """exec eines Containers bzw. des Hosts: sh -s (KONFIG_DATEIEN_SH) wirklich ausführen, sonst antworten
    nach dem letzten Argument. Die Aufrufe stehen in .aufrufe."""
    def exec_(cmd, input=None, **kw):
        exec_.aufrufe.append((cmd, kw.get("user")))
        if cmd[0] == "sh":
            p = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, universal_newlines=True)
            return p.returncode, p.stdout
        return (antworten or {}).get(cmd[-1], (1, ""))
    exec_.aufrufe = []
    return exec_


class Nginx(unittest.TestCase):
    def test_parse(self):
        w = web(docroots=scanner.defaultdict(list), backends=scanner.defaultdict(list),
                vhosts=scanner.defaultdict(list), upstreams=scanner.defaultdict(list))
        scanner.parse_nginx(NGINX_T, w, "/usr/sbin/nginx")
        self.assertEqual(w["upstreams"]["api"], ["app-api:8000", "10.0.0.5:8000"])
        self.assertEqual(w["docroots"]["/usr/sbin/nginx"], ["/var/www/public", "/srv/app/public"])
        self.assertEqual(w["backends"]["/usr/sbin/nginx"], ["php:9000", "http://api", "http://127.0.0.1:3000"])
        self.assertEqual(w["vhosts"]["/usr/sbin/nginx"], [
            "listen 80,[::]:80 server_name example.org www.example.org root /var/www/public", "listen 8080"])

    def container(self, exec_rc=0, conf="events {} http {}"):
        c = mock.Mock()
        c.info = {"HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Ports": {
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}, {"HostIp": "::", "HostPort": "8080"}],
            "443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}], "53/udp": [{"HostPort": "53"}], "9000/tcp": None}}}
        c.exec.return_value = (exec_rc, conf)
        return c

    def test_eigene_konfiguration_wird_an_nginx_t_uebergeben(self):
        c = self.container()
        master = proc(1, "/usr/sbin/nginx", ["nginx: master process nginx -p /srv/ -c conf/nginx.conf -g daemon off;"])
        worker = proc(2, "/usr/sbin/nginx", ["nginx: worker process"], user="101:101", ppid=1)
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": master, "2": worker})
            self.assertEqual(w["problems"], [])
            self.assertEqual(c.exec.call_count, 1)        # Worker: keine eigene Abfrage
            self.assertEqual(c.exec.call_args[0][0], ["/usr/sbin/nginx", "-p", "/srv/", "-c", "conf/nginx.conf", "-T"])
            self.assertEqual(c.exec.call_args[1]["user"], "0:0")
            master["argv"] = ["nginx", "-g", "daemon off;"]
            scanner.collect_web(c, {"1": master})
            self.assertEqual(c.exec.call_args[0][0], ["/usr/sbin/nginx", "-T"])

    def test_nginx_t_mit_benutzer_des_masters(self):
        # nginx ohne root (z.B. Bitnami, nginx-unprivileged): Konfiguration und Module darf dieser Benutzer
        # ändern -> nginx -T nie als root, sonst würde load_module als root ausgeführt
        c = self.container()
        procs = {"1": proc(1, "/opt/bitnami/nginx/sbin/nginx", ["nginx: master process nginx -c /opt/bitnami/nginx/conf/nginx.conf"],
                           user="1001:0"),
                 "2": proc(2, "/opt/bitnami/nginx/sbin/nginx", ["nginx: worker process"], user="1001:0", ppid=1)}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            scanner.collect_web(c, procs)
        self.assertEqual([kw["user"] for _, kw in c.exec.call_args_list], ["1001:0"])

    def test_fremdes_programm_namens_nginx_nie_als_root(self):
        c = self.container()
        procs = {"1": proc(1, "/usr/sbin/nginx", ["nginx: master process nginx -g daemon off;"], user="0:0"),
                 "2": proc(2, "/usr/sbin/nginx", ["nginx: worker process"], user="33:33", ppid=1),
                 # Angreifer als www-data: eigenes Programm "nginx" und echtes nginx mit eigener Konfiguration
                 "7": proc(7, "/tmp/x/nginx", ["/tmp/x/nginx", "-c", "/tmp/x/evil.conf"], user="33:33", ppid=6),
                 "8": proc(8, "/usr/sbin/nginx", ["/usr/sbin/nginx", "-c", "/tmp/x/evil.conf"], user="33:33", ppid=6),
                 "9": proc(9, "/usr/sbin/nginx", ["nginx"], user="", ppid=6)}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            scanner.collect_web(c, procs)
        calls = [(cmd[0], tuple(cmd[1:]), kw["user"]) for (cmd,), kw in c.exec.call_args_list]
        self.assertIn(("/usr/sbin/nginx", ("-T",), "0:0"), calls)
        self.assertIn(("/usr/sbin/nginx", ("-c", "/tmp/x/evil.conf", "-T"), "33:33"), calls)
        self.assertIn(("/tmp/x/nginx", ("-c", "/tmp/x/evil.conf", "-T"), "33:33"), calls)
        self.assertIn(("/usr/sbin/nginx", ("-T",), scanner.NOBODY), calls)     # Benutzer unbekannt
        self.assertFalse([x for x in calls if x[2] == "0:0" and (x[0] != "/usr/sbin/nginx" or "-c" in x[1])])

    def test_nginx_t_fehlgeschlagen_ist_unvollstaendig(self):
        c = self.container(exec_rc=1, conf="nginx: [emerg] open() failed")
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": proc(1, "/usr/sbin/nginx")})
        self.assertIn("-T fehlgeschlagen", w["problems"][0])

    def test_ohne_nginx_t_dateien_selbst_gelesen(self):
        # nginx vor 1.9.2 kennt -T nicht: Hauptdatei aus -c bzw. nginx -V, dazu alle include-Dateien (glob,
        # relativ zum Verzeichnis der Hauptdatei), mit dem Benutzer des Masters
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        dateien(tmp, {"nginx.conf": "events {}\nhttp {\n  include mime.types;\n  include conf.d/*.conf;  # include x;\n}\n",
                      "mime.types": "types { text/html html; }\n",
                      "conf.d/a.conf": "server { listen 80; location / { proxy_pass http://app:3000; } }\n",
                      "conf.d/b.conf": "include '%s/extra/*.inc';\n" % tmp,
                      "conf.d/c.txt": "server { location / { proxy_pass http://falsch:1; } }\n",
                      "extra/x.inc": "upstream api { server api:8000; }\n"})
        exec_ = sh_echt({"-T": (1, 'nginx: invalid option: "T"'),
                         "-V": (0, "nginx version: nginx/1.8.1\nconfigure arguments: --prefix=/usr/share/nginx "
                                   "--conf-path=%s/nginx.conf --user=nginx\n" % tmp)})
        c = self.container()
        c.exec.side_effect = exec_
        master = proc(1, "/usr/sbin/nginx", ["nginx: master process /usr/sbin/nginx"], user="0:0")
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": master})
        self.assertEqual((w["problems"], w["unlesbar"]), ([], set()))
        self.assertEqual(w["backends"]["/usr/sbin/nginx"], ["http://app:3000"])
        self.assertEqual(w["upstreams"]["api"], ["api:8000"])
        self.assertEqual([s["datei"] for s in w["sites"]], [tmp + "/conf.d/a.conf"])
        self.assertTrue(w["raw"][0].startswith("--- /usr/sbin/nginx Dateien (Auszug)"))
        self.assertEqual({u for _, u in exec_.aufrufe}, {"0:0"})
        # -c relativ zu -p (nginx -V ohne Angaben)
        exec_ = sh_echt({"-T": (1, 'nginx: invalid option: "T"')})
        c.exec.side_effect = exec_
        master["argv"] = ["nginx: master process nginx -p %s/ -c nginx.conf" % tmp]
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": master})
        self.assertEqual((w["problems"], w["backends"]["/usr/sbin/nginx"]), ([], ["http://app:3000"]))
        self.assertEqual(exec_.aufrufe[2][0][3:], [tmp + "/nginx.conf"])

    def test_ohne_nginx_t_unvollstaendig(self):
        # fehlende eingebundene Datei: Gelesenes wird ausgewertet, aber unvollständig (Rückfallregel, Rückgabewert 2);
        # ein Muster mit Platzhalter ohne Treffer ist zulässig
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        dateien(tmp, {"nginx.conf": "http { include leer/*.conf; include fehlt.conf; "
                                    "server { location / { proxy_pass http://app:3000; } } }\n"})
        c = self.container()
        c.exec.side_effect = sh_echt({"-T": (1, 'nginx: invalid option: "T"')})
        master = proc(1, "/usr/sbin/nginx", ["nginx: master process nginx -c %s/nginx.conf" % tmp])
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": master})
        self.assertEqual(w["backends"]["/usr/sbin/nginx"], ["http://app:3000"])
        self.assertEqual(w["unlesbar"], {"/usr/sbin/nginx"})
        self.assertEqual(len(w["problems"]), 1)
        self.assertIn("nicht vollständig lesbar (%s/fehlt.conf)" % tmp, w["problems"][0])
        self.assertNotIn("leer", w["problems"][0])

    def test_konfig_dateien_unvollstaendig(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        dateien(tmp, {"a.conf": "include b.conf;", "b.conf": "include c.conf;", "c.conf": "include a.conf;",
                      "leer.conf": "", "ok.conf": "include conf.d/*;", "conf.d/x": "events {}", "conf.d/sub/y": ""})
        c = mock.Mock()
        c.exec.side_effect = sh_echt()
        # Kreis: jede Datei nur einmal, vollständig; Verzeichnisse unter einem Platzhalter werden übergangen
        text, fehlt = scanner.konfig_dateien(c, [tmp + "/a.conf"], "0:0", scanner.nginx_includes, tmp)
        self.assertEqual((text.count("# configuration file"), fehlt), (3, []))
        self.assertEqual(scanner.konfig_dateien(c, [tmp + "/ok.conf"], "0:0", scanner.nginx_includes, tmp)[1], [])
        # leere Datei: gelesen, nicht fehlend
        self.assertEqual(scanner.konfig_dateien(c, [tmp + "/leer.conf"], "0:0", scanner.nginx_includes, tmp)[1], [])
        # mehr include-Ebenen als Runden
        fehlt = scanner.konfig_dateien(c, [tmp + "/a.conf"], "0:0", scanner.nginx_includes, tmp, runden=2)[1]
        self.assertEqual(fehlt, ["mehr als 2 include-Ebenen"])
        # spätere Abfrage fehlgeschlagen
        echt = sh_echt()
        c.exec.side_effect = lambda cmd, **kw: echt(cmd, **kw) if not echt.aufrufe else (126, "")
        text, fehlt = scanner.konfig_dateien(c, [tmp + "/a.conf"], "0:0", scanner.nginx_includes, tmp)
        self.assertEqual((text.count("# configuration file"), fehlt), (1, ["Abfrage fehlgeschlagen: %s/b.conf" % tmp]))

    def test_veroeffentlichte_ports_und_andere_container(self):
        c = self.container()
        andere = [{"Name": "/app-api", "Config": {"Hostname": "f00", "Labels": {"com.docker.compose.service": "api"}},
                   "NetworkSettings": {"Networks": {"n": {"IPAddress": "10.0.0.5", "Aliases": ["api-alias"],
                                                          "DNSNames": ["app-api"]}}}}]

        def run(cmd, *a, **kw):
            return (0, "abc\n") if cmd[:2] == ["docker", "ps"] else (0, scanner.json.dumps(andere))
        with mock.patch.object(scanner, "run", side_effect=run):
            w = scanner.collect_web(c, {})
        self.assertEqual(w["published"]["80"], ["0.0.0.0:8080", ":::8080"])
        self.assertIn("nur lokal", w["published"]["443"][0])
        self.assertEqual(w["published"]["53/udp"], ["0.0.0.0:53"])
        self.assertNotIn("9000", w["published"])
        for key in ("app-api", "f00", "api", "10.0.0.5", "api-alias"):
            self.assertEqual(w["containers"][key], "app-api")


NGINX_VARIABLEN = """
http {
    map $http_x_tenant $tenant_backend { default http://app-a:3000; beta http://app-b:3000; }
    server {
        listen 80;
        resolver 127.0.0.11 valid=10s;
        set $backend "http://app:3000";
        set $api api;
        location / { proxy_pass $backend; }
        location /x/ { proxy_pass http://$api:8000$request_uri; }
        location /t/ { proxy_pass $tenant_backend; }
        location /h/ { proxy_pass $scheme://$host; }
        location /k/ { proxy_pass http://${api}:9000; }
    }
}
"""


class NginxVariablen(unittest.TestCase):
    def test_set_und_map_werden_aufgeloest(self):
        w = web(docroots=scanner.defaultdict(list), backends=scanner.defaultdict(list),
                vhosts=scanner.defaultdict(list), upstreams=scanner.defaultdict(list))
        scanner.parse_nginx(NGINX_VARIABLEN, w, "/usr/sbin/nginx")
        self.assertEqual(w["backends"]["/usr/sbin/nginx"], [
            "http://app:3000", "http://api:8000", "http://app-a:3000", "http://app-b:3000", "http://$host",
            "http://api:9000"])
        self.assertEqual(len(w["vhosts"]["/usr/sbin/nginx"]), 1)     # ${api} kein Block

    def test_nginx_ziele(self):
        v = {"b": ["http://app:3000"], "zwei": ["x:1", "y:2"]}
        self.assertEqual(scanner.nginx_ziele("http://$b$request_uri", v), ["http://app:3000"])
        self.assertEqual(scanner.nginx_ziele("$scheme://${zwei}/$1", v), ["http://x:1/", "http://y:2/"])
        self.assertEqual(scanner.nginx_ziele("http://$unbekannt", v), ["http://$unbekannt"])


def inspect(name, netze=(), mode="bridge", ports=None, labels=None, cid=None):
    """Container wie von docker inspect geliefert."""
    return {"Id": cid or (name + "0" * 12), "Name": "/" + name, "HostConfig": {"NetworkMode": mode},
            "Config": {"Hostname": name[:3], "Labels": labels or {}},
            "NetworkSettings": {"Ports": ports or {}, "Networks": {n: {"IPAddress": "10.0.%d.%d" % (i, len(name)),
                                                                       "DNSNames": [name]} for i, n in enumerate(netze)}}}


class DockerLage(unittest.TestCase):
    def setUp(self):
        self.proxy = inspect("proxy", ["front", "back"], ports={"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]})
        self.app = inspect("app", ["back"])
        self.vpn = inspect("vpn", ["back"], ports={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]})
        self.mit = inspect("mit", [], mode="container:" + self.vpn["Id"])
        self.lan = inspect("lan", ["mv"])
        self.allein = inspect("allein", ["eigen"])
        self.hostnetz = inspect("hostnetz", [], mode="host")
        self.infos = [self.proxy, self.app, self.vpn, self.mit, self.lan, self.allein, self.hostnetz]
        self.netze = {"front": {"Driver": "bridge"}, "back": {"Driver": "bridge"}, "mv": {"Driver": "macvlan"},
                      "eigen": {"Driver": "bridge", "Options": {"com.docker.network.bridge.gateway_mode_ipv6": "routed"}}}

    def test_direkt_erreichbar(self):
        published, host, lan, spender = scanner.direkt_erreichbar(self.proxy, self.infos, self.netze)
        self.assertEqual((dict(published), host, lan, spender), ({"443": ["0.0.0.0:443"]}, False, [], None))
        self.assertEqual(scanner.direkt_erreichbar(self.app, self.infos, self.netze)[:3], ({}, False, []))
        # gemeinsamer Netzwerk-Namespace: Ports des Spenders gelten
        published, _, _, spender = scanner.direkt_erreichbar(self.mit, self.infos, self.netze)
        self.assertEqual((list(published), spender), (["8080"], "vpn"))
        self.assertEqual(scanner.direkt_erreichbar(self.lan, self.infos, self.netze)[2], ["macvlan-Netz mv"])
        self.assertEqual(scanner.direkt_erreichbar(self.allein, self.infos, self.netze)[2], ["Netz eigen (IPv6 routed)"])
        self.assertTrue(scanner.direkt_erreichbar(self.hostnetz, self.infos, self.netze)[1])

    def test_nachbarn_und_netz_gruppe(self):
        self.assertEqual(scanner.nachbarn_von(self.proxy, self.infos), ["app", "mit", "vpn"])
        self.assertEqual(scanner.nachbarn_von(self.mit, self.infos), ["app", "proxy", "vpn"])
        self.assertEqual(scanner.nachbarn_von(self.allein, self.infos), [])
        # Host-Netzwerk: der Host erreicht alle Container mit einem Docker-Netz
        self.assertEqual(scanner.nachbarn_von(self.hostnetz, self.infos), ["allein", "app", "lan", "mit", "proxy", "vpn"])
        self.assertEqual(scanner.netz_gruppe(self.vpn, self.infos), ["mit"])
        self.assertEqual(scanner.netz_gruppe(self.mit, self.infos), ["vpn"])
        self.assertEqual(scanner.netz_gruppe(self.app, self.infos), [])
        # dasselbe Loopback: Host-Netzwerk (auch über einen Spender im Host-Netzwerk) bzw. gemeinsamer Namespace
        hostmit = inspect("hostmit", [], mode="container:" + self.hostnetz["Id"])
        infos = self.infos + [hostmit, inspect("host2", [], mode="host")]
        self.assertEqual(scanner.loopback_gruppe(self.hostnetz, infos), ["host2", "hostmit"])
        self.assertEqual(scanner.loopback_gruppe(hostmit, infos), ["host2", "hostnetz"])
        self.assertEqual(scanner.loopback_gruppe(self.vpn, infos), ["mit"])
        self.assertEqual(scanner.loopback_gruppe(self.app, infos), [])
        # Docker speichert die volle ID; ältere Angaben per Name
        self.assertIs(scanner.spender_von(inspect("x", mode="container:vpn"), self.infos), self.vpn)

    def test_label_ziele(self):
        infos = [inspect("a", labels={"traefik.enable": "true",
                                      "traefik.http.services.a.loadbalancer.server.port": "8080",
                                      "traefik.udp.services.d.loadbalancer.server.port": "53"}),
                 inspect("b", labels={"traefik.http.routers.b.rule": "Host(`b`)"}),
                 inspect("c", labels={"traefik.enable": "false", "traefik.http.routers.c.rule": "Host(`c`)"}),
                 inspect("d", labels={"caddy": "d.example.org", "caddy.reverse_proxy": "{{upstreams 3000}}",
                                      "caddy_1.reverse_proxy": "{{upstreams https}}"}),
                 inspect("e")]
        self.assertEqual(scanner.label_ziele("traefik", infos), [("a", "8080"), ("a", "53/udp"), ("b", "*")])
        self.assertEqual(scanner.label_ziele("caddy", infos), [("d", "3000"), ("d", "443")])

    def test_collect_web(self):
        c = mock.Mock(info=self.mit)
        infos = self.infos

        def run(cmd, *a, **kw):
            if cmd[:2] == ["docker", "ps"]:
                return 0, "x\n"
            if cmd[:3] == ["docker", "network", "inspect"]:
                return 0, scanner.json.dumps([dict(v, Name=k) for k, v in self.netze.items()])
            return 0, scanner.json.dumps(infos)
        traefik = proc(1, "/usr/local/bin/traefik", ports={"80": "alle"})
        with mock.patch.object(scanner, "run", side_effect=run):
            w = scanner.collect_web(c, {"1": traefik})
        self.assertEqual((list(w["published"]), w["spender"], w["netz_gruppe"]), (["8080"], "vpn", ["vpn"]))
        self.assertEqual(w["nachbarn"], ["app", "proxy", "vpn"])
        self.assertEqual(w["label_ziele"], {"traefik": []})
        self.assertEqual(w["containers"]["app.back"], "app")     # Docker-DNS: <name>.<netz>

    def test_mehrdeutiger_dienstname(self):
        # Compose-Dienst app in zwei Projekten; der fremde steht bei docker ps zuerst
        def ct(name, projekt, netze, **kw):
            return inspect(name, netze, labels={"com.docker.compose.project": projekt,
                                                "com.docker.compose.service": "app"}, **kw)
        fremd = ct("other-app-1", "other", ["other_default"])
        eigen = ct("dla-app-1", "dla", ["dla_default"])
        nginx = ct("dla-nginx-1", "dla", ["dla_default", "proxy"])
        nginx["Config"]["Labels"]["com.docker.compose.service"] = "nginx"
        infos = [fremd, eigen, nginx]
        self.assertEqual(scanner.container_index(infos)["app"], "other-app-1")      # ohne Bezug wie bisher
        self.assertEqual(scanner.container_index(infos, nginx)["app"], "dla-app-1")
        # gemeinsames Netz vor gleichem Projekt: nur dort löst Dockers DNS den Namen auf
        eigen_ohne_netz = ct("dla-app-1", "dla", ["dla_intern"])
        im_netz = ct("other-app-1", "other", ["proxy"])
        self.assertEqual(scanner.container_index([eigen_ohne_netz, im_netz, nginx], nginx)["app"], "other-app-1")
        # beide im gemeinsamen Netz: das eigene Projekt
        self.assertEqual(scanner.container_index([im_netz, ct("dla-app-1", "dla", ["proxy"]), nginx], nginx)["app"],
                         "dla-app-1")
        # gemeinsamer Netzwerk-Namespace: Netze des Spenders zählen
        mit = inspect("mit", [], mode="container:" + nginx["Id"])
        self.assertEqual(scanner.container_index(infos + [mit], mit)["app"], "dla-app-1")

    def test_docker_nicht_erreichbar(self):
        with mock.patch.object(scanner, "run", return_value=(1, "")):
            self.assertRaises(scanner.ScanError, scanner.docker_lage)

    def test_zwischenzeitlich_entfernter_container(self):
        # docker run --rm zwischen docker ps und docker inspect beendet: docker liefert die übrigen und 1
        def run(cmd, *a, **kw):
            if cmd[:2] == ["docker", "ps"]:
                return 0, "a\nweg\n"
            if cmd[:3] == ["docker", "network", "inspect"]:
                return 0, scanner.json.dumps([dict(self.netze["back"], Name="back")])
            return 1, scanner.json.dumps([self.app])
        with mock.patch.object(scanner, "run", side_effect=run):
            infos, netze = scanner.docker_lage()
        self.assertEqual(([scanner.name_von(d) for d in infos], list(netze)), (["app"], ["back"]))


class Stunnel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        dateien(self.tmp, {
            "stunnel.conf": "; Kommentar\nsetuid = stunnel4\ninclude = %s/conf.d\n\n[pg]\naccept  = 5433\n"
                            "connect = db:5432\n[web]\naccept = 0.0.0.0:443\nconnect = 8080\n" % self.tmp,
            "conf.d/x.conf": "[sock]\naccept = 9000\nconnect = /run/app.sock\n[client]\nclient = yes\n"
                             "accept = 127.0.0.1:6380\nconnect = remote.example.org:6379\n"})

    def lesen(self, argv, user="0:0"):
        c = mock.Mock(info={"HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {}})
        c.exec.side_effect = exec_ = sh_echt()
        procs = {"1": proc(1, "/usr/bin/stunnel4", argv, user=user, ports={"5433": "alle"})}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            return scanner.collect_web(c, procs), exec_.aufrufe

    def test_konfiguration(self):
        # je Dienst accept -> connect (Server- und Client-Modus), include-Verzeichnis, als Benutzer des Prozesses
        w, aufrufe = self.lesen(["/usr/bin/stunnel4", self.tmp + "/stunnel.conf"], user="110:117")
        self.assertEqual((w["problems"], w["unlesbar"]), ([], set()))
        self.assertEqual(w["backends"]["/usr/bin/stunnel4"],
                         ["db:5432", "127.0.0.1:8080", "unix:/run/app.sock", "remote.example.org:6379"])
        self.assertEqual(w["vhosts"]["/usr/bin/stunnel4"][:2],
                         ["[pg] accept 5433 connect db:5432", "[web] accept 0.0.0.0:443 connect 127.0.0.1:8080"])
        self.assertEqual({u for _, u in aufrufe}, {"110:117"})
        self.assertNotIn("stunnel4", scanner.PROXY_UNBEKANNT)

    def test_uebliche_datei_ohne_angabe(self):
        with mock.patch.object(scanner, "STUNNEL_KONF", [self.tmp + "/fehlt.conf", self.tmp + "/stunnel.conf"]):
            w, _ = self.lesen(["stunnel4"])
        self.assertEqual((w["problems"], len(w["backends"]["/usr/bin/stunnel4"])), ([], 4))

    def test_nicht_lesbar_ist_unvollstaendig(self):
        # Konfiguration über einen Dateideskriptor bzw. Datei fehlt: Weiterleitungen nicht auswertbar
        for argv in (["stunnel", "-fd", "0"], ["stunnel", self.tmp + "/fehlt.conf"]):
            w, _ = self.lesen(argv)
            self.assertEqual(w["unlesbar"], {"/usr/bin/stunnel4"}, argv)
            self.assertIn("nicht lesbar", w["problems"][0])

    def test_include_unvollstaendig(self):
        # Abfrage des include-Verzeichnisses fehlgeschlagen: Gelesenes zählt, aber unvollständig
        c = mock.Mock(info={"HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {}})
        echt = sh_echt()
        c.exec.side_effect = lambda cmd, **kw: echt(cmd, **kw) if not echt.aufrufe else (1, "")
        procs = {"1": proc(1, "/usr/bin/stunnel4", ["stunnel4", self.tmp + "/stunnel.conf"])}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, procs)
        self.assertEqual(w["backends"]["/usr/bin/stunnel4"], ["db:5432", "127.0.0.1:8080"])
        self.assertEqual(w["unlesbar"], {"/usr/bin/stunnel4"})
        self.assertIn("nicht vollständig lesbar (Abfrage fehlgeschlagen: %s/conf.d/*)" % self.tmp, w["problems"][0])

    def nur_root(self, *pfade):
        """KONFIG_DATEIEN_NUR_ROOT_SH wirklich ausführen (als aktueller Benutzer)."""
        p = subprocess.run(["sh", "-s", "--"] + list(pfade), input=scanner.KONFIG_DATEIEN_NUR_ROOT_SH,
                           stdout=subprocess.PIPE, universal_newlines=True)
        return p.stdout

    def test_als_root_nur_dateien_die_nur_root_aendern_kann(self):
        # nicht root gehörend bzw. Verzeichnis für andere beschreibbar (/tmp), symbolischer Link, relativer Pfad:
        # wie nicht lesbar
        os.symlink(self.tmp + "/stunnel.conf", self.tmp + "/link.conf")
        for pfad in (self.tmp + "/stunnel.conf", self.tmp + "/link.conf", "stunnel.conf"):
            self.assertEqual(self.nur_root(pfad), "\x1f%s\n" % pfad, pfad)

    @unittest.skipUnless(all(os.path.exists(d) and not os.path.islink(d) and os.stat(d).st_uid == 0
                             and not os.stat(d).st_mode & 0o022 for d in ("/", "/etc", "/etc/passwd")),
                         "kein /etc/passwd mit Pfad nur für root beschreibbar (z.B. macOS: /etc ist ein Link)")
    def test_als_root_datei_mit_pfad_nur_fuer_root(self):
        self.assertTrue(self.nur_root("/etc/passwd").startswith("# configuration file /etc/passwd:\n"))

    def test_als_root_wenn_fuer_den_prozess_nicht_lesbar(self):
        # stunnel (SUSE) startet als root, wechselt per setuid zu stunnel; /etc/stunnel ist nur für root: zuerst als
        # Benutzer des Prozesses, dann als root mit Prüfung des Pfads
        conf = "# configuration file /etc/stunnel/stunnel.conf:\nsetuid = stunnel\n[ldap]\naccept = 389\n" \
               "connect = ldap.example.org:636\n"
        aufrufe = []

        def exec_(cmd, input=None, user=None, **kw):
            aufrufe.append((user, "nur_root" in input))
            return (0, conf) if user == "0:0" and "nur_root" in input else (0, "\x1f%s\n" % cmd[-1])
        procs = {"1": proc(1, "/usr/sbin/stunnel", ["/usr/sbin/stunnel"], user="490:65534", ports={"389": "alle"})}
        w = web(backends=scanner.defaultdict(list), vhosts=scanner.defaultdict(list), problems=[], unlesbar=set(),
                raw=[])
        with mock.patch.object(scanner, "STUNNEL_KONF", ["/etc/stunnel/stunnel.conf"]):
            scanner.stunnel_lesen(mock.Mock(spec=["exec", "info"], exec=exec_), procs, w, "/usr/sbin/stunnel")
        self.assertEqual(aufrufe, [("490:65534", False), ("0:0", True)])
        self.assertEqual((w["problems"], w["unlesbar"]), ([], set()))
        self.assertEqual(w["backends"]["/usr/sbin/stunnel"], ["ldap.example.org:636"])
        self.assertIn("als root gelesen", w["raw"][0])
        # im Container nur, wenn der Scan dort root ist (--user 0)
        for c_user, root in (("0", True), ("1000", False)):
            aufrufe[:] = []
            w = web(backends=scanner.defaultdict(list), vhosts=scanner.defaultdict(list), problems=[],
                    unlesbar=set(), raw=[])
            with mock.patch.object(scanner, "STUNNEL_KONF", ["/etc/stunnel/stunnel.conf"]):
                scanner.stunnel_lesen(mock.Mock(user=c_user, exec=exec_), procs, w, "/usr/sbin/stunnel")
            self.assertEqual(("0:0", True) in aufrufe, root, c_user)
            self.assertEqual(bool(w["problems"]), not root, c_user)
        self.assertIn("als root nur, wenn Datei und Verzeichnisse root gehören", w["problems"][0])

    def test_auf_dem_host(self):
        # stunnel auf dem Host vor der Datenbank eines Containers: genau dieses Ziel, nicht alle Container
        infos = [inspect("app", ["back"]), inspect("db", ["back"])]
        ip = infos[1]["NetworkSettings"]["Networks"]["back"]["IPAddress"]
        dateien(self.tmp, {"host.conf": "[pg]\naccept = 5433\nconnect = %s:5432\n" % ip})
        procs = ("P\t10\t/usr/bin/stunnel4\t/\t/usr/bin/stunnel4\x1f%s/host.conf\t0:0\t1\nS\t10\t5\n"
                 "T\t5\t00000000:1539\ttcp\n" % self.tmp)
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner.Host, "exec", side_effect=sh_echt()):
            ziele, services, warnings, problems, _ = scanner.host_proxys(infos)
        self.assertEqual(ziele, [("db", "5432", "stunnel4:5433 auf dem Host")])
        self.assertEqual((warnings, problems, services[0]["unklar"]), ([], [], []))


class HostProxys(unittest.TestCase):
    def test_host_proxy_pids(self):
        # nur bekannte Proxys mit dem Wurzelverzeichnis des Hosts und nicht in der cgroup eines Containers
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        anderes = os.path.join(tmp, "rootfs")
        os.mkdir(anderes)
        for pid, exe, root, cgroup in (("10", "/usr/sbin/nginx", "/", "0::/system.slice/nginx.service\n"),
                                       ("11", "/usr/sbin/sshd", "/", "0::/system.slice/ssh.service\n"),
                                       ("12", "/usr/sbin/nginx", anderes, "0::/system.slice/docker-x.scope\n"),
                                       ("13", "/usr/sbin/nginx", "/", "0::/system.slice/docker-abc123.scope\n"),
                                       ("14", "/usr/local/bin/cloudflared (deleted)", "/", "0::/x\n")):
            os.mkdir(os.path.join(tmp, pid))
            os.symlink(exe, os.path.join(tmp, pid, "exe"))
            os.symlink(root, os.path.join(tmp, pid, "root"))
            with open(os.path.join(tmp, pid, "cgroup"), "w") as f:
                f.write(cgroup)
        os.mkdir(os.path.join(tmp, "15"))       # Kernel-Thread: kein exe
        self.assertEqual(scanner.host_proxy_pids([{"Id": "abc123"}], proc=tmp), (["10", "14"], 0))

    def test_host_proxys(self):
        infos = [inspect("app", ["back"]), inspect("db", ["back"]), inspect("ohne")]
        infos[2]["NetworkSettings"]["Networks"] = {}
        ip = infos[0]["NetworkSettings"]["Networks"]["back"]["IPAddress"]
        procs = ("P\t10\t/usr/sbin/nginx\t/\tnginx: master process /usr/sbin/nginx\t0:0\t1\nS\t10\t5\n"
                 "T\t5\t00000000:01BB\ttcp\n")
        conf = "http { server { listen 443; location / { proxy_pass http://%s:3000; } } }" % ip
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)) as ex:
            ziele, services, warnings, problems, _ = scanner.host_proxys(infos)
        self.assertEqual(ex.call_args[0][0], ["/usr/sbin/nginx", "-T"])
        self.assertEqual(ex.call_args[1]["user"], "0:0")
        self.assertEqual(ziele, [("app", "3000", "nginx:443 auf dem Host")])
        self.assertEqual((warnings, problems), ([], []))
        # offene Verbindung des Proxys auf dem Host: Kennzeichen bleibt im Grund erhalten
        db_ip = infos[1]["NetworkSettings"]["Networks"]["back"]["IPAddress"]
        hex_ip = "".join("%02X" % int(x) for x in reversed(db_ip.split(".")))
        mit_verbindung = procs + "S\t10\t6\nC\t6\t0100000A:D431\t%s:1F90\n" % hex_ip
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, mit_verbindung)), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele = scanner.host_proxys(infos)[0]
        self.assertEqual(ziele, [("app", "3000", "nginx:443 auf dem Host"),
                                 ("db", "8080", "nginx:443 auf dem Host (offene Verbindung)")])
        # Ziel über Loopback: Container im Host-Netzwerk, die dort lauschen (nicht die übrigen)
        hostnetz = inspect("hostnetz", mode="host")
        conf_lo = "http { server { listen 443; location /gvp/ { proxy_pass http://127.0.0.1:7777; } } }"
        # (lauschender Prozess nicht zuordenbar: alle Container im Host-Netzwerk)
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner, "socket_besitzer", return_value={}), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf_lo)):
            ziele, services, warnings, problems, _ = scanner.host_proxys(infos + [hostnetz])
        self.assertEqual(ziele, [("hostnetz", "7777", "nginx:443 auf dem Host (über Loopback)")])
        self.assertIn("Backend http://127.0.0.1:7777 (Host; Loopback gemeinsam mit hostnetz)", services[0]["description"])
        self.assertEqual((warnings, problems), ([], []))
        # variables Ziel: alle Container mit Docker-Netz möglicherweise erreichbar
        conf = "http { server { listen 443; location / { proxy_pass http://$host; } } }"
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 2)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele, services, warnings, problems, _ = scanner.host_proxys(infos)
        self.assertEqual(ziele, [("app", "*", "nginx:443 auf dem Host"), ("db", "*", "nginx:443 auf dem Host")])
        self.assertIn("nicht vollständig lesbar (2;", warnings[0])
        self.assertIn("Weiterleitungen von nginx:443 auf dem Host nicht vollständig auswertbar", warnings[1])

    def test_host_proxys_loopback_zugeordnet(self):
        # nginx auf dem Host vor mehreren Containern per 127.0.0.1: jeder Port nur bei dem Container, der dort
        # lauscht bzw. ihn auf Loopback veröffentlicht – nicht alle Ports bei allen Containern im Host-Netzwerk
        infos = [inspect("gvp", mode="host"), inspect("selfreg", mode="host"), inspect("leer", mode="host"),
                 inspect("regdido", ["back"], ports={"7776/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7776"}]}),
                 inspect("extern", ["back"], ports={"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}]})]
        procs = ("P\t10\t/usr/sbin/nginx\t/\tnginx: master process /usr/sbin/nginx\t0:0\t1\nS\t10\t5\n"
                 "T\t5\t00000000:01BB\ttcp\n")
        conf = ("http { upstream reg { server 127.0.0.1:7776; } server { listen 443; "
                "location /gvp/ { proxy_pass http://127.0.0.1:7777; } location /selfreg/ { proxy_pass http://localhost:7775; } "
                "location /reg/ { proxy_pass http://reg; } location /x/ { proxy_pass http://127.0.0.1:8000; } "
                "location /h/ { proxy_pass http://127.0.0.1:7443; } } }")
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner, "socket_besitzer",
                                  return_value={("127.0.0.1", "7777"): ["gvp"], ("127.0.0.1", "7775"): ["selfreg"],
                                                ("::1", "7775"): ["selfreg"], ("127.0.0.1", "7443"): [None]}) as sb, \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele, services, warnings, problems, _ = scanner.host_proxys(infos)
        # veröffentlichte Ports werden nicht mehr nach dem lauschenden Prozess gesucht; localhost: IPv4 und IPv6
        self.assertEqual(sb.call_args[0][0], [("127.0.0.1", "7443"), ("127.0.0.1", "7775"), ("127.0.0.1", "7777"),
                                              ("::1", "7775")])
        self.assertEqual(sorted(ziele), [("extern", "3000", "nginx:443 auf dem Host"),
                                         ("gvp", "7777", "nginx:443 auf dem Host (über Loopback)"),
                                         ("regdido", "7776", "nginx:443 auf dem Host"),
                                         ("selfreg", "7775", "nginx:443 auf dem Host (über Loopback)")])
        self.assertIn("Backend http://127.0.0.1:7777 -> Container gvp, Port 7777", services[0]["description"])
        self.assertIn("Backend http://127.0.0.1:8000 -> Container extern, Port 3000", services[0]["description"])
        self.assertIn("Backend http://127.0.0.1:7443 (Host)", services[0]["description"])
        self.assertEqual((warnings, problems), ([], []))
        ausgabe = io.StringIO()
        with mock.patch.object(scanner.sys, "stdout", ausgabe):
            scanner.host_ausgeben(services, warnings, problems)
        self.assertIn("gvp (7777)", ausgabe.getvalue())
        self.assertIn("regdido (7776)", ausgabe.getvalue())
        self.assertNotIn("leer", ausgabe.getvalue())

    def test_host_proxys_eigene_adresse(self):
        # nginx auf dem Host leitet an die eigene IP bzw. 0.0.0.0 weiter: veröffentlichter Port -> Container (auch
        # nur an 127.0.0.1 veröffentlicht, 0.0.0.0 geht an Loopback), eigener Port -> nginx selbst; keine Warnung
        # "anderer Server?" außer für eine fremde Adresse
        infos = [inspect("app", ["back"], ports={"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "21451"}]}),
                 inspect("lokal", ["back"], ports={"4000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "53023"}]})]
        procs = ("P\t10\t/usr/sbin/nginx\t/\tnginx: master process /usr/sbin/nginx\t0:0\t1\nS\t10\t5\n"
                 "T\t5\t00000000:01BB\ttcp\n")
        conf = ("http { server { listen 443; location /a/ { proxy_pass https://192.0.2.31:21451; } "
                "location /selbst/ { proxy_pass https://192.0.2.31:443; } location /b/ { proxy_pass http://0.0.0.0:53023; } "
                "location /fremd/ { proxy_pass http://198.51.100.7; } } }")
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner, "eigene_adressen", return_value={"192.0.2.31"}), \
                mock.patch.object(scanner, "socket_besitzer", return_value={("192.0.2.31", "443"): [None]}) as sb, \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele, services, warnings, problems, urls = scanner.host_proxys(infos)
        self.assertEqual(sb.call_args[0][0], [("192.0.2.31", "443")])      # veröffentlichte nicht gesucht
        # die Webadressen gehen an die Container
        self.assertEqual([e["url"] for e in urls[("app", "3000")]], ["http://*:443/a/"])
        self.assertEqual([e["url"] for e in urls[("lokal", "4000")]], ["http://*:443/b/"])
        self.assertEqual(sorted(ziele), [("app", "3000", "nginx:443 auf dem Host"),
                                         ("lokal", "4000", "nginx:443 auf dem Host")])
        self.assertIn("Backend https://192.0.2.31:443 (Host)", services[0]["description"])
        self.assertEqual(warnings, ["Backend http://198.51.100.7 von nginx:443 auf dem Host keinem Container "
                                    "zuordenbar (anderer Server?)"])

    def test_socket_besitzer(self):
        # lauschende Sockets des Host-Netzwerks per Inode einem Prozess und dessen cgroup zuordnen, passend zu
        # Adresse und Port des Ziels
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        os.mkdir(os.path.join(tmp, "net"))
        kopf = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        zeile = "   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %s 1 0 100 0 0 10 0\n"
        lo6, alle6 = "00000000000000000000000001000000", "0" * 32
        with open(os.path.join(tmp, "net", "tcp"), "w") as f:
            f.write(kopf + zeile % ("0100007F:1E61", "101")      # 127.0.0.1:7777 – Container gvp
                    + zeile % ("00000000:1D13", "102")             # *:7443 – Host
                    + zeile % ("0100007F:1E5E", "103")             # 127.0.0.1:7774 – Prozess nicht lesbar
                    + zeile % ("0100007F:1E5F", "104")             # 127.0.0.1:7775 – zwei Besitzer
                    + zeile % ("0500000A:1E60", "105")             # 10.0.0.5:7776 – nicht über Loopback
                    + zeile.replace(" 0A ", " 01 ") % ("0100007F:1E62", "106")    # 7778: keine Verbindung
                    + zeile % ("0100007F:1E64", "110")             # 127.0.0.1:7780 – gvp …
                    + zeile % ("0100007F:1E65", "112"))            # 127.0.0.1:7781 – gvp
        with open(os.path.join(tmp, "net", "tcp6"), "w") as f:
            f.write(kopf + zeile % (lo6 + ":1E61", "107")         # [::1]:7777 – gvp
                    + zeile % (alle6 + ":1E64", "111"))            # [::]:7780 – … und ein nicht lesbarer Prozess
        ids = {"gvp": "a" * 64, "selfreg": "b" * 64}
        for pid, cgroup, inodes in (("20", "0::/system.slice/docker-%s.scope\n" % ids["gvp"], ["101", "107", "110", "112"]),
                                    ("21", "0::/system.slice/nginx.service\n", ["102"]),
                                    ("22", "0::/system.slice/docker-%s.scope\n" % ids["selfreg"], ["104"]),
                                    ("23", "0::/system.slice/other.service\n", ["104", "105", "106"])):
            os.makedirs(os.path.join(tmp, pid, "fd"))
            for n, inode in enumerate(inodes):
                os.symlink("socket:[%s]" % inode, os.path.join(tmp, pid, "fd", str(n)))
            with open(os.path.join(tmp, pid, "cgroup"), "w") as f:
                f.write(cgroup)
        infos = [inspect(n, mode="host", cid=i) for n, i in sorted(ids.items())]
        ziele = [(a, p) for a in ("127.0.0.1", "::1") for p in ("7777", "7443", "7774", "7775", "7776", "7778", "7780")]
        self.assertEqual(scanner.socket_besitzer(ziele, infos, proc=tmp),
                         {("127.0.0.1", "7777"): ["gvp"], ("::1", "7777"): ["gvp"], ("127.0.0.1", "7443"): [None],
                          # dort lauscht nichts (7776 nur auf 10.0.0.5, 7778 nur eine Verbindung)
                          ("127.0.0.1", "7776"): [], ("127.0.0.1", "7778"): [], ("::1", "7443"): [],
                          ("::1", "7774"): [], ("::1", "7775"): [], ("::1", "7776"): [], ("::1", "7778"): []})
        self.assertEqual(scanner.socket_besitzer(ziele, infos, proc=os.path.join(tmp, "fehlt")), {})
        # Ziele: je Adresse veröffentlichter Port vor lauschendem Prozess, aus Sicht des Hosts bzw. eines Containers
        # im Host-Netzwerk; nur passende Adressen (nicht [::1] für 127.0.0.1, nicht 127.0.0.2 für 127.0.0.1)
        infos.append(inspect("reg", ["back"], ports={"7776/tcp": [{"HostIp": "0.0.0.0", "HostPort": "7443"}],
                                                     "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "7777"}],
                                                     "80/tcp": [{"HostIp": "::1", "HostPort": "7781"}],
                                                     "81/tcp": [{"HostIp": "127.0.0.2", "HostPort": "7782"}]}))
        ziele = {("127.0.0.1", "7777"), ("127.0.0.1", "7443"), ("127.0.0.1", "7774"), ("localhost", "7777"),
                 ("127.0.0.1", "7780"), ("127.0.0.1", "7781"), ("::1", "7781"), ("localhost", "7781"),
                 ("127.0.0.1", "7782"), ("127.0.0.2", "7782"), ("localhost", "7443")}
        self.assertEqual(scanner.loopback_ziele(ziele, infos, "Host", proc=tmp), {
            ("127.0.0.1", "7443"): [("reg", "7776")],
            ("127.0.0.1", "7777"): [("gvp", "7777")],
            ("127.0.0.1", "7781"): [("gvp", "7781")],
            ("127.0.0.2", "7782"): [("reg", "81")],
            ("::1", "7781"): [("reg", "80")],
            ("localhost", "7443"): [("reg", "7776")],        # auf ::1 lauscht nichts
            ("localhost", "7777"): [("gvp", "7777")],
            ("localhost", "7781"): [("gvp", "7781"), ("reg", "80")]})
        # (fehlen: 7774 nicht lesbar, 7780 zusätzlich ein nicht lesbarer Socket, 7782 auf 127.0.0.1 ohne Socket –
        # Rückfallregel)
        self.assertEqual(scanner.loopback_ziele({("127.0.0.1", "7777")}, infos[:2], "gvp", proc=tmp),
                         {("127.0.0.1", "7777"): [("gvp", "7777")]})

    def test_host_exec_mit_benutzer_des_masters(self):
        h = scanner.Host()
        with mock.patch.object(scanner, "run", return_value=(0, "")) as run, \
                mock.patch.object(scanner.os, "geteuid", return_value=0), mock.patch.object(scanner.os, "getegid", return_value=0):
            h.exec(["/usr/sbin/nginx", "-T"], user="0:0")
            self.assertEqual(run.call_args[0][0], ["env", "-i", "PATH=" + scanner.SAFE_PATH, "/usr/sbin/nginx", "-T"])
            h.exec(["/usr/sbin/nginx", "-T"], user="33:33")
            self.assertEqual(run.call_args[0][0][:5], ["setpriv", "--reuid=33", "--regid=33", "--clear-groups", "--"])
        with mock.patch.object(scanner, "run") as run, \
                mock.patch.object(scanner.os, "geteuid", return_value=1000), mock.patch.object(scanner.os, "getegid", return_value=1000):
            self.assertEqual(h.exec(["/usr/sbin/nginx", "-T"], user="0:0")[0], 126)   # ohne root kein Wechsel
            run.assert_not_called()

    def test_tunnel_container_vorgezogen(self):
        infos = [inspect("app", ["n"]), inspect("tunnel", ["n"])]
        infos[1]["Config"].update(Image="cloudflare/cloudflared:2026.1.0", Cmd=["tunnel", "run"])
        self.assertEqual(scanner.container_liste(infos, {})[:2], (["tunnel"], ["app"]))


class Apache(unittest.TestCase):
    def test_debian_konfiguration_mit_umgebungsvariablen(self):
        c = mock.Mock(has_sh=False)
        c.info = {"Config": {"Env": ["APACHE_DOCUMENT_ROOT=/var/www/html/public", "PATH=/usr/bin"]}}
        antworten = {"-S": (0, 'Main DocumentRoot: "/var/www/html"\n'), "-M": (0, " php_module (shared)\n"),
                     "-t": (0, "Included configuration files:\n  (*) /etc/apache2/apache2.conf\n"
                               "    (1) /etc/apache2/sites-enabled/000-default.conf\n")}
        c.exec.side_effect = lambda cmd, **kw: antworten[cmd[1]]
        dateien = {"/etc/apache2/apache2.conf": "ServerRoot /etc/apache2\n",
                   "/etc/apache2/sites-enabled/000-default.conf": """
<VirtualHost *:80>
    ServerName shop.example.org
    DocumentRoot ${APACHE_DOCUMENT_ROOT}
    Alias /static "/srv/static"
    DocumentRoot ${UNBEKANNT}/x
    ProxyPass /api http://backend:8080/api
    <FilesMatch \\.php$>
        SetHandler "proxy:fcgi://php-fpm:9000"
    </FilesMatch>
</VirtualHost>
"""}
        c.read_file.side_effect = lambda p: dateien[p]
        w = web(docroots=scanner.defaultdict(list), backends=scanner.defaultdict(list), vhosts=scanner.defaultdict(list))
        scanner.parse_apache(c, "/usr/sbin/apache2", w)
        self.assertEqual(w["docroots"]["/usr/sbin/apache2"], ["/var/www/html", "/var/www/html/public", "/srv/static"])
        self.assertEqual(w["backends"]["/usr/sbin/apache2"], ["http://backend:8080/api", "fcgi://php-fpm:9000"])
        self.assertEqual(w["modphp"], {"/usr/sbin/apache2"})
        self.assertEqual((w["problems"], w["unlesbar"]), ([], set()))
        self.assertEqual(w["vhosts"]["/usr/sbin/apache2"],
                         ["VirtualHost *:80 ServerName shop.example.org DocumentRoot /var/www/html/public"])

    def test_apache_abfrage_fehlgeschlagen_ist_unvollstaendig(self):
        c = mock.Mock(has_sh=False, info={"Config": {"Env": []}})
        c.exec.side_effect = lambda cmd, **kw: (1, "AH00526: Syntax error") if cmd[1] in ("-S", "-t") else (0, "")
        w = scanner.web_leer()
        scanner.parse_apache(c, "/usr/sbin/apache2", w)
        self.assertEqual(w["unlesbar"], {"/usr/sbin/apache2"})
        self.assertIn("/usr/sbin/apache2 -S bzw. -t -D DUMP_INCLUDES fehlgeschlagen", w["problems"][0])


    def test_rewriterule_proxy_fortsetzungszeilen_und_kommentare(self):
        c = mock.Mock(has_sh=False, info={"Config": {"Env": []}})
        antworten = {"-S": (0, ""), "-M": (0, ""),
                     "-t": (0, "Included configuration files:\n  (*) /etc/httpd/conf/httpd.conf\n")}
        c.exec.side_effect = lambda cmd, **kw: antworten[cmd[1]]
        c.read_file.return_value = """
RewriteEngine On
RewriteRule ^/api/(.*)$ http://api:8080/$1 [P,L]
RewriteRule ^/alt/(.*)$ http://alt.example.org/$1 [R=301,L]
RewriteRule ^/shop/(.*)$ http://shop:3000/$1 [NC,proxy]
RewriteRule ^/(.*)$ http://%{HTTP_HOST}:8081/$1 [P]
# ProxyPass /auskommentiert http://alt:1/
ProxyPass /lang \\
    http://lang:9000/ retry=0
ProxyPass /anker http://anker:9001/#x
"""
        w = scanner.web_leer()
        scanner.parse_apache(c, "/usr/sbin/httpd", w)
        self.assertEqual(w["backends"]["/usr/sbin/httpd"], ["http://api:8080/$1", "http://shop:3000/$1",
                                                            "http://%{HTTP_HOST}:8081/$1", "http://lang:9000/",
                                                            "http://anker:9001/#x"])
        self.assertTrue(scanner.ziel_variabel("http://%{HTTP_HOST}:8081/$1"))
        self.assertFalse(scanner.ziel_variabel("http://api:8080/$1"))

    def test_optionen_des_hauptprozesses(self):
        self.assertEqual(scanner.apache_optionen(["httpd", "-DFOREGROUND"]), ["-DFOREGROUND"])
        self.assertEqual(scanner.apache_optionen(["/usr/sbin/httpd", "-f", "/etc/httpd/app.conf", "-D", "SSL", "-k",
                                                  "start", "-C", "Include /x.conf"]),
                         ["-f", "/etc/httpd/app.conf", "-D", "SSL", "-C", "Include /x.conf"])
        # -S, -M und -t mit denselben Optionen, sonst liest Apache eine andere Konfiguration
        c = mock.Mock(has_sh=True, info={"Config": {"Env": []}, "HostConfig": {}, "NetworkSettings": {}})
        c.exec.return_value = (0, "")
        c.read_file.return_value = ""
        procs = {"1": proc(1, "/usr/sbin/httpd", ["httpd", "-f", "/etc/httpd/app.conf"], user="0:0")}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            scanner.collect_web(c, procs)
        self.assertEqual([call[0][0][4:] for call in c.exec.call_args_list],
                         [["-f", "/etc/httpd/app.conf", "-S"], ["-f", "/etc/httpd/app.conf", "-M"],
                          ["-f", "/etc/httpd/app.conf", "-t", "-D", "DUMP_INCLUDES"]])

class ApacheBenutzer(unittest.TestCase):
    def test_abfrage_mit_benutzer_des_hauptprozesses(self):
        for master_user, erwartet in (("1001:0", "1001:0"), ("0:0", "0:0"), ("", scanner.NOBODY)):
            c = mock.Mock(has_sh=True, info={"Config": {"Env": []}, "HostConfig": {}, "NetworkSettings": {}})
            c.exec.return_value = (0, "")
            c.read_file.return_value = ""
            procs = {"1": proc(1, "/usr/sbin/apache2", ["apache2", "-DFOREGROUND"], user=master_user),
                     "2": proc(2, "/usr/sbin/apache2", ["apache2", "-DFOREGROUND"], user="33:33", ppid=1)}
            with mock.patch.object(scanner, "run", return_value=(0, "")):
                scanner.collect_web(c, procs)
            self.assertEqual({kw["user"] for _, kw in c.exec.call_args_list}, {erwartet})
            self.assertEqual(c.exec.call_count, 3)      # -S, -M, -t -D DUMP_INCLUDES; Worker nicht


class Backends(unittest.TestCase):
    def setUp(self):
        self.w = web(upstreams={"api": ["app-api:8000", "localhost:9000"]}, containers={"app-api": "app-api", "app": "app"},
                     self="app")

    def test_split_target(self):
        self.assertEqual(scanner.split_target("http://app:3000/x"), ("app", "3000"))
        self.assertEqual(scanner.split_target("https://app"), ("app", "443"))
        self.assertEqual(scanner.split_target("php:9000"), ("php", "9000"))
        self.assertEqual(scanner.split_target("unix:/run/php.sock"), ("", ""))
        # ohne Port: wie nginx 80 (upstream { server app; }), sonst Standardport des Schemas
        self.assertEqual(scanner.split_target("app"), ("app", "80"))
        self.assertEqual(scanner.split_target("ajp://tomcat"), ("tomcat", "8009"))
        self.assertEqual(scanner.split_target("grpcs://api"), ("api", "443"))
        self.assertEqual(scanner.split_target("http://[fd00::2]:8080/x"), ("fd00::2", "8080"))
        self.assertEqual(scanner.split_target("http://[fd00::2]"), ("fd00::2", "80"))
        # IPv6 einheitlich; 0.0.0.0 und :: verbinden unter Linux an die Loopback-Adresse
        self.assertEqual(scanner.split_target("https://[2001:DB8:0::31]:21451"), ("2001:db8::31", "21451"))
        self.assertEqual(scanner.split_target("http://0.0.0.0:53023"), ("127.0.0.1", "53023"))
        self.assertEqual(scanner.split_target("http://[::]:8080"), ("::1", "8080"))

    def test_lokale_ziele(self):
        # eigene Adressen des Hosts nur im Netzwerk des Hosts (dort gesetzt) wie Loopback
        w = web(eigene_adressen={"192.0.2.31"}, self="Host")
        for host in ("127.0.0.1", "127.0.0.11", "localhost", "::1", "192.0.2.31"):
            self.assertTrue(scanner.lokales_ziel(host, w), host)
        for host in ("192.0.2.32", "app", "10.0.0.5"):
            self.assertFalse(scanner.lokales_ziel(host, w), host)
        self.assertFalse(scanner.lokales_ziel("192.0.2.31", web()))

    def test_eigene_adressen(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        os.mkdir(os.path.join(tmp, "net"))
        with open(os.path.join(tmp, "net", "fib_trie"), "w") as f:
            f.write("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n"
                    "     +-- 127.0.0.0/8 2 0 2\n        +-- 127.0.0.0/31 1 0 0\n           |-- 127.0.0.1\n"
                    "              /32 host LOCAL\n     |-- 192.0.2.31\n        /32 host LOCAL\n"
                    "     |-- 192.0.2.255\n        /32 link BROADCAST\n"
                    "Local:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 172.17.0.1\n        /32 host LOCAL\n")
        with open(os.path.join(tmp, "net", "if_inet6"), "w") as f:
            f.write("00000000000000000000000000000001 01 80 10 80       lo\n"
                    "20010db8000000000000000000000031 02 40 00 80     eth0\n")
        self.assertEqual(scanner.eigene_adressen(tmp), {"192.0.2.31", "172.17.0.1", "2001:db8::31"})
        self.assertEqual(scanner.eigene_adressen(os.path.join(tmp, "fehlt")), set())

    def test_ipv6_ziele(self):
        w = web(containers={"fd00::2": "app6"}, self="proxy")
        self.assertEqual(scanner.backend_containers("http://[fd00::2]:8080", w), [("app6", "8080")])
        self.assertEqual(scanner.backend_containers("http://[::1]:9000", w), [("proxy", "9000")])
        self.assertIn("-> Container app6", scanner.resolve_backend("http://[fd00::2]:8080", w, "proxy"))
        self.assertIn("(gleicher Container)", scanner.resolve_backend("http://[::1]:9000", w, "proxy"))

    def test_ziele_ueber_gemeinsames_loopback(self):
        # Host-Netzwerk bzw. gemeinsamer Netzwerk-Namespace: localhost trifft auch die anderen Container dort
        w = web(upstreams={"u": ["127.0.0.1:7777", "app-api:8000"]}, containers={"app-api": "app-api"},
                self="proxy", loopback=["app"])
        self.assertEqual(scanner.backend_containers("http://127.0.0.1:7777", w), [("proxy", "7777"), ("app", "7777")])
        self.assertEqual(scanner.backend_containers("http://u", w, nur_loopback=True), [("app", "7777")])
        self.assertEqual(scanner.backend_containers("http://app-api:8000", w, nur_loopback=True), [])
        self.assertEqual(scanner.resolve_backend("http://localhost:7777", w, "proxy"),
                         "http://localhost:7777 (gleicher Container; Loopback gemeinsam mit app)")
        self.assertEqual(scanner.resolve_backend("http://localhost:7777", web(loopback=["app"]), "Host"),
                         "http://localhost:7777 (Host; Loopback gemeinsam mit app)")
        nginx = proc(1, "/usr/sbin/nginx", ports={"443": "alle"})
        s = scanner.mark_usage([], {"1": nginx}, {}, dict(w, published={"443": ["0.0.0.0:443"]},
                                                          backends={"/usr/sbin/nginx": ["http://u"]}))[0]
        self.assertEqual(s["backends"], [("app", "7777", "nginx:443 (über Loopback)"), ("app-api", "8000", "nginx:443")])
        # nicht auswertbares Ziel: auch die Container mit demselben Loopback möglicherweise erreichbar
        s = scanner.mark_usage([], {"1": nginx}, {}, dict(w, published={"443": ["0.0.0.0:443"]}, nachbarn=["app-api"],
                                                          backends={"/usr/sbin/nginx": ["http://$host"]}))[0]
        self.assertEqual(s["backends"], [("app-api", "*", "nginx:443"), ("app", "*", "nginx:443 (über Loopback)")])

    def test_unix_socket(self):
        self.assertEqual(scanner.unix_socket("unix:/home/redmine/tmp/redmine.socket"), "/home/redmine/tmp/redmine.socket")
        self.assertEqual(scanner.unix_socket("http://unix:/run/app.sock:/api/"), "/run/app.sock")
        self.assertEqual(scanner.unix_socket("unix:/run/app.sock|http://localhost/"), "/run/app.sock")   # Apache
        self.assertEqual(scanner.unix_socket("http://app:3000"), "")
        self.assertEqual(scanner.endziele("http://r", web(upstreams={"r": ["unix:/a.sock", "app:80"]})),
                         ["unix:/a.sock", "app:80"])

    def test_upstream_auf_unix_socket_im_container(self):
        # Redmine (sameersbn/redmine): nginx -> upstream redmine { server unix:/home/redmine/tmp/redmine.socket; }
        # Der Besitzer des Sockets ist genau bekannt (Socket-Inode); andere Prozesse (Sidekiq, cron) nicht dahinter.
        socket = "/home/redmine/tmp/redmine.socket"
        libssl = scanner.comp("os-paket", "libssl3", "3.0")
        for ziel in ("http://redmine", "http://unix:%s:/" % socket):
            for besitzer in ([socket], []):     # [] = Socket gehört einem anderen Container (gemeinsames Volume)
                nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
                worker = proc(2, "/usr/sbin/nginx", ppid=1)
                ruby = proc(3, "/usr/bin/ruby", maps={"/usr/lib/libssl.so.3"}, unix=besitzer)
                sidekiq = proc(4, "/usr/bin/ruby2", maps={"/usr/lib/libssl.so.3"}, unix=["/tmp/anderer.sock"])
                libssl["aktiv"], libssl["aktiv_ohne_port"] = [], []
                w = web(published={"80": ["0.0.0.0:80"]}, upstreams={"redmine": ["unix:" + socket]},
                        backends={"/usr/sbin/nginx": [ziel]})
                services = scanner.mark_usage([libssl], {"1": nginx, "2": worker, "3": ruby, "4": sidekiq},
                                              {"/lib/libssl.so.3": {"libssl3"}}, w)
                s = [s for s in services if s["label"] == "nginx:80"][0]
                self.assertNotIn("frontends", worker)
                self.assertNotIn("frontends", sidekiq)
                if besitzer:
                    self.assertEqual((s["unresolved"], ruby["frontends"]), ([], ["nginx:80"]), ziel)
                    self.assertEqual(scanner.priority(libssl, {"nginx:80"}), 1)
                else:
                    self.assertEqual((s["unresolved"], "frontends" in ruby), ([ziel], False), ziel)
                    self.assertEqual(scanner.priority(libssl, {"nginx:80"}), 3)

    def test_upstream_teils_nicht_zuordenbar(self):
        # ein Ziel des upstream zugeordnet, ein anderes nicht: Warnung für das Backend bleibt (auch bei TCP-Zielen)
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        puma = proc(2, "/usr/bin/ruby", unix=["/run/eigen.sock"])
        for ziele, erwartet in ((["unix:/run/eigen.sock", "unix:/run/fremd.sock"], ["http://u"]),
                                (["app:3000", "10.0.0.99:80"], ["http://u"]),
                                (["unix:/run/eigen.sock", "app:3000"], [])):
            w = web(published={"80": ["0.0.0.0:80"]}, upstreams={"u": ziele}, containers={"app": "app-c"},
                    backends={"/usr/sbin/nginx": ["http://u"]})
            s = scanner.mark_usage([], {"1": nginx, "2": puma}, {}, w)
            self.assertEqual([x["unresolved"] for x in s if x["label"] == "nginx:80"], [erwartet], ziele)

    def test_upstream_ohne_port(self):
        w = web(upstreams={"b": ["app"]}, containers={"app": "app-c"})
        self.assertEqual(scanner.backend_containers("http://b", w), [("app-c", "80")])

    def test_ziel_variabel(self):
        self.assertTrue(scanner.ziel_variabel("http://$host"))
        self.assertTrue(scanner.ziel_variabel("http://app:$port/x"))
        self.assertFalse(scanner.ziel_variabel("http://app:3000/$1"))
        self.assertFalse(scanner.ziel_variabel("unix:/run/php.sock"))

    def test_backend_containers(self):
        self.assertEqual(scanner.backend_containers("http://api", self.w), [("app-api", "8000"), ("app", "9000")])
        self.assertEqual(scanner.backend_containers("http://unbekannt:1", self.w), [])

    def test_resolve_backend(self):
        self.assertEqual(scanner.resolve_backend("http://app-api:8000", self.w, "app"), "http://app-api:8000 -> Container app-api")
        self.assertEqual(scanner.resolve_backend("http://app:80", self.w, "app"), "http://app:80 (gleicher Container)")
        self.assertEqual(scanner.resolve_backend("unix:/run/php.sock", self.w, "app"), "unix:/run/php.sock (gleicher Container)")
        self.assertEqual(scanner.resolve_backend("http://$host", self.w, "app"), "http://$host (Variable, nicht auswertbar)")
        self.assertEqual(scanner.resolve_backend("http://example.com", self.w, "app"), "http://example.com (extern/unbekannt)")
        self.assertIn("-> Container app-api", scanner.resolve_backend("http://api", self.w, "app"))


class ApacheSites(unittest.TestCase):
    def test_vhosts_aus_S(self):
        out = """VirtualHost configuration:
*:443                  www.example.org (/etc/apache2/vhosts.d/www-ssl.conf:2)
*:80                   is a NameVirtualHost
         default server www.example.org (/etc/apache2/vhosts.d/www.conf:1)
         port 80 namevhost www.example.org (/etc/apache2/vhosts.d/www.conf:1)
                 alias example.org
                 wild alias *.example.org
         port 80 namevhost intranet (/etc/apache2/vhosts.d/intra.conf:1)
127.0.0.1:8080         app.example.org (/etc/apache2/vhosts.d/app.conf:3)
ServerRoot: "/srv/www"
"""
        self.assertEqual(scanner.apache_vhosts(out), [
            {"adresse": "*", "port": "443", "name": "www.example.org", "aliase": [],
             "datei": "/etc/apache2/vhosts.d/www-ssl.conf", "zeile": 2},
            {"adresse": "*", "port": "80", "name": "www.example.org", "aliase": ["example.org", "*.example.org"],
             "datei": "/etc/apache2/vhosts.d/www.conf", "zeile": 1},
            {"adresse": "*", "port": "80", "name": "intranet", "aliase": [], "datei": "/etc/apache2/vhosts.d/intra.conf",
             "zeile": 1},
            {"adresse": "127.0.0.1", "port": "8080", "name": "app.example.org", "aliase": [],
             "datei": "/etc/apache2/vhosts.d/app.conf", "zeile": 3}])
        self.assertEqual(scanner.apache_name("https://www.example.org:443"), ("www.example.org", "https"))
        self.assertEqual(scanner.apache_name("www.example.org"), ("www.example.org", ""))

    def apache(self, dateien, s_out):
        c = mock.Mock(has_sh=False, info={"Config": {"Env": []}})
        antworten = {"-S": (0, s_out), "-M": (0, ""),
                     "-t": (0, "Included configuration files:\n" + "".join("  (*) %s\n" % d for d in dateien))}
        c.exec.side_effect = lambda cmd, **kw: antworten[next(x for x in cmd if x in antworten)]
        c.read_file.side_effect = lambda p: dateien[p]
        w = scanner.web_leer()
        scanner.parse_apache(c, "/usr/sbin/httpd-prefork", w)
        return w

    DATEIEN = {"/etc/apache2/httpd.conf": """Listen 80
<IfDefine SSL>
    Listen 443
</IfDefine>
ServerName web01.example.com
""", "/etc/apache2/vhosts.d/www.conf": """
<VirtualHost \\
    *:443>
    ServerName https://www.example.org:443
    ServerAlias example.org
    SSLEngine on
    DocumentRoot /srv/www/htdocs
    ProxyPass /api/ http://127.0.0.1:3000/ \\
        retry=0
    <LocationMatch "^/app/">
        ProxyPass http://app:8080/
    </LocationMatch>
    <FilesMatch \\.php$>
        SetHandler "proxy:fcgi://php:9000"
    </FilesMatch>
    RewriteRule ^/shop/(.*)$ http://shop:3000/$1 [P]
</VirtualHost>
"""}

    def test_websites(self):
        # vHost aus -S (Zeile des Blockanfangs, auch über eine Fortsetzungszeile), TLS, Docroot und Weiterleitungen
        # aus dem Block; der Hauptserver an den Ports ohne vHost
        s_out = "VirtualHost configuration:\n*:443                  www.example.org (/etc/apache2/vhosts.d/www.conf:2)\n"
        www, haupt = self.apache(self.DATEIEN, s_out)["sites"]
        self.assertEqual((www["namen"], www["listen"], www["roots"], www["datei"]), (
            ["www.example.org"], [{"adresse": "*", "port": "443", "ssl": True}], ["/srv/www/htdocs"],
            "/etc/apache2/vhosts.d/www.conf:2"))
        self.assertEqual(www["weiter"], [("/api/", "http://127.0.0.1:3000/"), ("~ ^/app/", "http://app:8080/"),
                                         ("~ \\.php$", "fcgi://php:9000"), ("~ ^/shop/(.*)$", "http://shop:3000/$1")])
        self.assertEqual((haupt["namen"], haupt["listen"], haupt["datei"]), (
            ["web01.example.com"], [{"adresse": "*", "port": "80", "ssl": False}], "(Hauptserver)"))

    def test_websites_ohne_S(self):
        # -S ohne vHosts: die Blöcke aus den Dateien (Name und TLS aus ServerName https://…)
        www, haupt = self.apache(self.DATEIEN, "")["sites"]
        self.assertEqual((www["namen"], www["listen"]), (["www.example.org", "example.org"],
                                                         [{"adresse": "*", "port": "443", "ssl": True}]))
        self.assertEqual([l["port"] for l in haupt["listen"]], ["80"])


NGINX_SITES = """# configuration file /etc/nginx/nginx.conf:
http {
    server { listen 80; server_name localhost; root /srv/www/htdocs/; }
    include /etc/nginx/vhosts.d/*.conf;
}
stream { server { listen 5432; proxy_pass db:5432; } }
# configuration file /etc/nginx/vhosts.d/www.conf:
server {
    listen 80;
    listen [::]:443 ssl http2;
    listen 127.0.0.1:8443 ssl;
    listen 443 quic;
    server_name www.example.org .example.net ~^(?<sub>.+)\\.example\\.com$;
    root /srv/www/htdocs;
    location /app/ { proxy_pass http://127.0.0.1:8080/; }
    location ~ \\.php$ { fastcgi_pass unix:/run/php-fpm.sock; }
}
server { listen 8080; ssl on; server_name _; }
"""


class NginxSites(unittest.TestCase):
    def setUp(self):
        self.w = scanner.web_leer()
        scanner.parse_nginx(NGINX_SITES, self.w, "/usr/sbin/nginx")

    def test_sites(self):
        lokal, www, alt = self.w["sites"]          # stream-Server: keine Website
        self.assertEqual((lokal["namen"], lokal["datei"], lokal["roots"]),
                         (["localhost"], "/etc/nginx/nginx.conf", ["/srv/www/htdocs/"]))
        self.assertEqual(www["datei"], "/etc/nginx/vhosts.d/www.conf")
        self.assertEqual(www["listen"], [{"adresse": "*", "port": "80", "ssl": False, "udp": False},
                                         {"adresse": "::", "port": "443", "ssl": True, "udp": False},
                                         {"adresse": "127.0.0.1", "port": "8443", "ssl": True, "udp": False}])
        self.assertEqual(www["weiter"], [("/app/", "http://127.0.0.1:8080/"), ("~ \\.php$", "unix:/run/php-fpm.sock")])
        self.assertEqual((alt["namen"], alt["listen"][0]["ssl"]), ([], True))      # ssl on; "_" ist kein Name
        self.assertIn("db:5432", self.w["backends"]["/usr/sbin/nginx"])

    def test_webadressen_einer_site(self):
        www = self.w["sites"][1]
        self.assertEqual(scanner.site_urls(www, self.w), [
            "http://www.example.org/", "http://example.net/", "http://*.example.net/", "https://www.example.org/",
            "https://example.net/", "https://*.example.net/", "https://www.example.org:8443/",
            "https://example.net:8443/", "https://*.example.net:8443/"])
        # ohne Namen: "*"; im Container: veröffentlichter Port statt des Ports im Container
        self.assertEqual(scanner.site_urls(self.w["sites"][2], self.w), ["https://*:8080/"])
        w = web(published={"8080": ["0.0.0.0:18080", "127.0.0.1:9000 (nur lokal – vermutlich hinter …)"]})
        self.assertEqual(scanner.site_urls(self.w["sites"][2], w), ["https://*:18080/"])
        self.assertEqual(scanner.url_pfad("https://a/", "/app/"), "https://a/app/")
        self.assertEqual(scanner.url_pfad("https://a/", "= /x"), "https://a/x")
        self.assertEqual(scanner.url_pfad("https://a/", "~* \\.php$"), "https://a/ (\\.php$)")


def dienst(label, exe, ports, exposed=False):
    return {"label": label, "name": os.path.basename(exe), "exe": exe, "exposed": exposed,
            "ports": scanner.OrderedDict((p, ("…", exposed)) for p in ports), "backends": [], "unresolved": [],
            "unklar": [], "endpoints": [], "description": ""}


class Webadressen(unittest.TestCase):
    """nginx (öffentlich) -> Apache (Loopback) -> php-fpm im selben Container."""

    def setUp(self):
        self.w = web(self="app",
                     sites=[{"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["www.example.org"], "datei": "www.conf",
                             "roots": ["/srv/www/htdocs"], "listen": [{"adresse": "*", "port": "443", "ssl": True}],
                             "weiter": [("/app/", "http://127.0.0.1:8080/"), ("/api/", "http://10.0.0.7:3000/")]},
                            {"exe": "/usr/sbin/httpd-prefork", "art": "apache", "namen": ["app.example.org"],
                             "datei": "app.conf:1", "roots": ["/srv/www/app/public"],
                             "listen": [{"adresse": "127.0.0.1", "port": "8080", "ssl": False}],
                             "weiter": [("~ \\.php$", "fcgi://127.0.0.1:9000")]}])
        self.services = [dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True),
                         dienst("httpd-prefork:8080", "/usr/sbin/httpd-prefork", ["8080"]),
                         dienst("php-fpm:9000", "/usr/sbin/php-fpm", ["9000"])]
        scanner.webadressen(self.services, self.w)

    def urls(self, i):
        return [(e["url"], e["erreichbar"]) for e in self.services[i]["webadressen"]]

    def test_kette(self):
        self.assertEqual(self.urls(0), [("https://www.example.org/", True)])
        self.assertEqual(self.urls(1), [("https://www.example.org/app/", True), ("http://app.example.org:8080/", False)])
        self.assertEqual(self.urls(2), [("https://www.example.org/app/ (\\.php$)", True),
                                        ("http://app.example.org:8080/ (\\.php$)", False)])
        self.assertEqual(self.services[2]["webadressen"][0]["weg"], "nginx:443 → httpd-prefork:8080 → php-fpm:9000")
        self.assertEqual(self.w["ziel_urls"], {})        # 10.0.0.7: kein Container

    def test_ziel_ueber_unix_socket(self):
        # nginx -> upstream auf einen Unix-Socket (Redmine): die Webadresse beim Prozess, der darauf lauscht
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        ruby = proc(2, "/usr/bin/ruby", unix=["/home/redmine/tmp/redmine.socket"])
        sidekiq = proc(3, "/usr/bin/sidekiq", unix=["/tmp/anderer.sock"])
        w = web(published={"80": ["0.0.0.0:80"]}, upstreams={"redmine": ["unix:/home/redmine/tmp/redmine.socket"]},
                backends={"/usr/sbin/nginx": ["http://redmine"]},
                sites=[{"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["redmine.example.org"], "datei": "r.conf",
                        "roots": [], "listen": [{"adresse": "*", "port": "80", "ssl": False}],
                        "weiter": [("/", "http://redmine")]}])
        services = scanner.mark_usage([], {"1": nginx, "2": ruby, "3": sidekiq}, {}, w)
        scanner.webadressen(services, w)
        urls = {s["label"]: [(e["url"], e["erreichbar"], e["weg"]) for e in s["webadressen"]] for s in services}
        self.assertEqual(urls["ruby"], [("http://redmine.example.org/", True, "nginx:80 → ruby")])
        self.assertNotIn("sidekiq", urls)

    def test_ziele_in_containern(self):
        # nginx auf dem Host leitet Pfade an Container weiter (veröffentlichter Port auf Loopback bzw. Container-IP):
        # deren Webadressen gehen an den Scan des Containers, mit dem Port im Container
        w = dict(self.w, self="Host", containers={"172.18.0.5": "api"},
                 loopback_ziele={("127.0.0.1", "7776"): [("regdido", "3000")]})
        w["sites"] = [dict(w["sites"][0], weiter=[("/regdido/", "http://127.0.0.1:7776/"),
                                                  ("/api/", "http://172.18.0.5:8080")])]
        services = [dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True)]
        scanner.webadressen(services, w)
        self.assertEqual(list(w["ziel_urls"]), [("regdido", "3000"), ("api", "8080")])
        self.assertEqual(w["ziel_urls"][("regdido", "3000")], [
            {"url": "https://www.example.org/regdido/", "erreichbar": True, "weg": "nginx:443 auf dem Host",
             "lokal": False}])
        # im Scan des Containers: Webadressen des Dienstes an diesem Port
        node = dienst("node:3000", "/usr/local/bin/node", ["3000"], exposed=True)
        cw = web(self="regdido", via_urls={"3000": w["ziel_urls"][("regdido", "3000")]})
        scanner.webadressen([node], cw)
        self.assertEqual([(e["url"], e["erreichbar"], e["weg"]) for e in node["webadressen"]], [
            ("https://www.example.org/regdido/", True, "nginx:443 auf dem Host → node:3000")])
        self.assertEqual(cw["ziel_urls"], {})
        # Proxy in einem anderen Container: Weg mit dessen Namen
        w = dict(self.w, self="proxy", containers={"app": "app"})
        w["sites"] = [dict(w["sites"][0], weiter=[("/", "http://app:3000")])]
        scanner.webadressen([dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True)], w)
        self.assertEqual([e["weg"] for e in w["ziel_urls"][("app", "3000")]], ["nginx:443 in proxy"])

    def test_ziel_nur_auf_loopback(self):
        # Proxy von außerhalb (Container-IP), Dienst lauscht nur auf Loopback: Adresse nicht erreichbar
        node = dienst("node:3000", "/usr/local/bin/node", ["3000"], exposed=False)
        e = {"url": "https://www.example.org/app/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False}
        scanner.webadressen([node], web(self="app", via_urls={"3000": [e]}))
        self.assertEqual([(x["url"], x["erreichbar"]) for x in node["webadressen"]],
                         [("https://www.example.org/app/", False)])

    def test_website_nur_an_loopback(self):
        # nginx lauscht an Port 80 öffentlich und mit einer zweiten Website nur an 127.0.0.1: diese ist nicht
        # erreichbar (auch nicht ihre Ziele), außer über einen Proxy mit demselben Loopback
        sites = [{"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["public.example"], "datei": "a.conf", "roots": [],
                  "listen": [{"adresse": "*", "port": "80", "ssl": False}], "weiter": []},
                 {"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["intern.example"], "datei": "b.conf", "roots": [],
                  "listen": [{"adresse": "127.0.0.1", "port": "80", "ssl": False}],
                  "weiter": [("/", "http://127.0.0.1:9000/")]}]
        for lokal_offen, erwartet in ((False, False), (True, True)):
            nginx = dienst("nginx:80", "/usr/sbin/nginx", ["80"], exposed=True)
            nginx["ports_lokal"] = {"80": lokal_offen}
            backend = dienst("python3:9000", "/usr/bin/python3", ["9000"])
            scanner.webadressen([nginx, backend], web(self="app", sites=sites))
            self.assertEqual(sorted((e["url"], e["erreichbar"]) for e in nginx["webadressen"]),
                             [("http://intern.example/", erwartet), ("http://public.example/", True)])
            self.assertEqual([(e["url"], e["erreichbar"]) for e in backend["webadressen"]],
                             [("http://intern.example/", erwartet)])

    def test_ziel_im_selben_container_ueber_namen(self):
        # proxy_pass über den eigenen Containernamen bzw. die Container-IP: erreicht keinen Dienst, der nur auf
        # Loopback lauscht; über 127.0.0.1 schon
        for ziel, bindung, erwartet in (("http://app:3000/", "localhost", (False, False)),
                                        ("http://app:3000/", "alle", (True, False)),
                                        ("http://127.0.0.1:3000/", "localhost", (True, True))):
            site = {"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["www.example.org"], "datei": "a.conf",
                    "roots": [], "listen": [{"adresse": "*", "port": "80", "ssl": False}], "weiter": [("/", ziel)]}
            nginx = dienst("nginx:80", "/usr/sbin/nginx", ["80"], exposed=True)
            node = dienst("node:3000", "/usr/local/bin/node", ["3000"])
            node["bindungen"] = {"3000": bindung}
            scanner.webadressen([nginx, node], web(self="app", sites=[site], containers={"app": "app"}))
            self.assertEqual([(e["erreichbar"], e["lokal"]) for e in node["webadressen"]], [erwartet], (ziel, bindung))

    def test_nur_loopback_je_weg(self):
        # Dienst nur auf Loopback, Port erreichbar über einen Proxy mit demselben Loopback: die Adresse eines
        # zweiten Proxys über die Container-IP erreicht ihn trotzdem nicht
        node = dienst("node:3000", "/usr/local/bin/node", ["3000"], exposed=True)
        node["bindungen"] = {"3000": "localhost"}
        via = [{"url": "https://a.example/", "erreichbar": True, "weg": "nginx:443 in proxy", "lokal": True},
               {"url": "https://b.example/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False}]
        scanner.webadressen([node], web(self="app", via_urls={"3000": via}))
        self.assertEqual([(e["url"], e["erreichbar"]) for e in node["webadressen"]],
                         [("https://a.example/", True), ("https://b.example/", False)])

    def test_weitergeleitete_adressen_je_port(self):
        # nginx im Container mit getrennten Websites an 80 und 8080: eine an Port 80 weitergeleitete Adresse gilt
        # nicht für die Website an 8080 (und deren Ziel)
        sites = [{"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["public.example"], "datei": "a.conf",
                  "roots": [], "listen": [{"adresse": "*", "port": "80", "ssl": False}], "weiter": []},
                 {"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["intern.example"], "datei": "b.conf",
                  "roots": [], "listen": [{"adresse": "*", "port": "8080", "ssl": False}],
                  "weiter": [("/private/", "http://127.0.0.1:9000/")]}]
        e = {"url": "https://public.example/app/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False}
        nginx = dienst("nginx:80,8080", "/usr/sbin/nginx", ["80", "8080"], exposed=True)
        backend = dienst("python3:9000", "/usr/bin/python3", ["9000"])
        scanner.webadressen([nginx, backend], web(self="app", sites=sites, via_urls={"80": [e]}))
        self.assertIn("https://public.example/app/", [x["url"] for x in nginx["webadressen"]])
        self.assertEqual([x["url"] for x in backend["webadressen"]], ["http://intern.example:8080/private/"])

    def test_erreichbarer_weg_ersetzt_nicht_erreichbaren(self):
        # dieselbe Adresse für dasselbe Ziel über einen internen und einen öffentlichen Webserver: erreichbar
        w = dict(self.w, self="Host", containers={"172.18.0.5": "api"})
        w["sites"] = [dict(w["sites"][1], namen=["www.example.org"], listen=[{"adresse": "127.0.0.1", "port": "80",
                                                                               "ssl": False}],
                           weiter=[("/api/", "http://172.18.0.5:8080/")]),
                      dict(w["sites"][0], namen=["www.example.org"], listen=[{"adresse": "*", "port": "80", "ssl": False}],
                           weiter=[("/api/", "http://172.18.0.5:8080/")])]
        services = [dienst("httpd-prefork:80", "/usr/sbin/httpd-prefork", ["80"]),
                    dienst("nginx:80", "/usr/sbin/nginx", ["80"], exposed=True)]
        scanner.webadressen(services, w)
        self.assertEqual([(x["url"], x["erreichbar"], x["weg"]) for x in w["ziel_urls"][("api", "8080")]],
                         [("http://www.example.org/api/", True, "nginx:80 auf dem Host")])
        liste = [{"url": "u", "erreichbar": False, "weg": "a"}]
        self.assertTrue(scanner.adresse_zufuegen(liste, {"url": "u", "erreichbar": True, "weg": "b"}))
        self.assertFalse(scanner.adresse_zufuegen(liste, {"url": "u", "erreichbar": False, "weg": "c"}))
        self.assertEqual(liste, [{"url": "u", "erreichbar": True, "weg": "b"}])

    def test_gleiche_url_eigene_website_und_proxy(self):
        # dieselbe URL vom Proxy übernommen und als eigene Website: beide bleiben (Zuordnung zur Website mit Docroot),
        # ebenso bei anderer Herkunft (lokal)
        site = {"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["www.example.org"], "datei": "www.conf",
                "roots": ["/var/www/html"], "listen": [{"adresse": "*", "port": "80", "ssl": False}], "weiter": []}
        via = [{"url": "http://www.example.org/", "erreichbar": True, "weg": "nginx:443 auf dem Host", "lokal": False},
               {"url": "http://www.example.org/", "erreichbar": True, "weg": "nginx:443 in proxy", "lokal": True}]
        nginx = dienst("nginx:80", "/usr/sbin/nginx", ["80"], exposed=True)
        scanner.webadressen([nginx], web(self="app", sites=[site], via_urls={"80": via}))
        self.assertEqual(sorted((e["site"] is site, e["lokal"]) for e in nginx["webadressen"]),
                         [(False, False), (False, True), (True, False)])

    def test_lokal_ueber_upstream(self):
        # upstream mit 127.0.0.1 im Host-Netzwerk: Anfrage kommt über Loopback (lokal), über die Container-IP nicht
        w = dict(self.w, self="Host", containers={"172.18.0.5": "api"}, loopback=["hostapp"],
                 upstreams={"status": ["127.0.0.1:8080"], "api": ["172.18.0.5:3000"]})
        w["sites"] = [dict(w["sites"][0], weiter=[("/status/", "http://status/"), ("/api/", "http://api/")])]
        services = [dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True)]
        scanner.webadressen(services, w)
        self.assertEqual([e["lokal"] for e in w["ziel_urls"][("hostapp", "8080")]], [True])
        self.assertEqual([e["lokal"] for e in w["ziel_urls"][("api", "3000")]], [False])

    def test_urls_zufuegen(self):
        # je Container und Port gesammelt, im gemeinsamen Netzwerk-Namespace auch für die übrigen Container der
        # Gruppe; eine schon übergebene Liste bleibt unverändert
        urls = {}
        e = {"url": "https://a/", "erreichbar": False, "weg": "x", "lokal": False}
        self.assertEqual(scanner.urls_zufuegen(urls, {("app", "80"): [e]}, {"app": ["vpn"]}), {"app", "vpn"})
        uebergeben = urls["app"]["80"]
        self.assertEqual(scanner.urls_zufuegen(urls, {("app", "80"): [e]}, {}), set())
        self.assertEqual(scanner.urls_zufuegen(urls, {("app", "80"): [dict(e, erreichbar=True)]}, {}), {"app"})
        self.assertEqual((uebergeben[0]["erreichbar"], urls["app"]["80"][0]["erreichbar"]), (False, True))


class HostWebadressen(unittest.TestCase):
    def test_webadressen_der_ziele(self):
        # nginx direkt auf dem Host: die Webadressen seiner Ziele in Containern (Container-IP, veröffentlichter Port
        # auf Loopback) gehen an deren Scan, ohne Scan des Hosts
        infos = [inspect("app", ["back"]),
                 inspect("regdido", ["back"], ports={"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7776"}]})]
        ip = infos[0]["NetworkSettings"]["Networks"]["back"]["IPAddress"]
        procs = ("P\t10\t/usr/sbin/nginx\t/\tnginx: master process /usr/sbin/nginx\t0:0\t1\nS\t10\t5\n"
                 "T\t5\t00000000:01BB\ttcp\n")
        conf = ("http { server { listen 443 ssl; server_name www.example.org; location /app/ { proxy_pass "
                "http://%s:3000/; } location /reg/ { proxy_pass http://127.0.0.1:7776/; } } }" % ip)
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 0)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele, services, _, _, ziel_urls = scanner.host_proxys(infos)
        self.assertEqual(ziel_urls, {
            ("app", "3000"): [{"url": "https://www.example.org/app/", "erreichbar": True,
                               "weg": "nginx:443 auf dem Host", "lokal": False}],
            ("regdido", "3000"): [{"url": "https://www.example.org/reg/", "erreichbar": True,
                                   "weg": "nginx:443 auf dem Host", "lokal": False}]})
        self.assertEqual(services[0]["label"], "nginx:443 auf dem Host")


if __name__ == "__main__":
    unittest.main()
