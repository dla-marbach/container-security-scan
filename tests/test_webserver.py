"""Webserver-Konfiguration (nginx, Apache), veröffentlichte Ports, Backends in anderen Containern."""
import io
import json
import os
import shutil
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
            ziele, services, warnings, problems = scanner.host_proxys(infos)
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
            ziele, services, warnings, problems = scanner.host_proxys(infos + [hostnetz])
        self.assertEqual(ziele, [("hostnetz", "7777", "nginx:443 auf dem Host (über Loopback)")])
        self.assertIn("Backend http://127.0.0.1:7777 (Host; Loopback gemeinsam mit hostnetz)", services[0]["description"])
        self.assertEqual((warnings, problems), ([], []))
        # variables Ziel: alle Container mit Docker-Netz möglicherweise erreichbar
        conf = "http { server { listen 443; location / { proxy_pass http://$host; } } }"
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10"], 2)), \
                mock.patch.object(scanner, "run", return_value=(0, procs)), \
                mock.patch.object(scanner.Host, "exec", return_value=(0, conf)):
            ziele, services, warnings, problems = scanner.host_proxys(infos)
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
            ziele, services, warnings, problems = scanner.host_proxys(infos)
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



SLES_ARGV = ["/usr/sbin/httpd-prefork", "-DSYSCONFIG", "-C", "PidFile /run/httpd.pid", "-C",
             "Include /etc/apache2/sysconfig.d//loadmodule.conf", "-f", "/etc/apache2/httpd.conf", "-c",
             "Include /etc/apache2/sysconfig.d//include.conf", "-DFOREGROUND", "-k", "start"]


class ApacheSles(unittest.TestCase):
    def test_programmnamen(self):
        for name in ("apache2", "httpd", "httpd-prefork", "httpd2-worker", "httpd-event"):
            self.assertTrue(scanner.ist_apache(name) and scanner.ist_webserver(name), name)
        self.assertFalse(scanner.ist_apache("httpd-helper"))
        self.assertTrue(scanner.ist_webserver("nginx"))
        self.assertIn("httpd-prefork", scanner.HOST_PROXYS)

    def test_optionen_des_hauptprozesses(self):
        # ohne sie zeigen -S/-M eine andere Konfiguration (ohne die Module aus /etc/sysconfig/apache2)
        self.assertEqual(scanner.apache_optionen(SLES_ARGV), SLES_ARGV[1:11])
        self.assertEqual(scanner.apache_optionen(["apache2", "-k", "start"]), [])
        c = mock.Mock(has_sh=False, info={"Config": {"Env": []}, "HostConfig": {}, "NetworkSettings": {}})
        c.exec.return_value = (0, "")
        c.read_file.return_value = ""
        procs = {"1": proc(1, "/usr/sbin/httpd-prefork", SLES_ARGV),
                 "2": proc(2, "/usr/sbin/httpd-prefork", SLES_ARGV, user="30:8", ppid=1)}
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            scanner.collect_web(c, procs)
        self.assertEqual([x[0][0] for x in c.exec.call_args_list],
                         [["/usr/sbin/httpd-prefork"] + SLES_ARGV[1:11] + a
                          for a in (["-S"], ["-M"], ["-t", "-D", "DUMP_INCLUDES"])])

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

    def apache(self, dateien, s_out, m_out=" status_module (shared)\n autoindex_module (shared)\n", host=False):
        c = scanner.Host() if host else mock.Mock(has_sh=False, info={"Config": {"Env": []}})
        antworten = {"-S": (0, s_out), "-M": (0, m_out),
                     "-t": (0, "Included configuration files:\n" + "".join("  (*) %s\n" % d for d in dateien))}
        w = scanner.web_leer()
        with mock.patch.object(c, "exec", side_effect=lambda cmd, **kw: antworten[next(x for x in cmd if x in antworten)]), \
                mock.patch.object(c, "read_file", side_effect=lambda p: dateien[p]):
            scanner.parse_apache(c, "/usr/sbin/httpd-prefork", w)
        return w

    def test_websites_status_und_verzeichnislisten(self):
        dateien = {"/etc/apache2/httpd.conf": """Listen 80
<IfDefine SSL>
    Listen 443
</IfDefine>
ServerName web01.example.com
<Directory "/usr/share/apache2/icons">
    Options Indexes MultiViews
</Directory>
<Location /server-status>
    SetHandler server-status
</Location>
<Location /server-status>
    Require local
</Location>
""", "/etc/apache2/vhosts.d/www.conf": """
<VirtualHost *:443>
    ServerName https://www.example.org:443
    ServerAlias example.org
    SSLEngine on
    DocumentRoot /srv/www/htdocs
    <Directory /srv/www/htdocs/downloads>
        Options +Indexes
    </Directory>
    ProxyPass /api/ http://127.0.0.1:3000/ \\
        retry=0
    <Location /info>
        SetHandler server-info
    </Location>
</VirtualHost>
"""}
        s_out = "VirtualHost configuration:\n*:443                  www.example.org (/etc/apache2/vhosts.d/www.conf:2)\n"
        w = self.apache(dateien, s_out, " status_module (shared)\n autoindex_module (shared)\n info_module (shared)\n")
        www, haupt = w["sites"]
        self.assertEqual((www["namen"], www["listen"], www["roots"]), (
            ["www.example.org"], [{"adresse": "*", "port": "443", "ssl": True}], ["/srv/www/htdocs"]))
        self.assertEqual(www["weiter"], [("/api/", "http://127.0.0.1:3000/")])      # Fortsetzungszeile
        self.assertEqual((haupt["namen"], haupt["listen"]), (["web01.example.com"], [
            {"adresse": "*", "port": "80", "ssl": False}]))       # 443 gehört dem vHost
        konf = {(k["id"], k["pfad"], k.get("nur_lokal")) for k in w["web_konf"]}
        # Symbole aus dem Paket: kein Fund; server-status nur lokal (zwei Location-Blöcke), server-info offen
        self.assertEqual(konf, {("WEB-AUTOINDEX", "/", None), ("WEB-STATUS", "/server-status", True),
                                ("WEB-STATUS", "/info", False)})
        idx = next(k for k in w["web_konf"] if k["id"] == "WEB-AUTOINDEX")
        self.assertEqual((idx["verzeichnis"], idx["site"]), ("/srv/www/htdocs/downloads", www))
        # Modul nicht geladen: kein Fund
        w = self.apache(dateien, s_out, " ssl_module (shared)\n")
        self.assertEqual(w["web_konf"], [])

    def test_verzeichnis_nicht_vorhanden(self):
        # SLES-Vorgabe mod_userdir: /home/*/public_html mit Indexes – auf dem Host nur, wenn es das Verzeichnis gibt
        dateien = {"/etc/apache2/mod_userdir.conf": "<Directory /home/*/public_html>\n Options MultiViews Indexes\n"
                                                    "</Directory>\n"}
        with mock.patch.object(scanner.glob, "glob", return_value=[]):
            self.assertEqual(self.apache(dateien, "", host=True)["web_konf"], [])
        with mock.patch.object(scanner.glob, "glob", return_value=["/home/anna/public_html"]):
            self.assertEqual(len(self.apache(dateien, "", host=True)["web_konf"]), 1)


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
    server_name www.example.org .example.net ~^(?<sub>.+)\\.example\\.com$;
    root /srv/www/htdocs;
    location /app/ { proxy_pass http://127.0.0.1:8080/; }
    location ~ \\.php$ { fastcgi_pass unix:/run/php-fpm.sock; }
    location /nginx_status { stub_status; }
    location /intern_status { stub_status; allow 127.0.0.1; deny all; }
    location /dateien/ { autoindex on; }
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

    def test_einstellungen(self):
        konf = [(k["id"], k["pfad"]) for k in self.w["web_konf"]]
        self.assertEqual(konf, [("WEB-AUTOINDEX", "/dateien/"), ("WEB-STATUS", "/nginx_status")])

    def test_webadressen_einer_site(self):
        www = self.w["sites"][1]
        self.w["fqdn"] = "web01.example.com"
        self.assertEqual(scanner.site_urls(www, self.w), [
            "http://www.example.org/", "http://example.net/", "http://*.example.net/", "https://www.example.org/",
            "https://example.net/", "https://*.example.net/", "https://www.example.org:8443/",
            "https://example.net:8443/", "https://*.example.net:8443/"])
        # ohne Namen: Name des Hosts; im Container: veröffentlichter Port statt des Ports im Container
        self.assertEqual(scanner.site_urls(self.w["sites"][2], self.w), ["https://web01.example.com:8080/"])
        w = web(published={"8080": ["0.0.0.0:18080", "127.0.0.1:9000 (nur lokal – vermutlich hinter …)"]})
        self.assertEqual(scanner.site_urls(self.w["sites"][2], w), ["https://*:18080/"])
        self.assertEqual(scanner.url_pfad("https://a/", "/app/"), "https://a/app/")
        self.assertEqual(scanner.url_pfad("https://a/", "= /x"), "https://a/x")
        self.assertEqual(scanner.url_pfad("https://a/", "~* \\.php$"), "https://a/ (\\.php$)")


def dienst(label, exe, ports, exposed=False, frontends=()):
    return {"label": label, "name": os.path.basename(exe), "exe": exe, "exposed": exposed, "frontends": list(frontends),
            "ports": scanner.OrderedDict((p, ("…", exposed)) for p in ports), "backends": [], "unresolved": [],
            "unklar": [], "endpoints": [], "description": ""}


class Webadressen(unittest.TestCase):
    """nginx (öffentlich) -> Apache (Loopback) -> php-fpm auf demselben Host."""

    def setUp(self):
        self.w = web(self="Host", ist_host=True, fqdn="web01.example.com",
                     sites=[{"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["www.example.org"], "datei": "www.conf",
                             "roots": ["/srv/www/htdocs"], "listen": [{"adresse": "*", "port": "443", "ssl": True}],
                             "weiter": [("/app/", "http://127.0.0.1:8080/"), ("/api/", "http://10.0.0.7:3000/")]},
                            {"exe": "/usr/sbin/httpd-prefork", "art": "apache", "namen": ["app.example.org"],
                             "datei": "app.conf:1", "roots": ["/srv/www/app/public"],
                             "listen": [{"adresse": "127.0.0.1", "port": "8080", "ssl": False}],
                             "weiter": [("~ \\.php$", "fcgi://127.0.0.1:9000")]}])
        self.services = [dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True),
                         dienst("httpd-prefork:8080", "/usr/sbin/httpd-prefork", ["8080"], frontends=["nginx:443"]),
                         dienst("php-fpm:9000", "/usr/sbin/php-fpm", ["9000"], frontends=["httpd-prefork:8080"])]
        scanner.webadressen(self.services, self.w)

    def urls(self, i):
        return [(e["url"], e["erreichbar"]) for e in self.services[i]["webadressen"]]

    def test_kette(self):
        self.assertEqual(self.urls(0), [("https://www.example.org/", True)])
        self.assertEqual(self.urls(1), [("https://www.example.org/app/", True), ("http://app.example.org:8080/", False)])
        self.assertEqual(self.urls(2), [("https://www.example.org/app/ (\\.php$)", True),
                                        ("http://app.example.org:8080/ (\\.php$)", False)])
        self.assertEqual(self.services[2]["webadressen"][0]["weg"], "nginx:443 → httpd-prefork:8080 → php-fpm:9000")

    def test_ziele_in_containern(self):
        # nginx auf dem Host leitet Pfade an Container weiter (veröffentlichter Port auf Loopback bzw. Container-IP):
        # deren Webadressen gehen an den Scan des Containers, mit dem Port im Container
        w = dict(self.w, containers={"172.18.0.5": "api"}, loopback_ziele={("127.0.0.1", "7776"): [("regdido", "3000")]})
        w["sites"] = [dict(w["sites"][0], weiter=[("/regdido/", "http://127.0.0.1:7776/"),
                                                  ("/api/", "http://172.18.0.5:8080")])]
        services = [dienst("nginx:443", "/usr/sbin/nginx", ["443"], exposed=True)]
        scanner.webadressen(services, w)
        self.assertEqual(list(w["ziel_urls"]), [("regdido", "3000"), ("api", "8080")])
        self.assertEqual(w["ziel_urls"][("regdido", "3000")], [
            {"url": "https://www.example.org/regdido/", "erreichbar": True, "weg": "nginx:443 auf dem Host"}])
        # im Scan des Containers: Webadressen des Dienstes an diesem Port
        node = dienst("node:3000", "/usr/local/bin/node", ["3000"], exposed=True)
        cw = web(self="regdido", via_urls={"3000": w["ziel_urls"][("regdido", "3000")]})
        scanner.webadressen([node], cw)
        self.assertEqual([(e["url"], e["erreichbar"], e["weg"]) for e in node["webadressen"]], [
            ("https://www.example.org/regdido/", True, "nginx:443 auf dem Host → node:3000")])
        self.assertEqual(cw["ziel_urls"], {})

    def test_komponenten(self):
        def C(typ, ort, aktiv):
            c = scanner.comp(typ, "x", "1", ort)
            c["aktiv"] = aktiv
            return c
        js_www = C("js-lib", "/srv/www/htdocs/js/jquery.js", ["nginx:443"])
        js_app = C("js-lib", "/srv/www/app/public/js/jquery.js",
                   ["httpd-prefork:8080", "nginx:443 (über httpd-prefork)", "php-fpm:9000"])
        comp = C("composer", "/srv/www/app", ["php-fpm:9000", "httpd-prefork:8080 (über php-fpm)",
                                             "httpd-prefork:8080", "nginx:443 (über httpd-prefork)"])
        ssl = C("os-paket", "", ["nginx:443"])
        scanner.komponenten_webadressen([js_www, js_app, comp, ssl], self.services)
        self.assertEqual(js_www["webadressen"], ["https://www.example.org/"])
        # nicht die Adressen von php-fpm (nur *.php): php-fpm liefert die Datei nicht aus
        self.assertEqual(js_app["webadressen"], ["https://www.example.org/app/", "http://app.example.org:8080/"])
        self.assertEqual(js_app["webadressen_erreichbar"], ["https://www.example.org/app/"])
        self.assertEqual(comp["webadressen_erreichbar"], ["https://www.example.org/app/"])
        self.assertEqual(ssl["webadressen"], ["https://www.example.org/"])

    def test_einstellungen(self):
        nginx_site, apache_site = self.w["sites"]
        self.w["web_konf"] = [
            {"id": "WEB-STATUS", "exe": "/usr/sbin/httpd-prefork", "site": None, "pfad": "/server-status",
             "nur_lokal": True, "text": "Apache: server-status nur für localhost"},
            {"id": "WEB-AUTOINDEX", "exe": "/usr/sbin/nginx", "site": nginx_site, "pfad": "/dateien/", "text": "x"},
            {"id": "WEB-AUTOINDEX", "exe": "/usr/sbin/httpd-prefork", "site": apache_site, "pfad": "/",
             "verzeichnis": "/srv/www/app/public/downloads", "text": "y"}]
        funde = scanner.webserver_pruefen(self.services, self.w)
        status, idx, idx_apache = funde
        # "nur localhost" hinter einem Proxy auf derselben Maschine: Anfragen kommen von 127.0.0.1
        self.assertTrue(status["erreichbar"])
        self.assertIn("damit greift die Beschränkung nicht", status["text"])
        self.assertIn("https://www.example.org/app/server-status", status["text"])
        self.assertEqual((idx["pkg"], idx["erreichbar"], idx["art"]), ("www.example.org", True, "web"))
        self.assertIn("Webadressen: https://www.example.org/dateien/", idx["text"])
        self.assertIn("http://app.example.org:8080/downloads/", idx_apache["text"])
        # ohne Proxy davor: "nur localhost" ist kein Fund; Webserver nicht erreichbar: zählt nicht
        self.services[0]["ports"]["443"] = ("…", False)
        self.services[0]["exposed"] = False
        scanner.webadressen(self.services, self.w)
        funde = scanner.webserver_pruefen(self.services, self.w)
        self.assertEqual([(k["id"], k["erreichbar"]) for k in funde], [("WEB-AUTOINDEX", False), ("WEB-AUTOINDEX", False)])
        self.assertFalse(scanner.konf_zaehlt(funde[0]))


class Tls(unittest.TestCase):
    def setUp(self):
        self.w = web(self="Host", ist_host=True, sites=[
            {"exe": "/usr/sbin/nginx", "art": "nginx", "namen": ["partner.example.org"], "datei": "p.conf", "roots": [],
             "weiter": [], "listen": [{"adresse": "*", "port": "8443", "ssl": True},
                                      {"adresse": "*", "port": "80", "ssl": False}]}])
        self.services = [dienst("nginx:80,8443", "/usr/sbin/nginx", ["80", "8443"], exposed=True)]
        scanner.webadressen(self.services, self.w)

    def test_alte_versionen_angenommen(self):
        h = mock.Mock()
        h.exec.return_value = (0, '{"TLSv1": "angenommen", "TLSv1.1": "abgelehnt"}')
        funde, warnungen = scanner.tls_pruefen(h, self.services, self.w, python="/usr/bin/python3")
        cmd = h.exec.call_args[0][0]
        self.assertEqual(cmd[:5], ["env", "OPENSSL_CONF=/dev/null", "/usr/bin/python3", "-I", "-c"])
        self.assertEqual(cmd[6:], ["127.0.0.1", "8443", "partner.example.org"])
        self.assertEqual(h.exec.call_args[1]["user"], scanner.NOBODY)
        self.assertEqual(h.exec.call_count, 1)              # nur der TLS-Port
        self.assertEqual(warnungen, [])
        self.assertEqual((funde[0]["id"], funde[0]["pkg"], funde[0]["quelle"]),
                         ("WEB-TLS-ALT", "partner.example.org", "127.0.0.1:8443"))
        self.assertIn("nimmt TLS 1.0 an", funde[0]["text"])
        self.assertIn("https://partner.example.org:8443/", funde[0]["text"])

    def test_abgelehnt_und_nicht_pruefbar(self):
        h = mock.Mock()
        h.exec.return_value = (0, '{"TLSv1": "abgelehnt", "TLSv1.1": "abgelehnt"}')
        self.assertEqual(scanner.tls_pruefen(h, self.services, self.w), ([], []))
        # 127.0.0.1 nicht erreichbar (nur IPv6): dann ::1
        h.exec.side_effect = [(0, '{"TLSv1": "nicht prüfbar: [Errno 111] Connection refused", "TLSv1.1": '
                                  '"nicht prüfbar: [Errno 111] Connection refused"}'),
                              (0, '{"TLSv1": "angenommen", "TLSv1.1": "angenommen"}')]
        funde, _ = scanner.tls_pruefen(h, self.services, self.w)
        self.assertEqual(h.exec.call_args[0][0][6], "::1")
        self.assertIn("TLS 1.0 und TLS 1.1", funde[0]["text"])
        h.exec.side_effect = None
        h.exec.return_value = (0, '{"TLSv1": "nicht prüfbar: NO_PROTOCOLS_AVAILABLE", "TLSv1.1": "abgelehnt"}')
        funde, warnungen = scanner.tls_pruefen(h, self.services, self.w)
        self.assertEqual(funde, [])
        self.assertIn("TLS-Versionen an Port 8443 (nginx:80,8443) nicht prüfbar", warnungen[0])
        # nicht erreichbar: keine Prüfung
        self.services[0]["ports"]["8443"] = ("…", False)
        h.reset_mock()
        self.assertEqual(scanner.tls_pruefen(h, self.services, self.w), ([], []))
        h.exec.assert_not_called()

    def test_pruefprogramm_echt(self):
        # das Prüfprogramm selbst (ohne Server: nicht prüfbar, kein Absturz) – mit diesem Python
        import subprocess
        import sys
        out = subprocess.run([sys.executable, "-I", "-c", scanner.TLS_PRUEFUNG, "127.0.0.1", "9", ""],
                             stdout=subprocess.PIPE, env={"OPENSSL_CONF": "/dev/null"}, timeout=60).stdout
        ergebnis = json.loads(out.decode())
        self.assertEqual(sorted(ergebnis), ["TLSv1", "TLSv1.1"])
        self.assertTrue(all(v.startswith("nicht prüfbar") for v in ergebnis.values()), ergebnis)
        # nur ASCII: mit leerer Umgebung (env -i, ohne LANG) liest Python 3.6 die Kommandozeile sonst nicht
        self.assertTrue(all(ord(c) < 128 for c in scanner.TLS_PRUEFUNG))


if __name__ == "__main__":
    unittest.main()
