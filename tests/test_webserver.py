"""Webserver-Konfiguration (nginx, Apache), veröffentlichte Ports, Backends in anderen Containern."""
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
    }
}
"""


class NginxVariablen(unittest.TestCase):
    def test_set_und_map_werden_aufgeloest(self):
        w = web(docroots=scanner.defaultdict(list), backends=scanner.defaultdict(list),
                vhosts=scanner.defaultdict(list), upstreams=scanner.defaultdict(list))
        scanner.parse_nginx(NGINX_VARIABLEN, w, "/usr/sbin/nginx")
        self.assertEqual(w["backends"]["/usr/sbin/nginx"], [
            "http://app:3000", "http://api:8000", "http://app-a:3000", "http://app-b:3000", "http://$host"])

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
        self.assertEqual(w["vhosts"]["/usr/sbin/apache2"],
                         ["VirtualHost *:80 ServerName shop.example.org DocumentRoot /var/www/html/public"])


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


if __name__ == "__main__":
    unittest.main()
