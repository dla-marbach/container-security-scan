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
        worker = proc(2, "/usr/sbin/nginx", ["nginx: worker process"])
        with mock.patch.object(scanner, "run", return_value=(0, "")):
            w = scanner.collect_web(c, {"1": master, "2": worker})
            self.assertEqual(w["problems"], [])
            self.assertEqual(c.exec.call_args[0][0], ["/usr/sbin/nginx", "-p", "/srv/", "-c", "conf/nginx.conf", "-T"])
            master["argv"] = ["nginx", "-g", "daemon off;"]
            scanner.collect_web(c, {"1": master})
            self.assertEqual(c.exec.call_args[0][0], ["/usr/sbin/nginx", "-T"])

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


class Backends(unittest.TestCase):
    def setUp(self):
        self.w = web(upstreams={"api": ["app-api:8000", "localhost:9000"]}, containers={"app-api": "app-api", "app": "app"},
                     self="app")

    def test_split_target(self):
        self.assertEqual(scanner.split_target("http://app:3000/x"), ("app", "3000"))
        self.assertEqual(scanner.split_target("https://app"), ("app", "443"))
        self.assertEqual(scanner.split_target("php:9000"), ("php", "9000"))
        self.assertEqual(scanner.split_target("unix:/run/php.sock"), ("", ""))

    def test_backend_containers(self):
        self.assertEqual(scanner.backend_containers("http://api", self.w), [("app-api", "8000"), ("app", "9000")])
        self.assertEqual(scanner.backend_containers("http://unbekannt:1", self.w), [])

    def test_resolve_backend(self):
        self.assertEqual(scanner.resolve_backend("http://app-api:8000", self.w, "app"), "http://app-api:8000 -> Container app-api")
        self.assertEqual(scanner.resolve_backend("http://app:80", self.w, "app"), "http://app:80 (gleicher Container)")
        self.assertEqual(scanner.resolve_backend("unix:/run/php.sock", self.w, "app"), "unix:/run/php.sock (gleicher Container)")
        self.assertEqual(scanner.resolve_backend("http://$host", self.w, "app"), "http://$host (Variable)")
        self.assertEqual(scanner.resolve_backend("http://example.com", self.w, "app"), "http://example.com (extern/unbekannt)")
        self.assertIn("-> Container app-api", scanner.resolve_backend("http://api", self.w, "app"))


if __name__ == "__main__":
    unittest.main()
