"""Welcher laufende Dienst nutzt welche Komponente – Grundlage der Priorität P1–P4."""
import unittest

from _laden import scanner, proc, web


def C(*a, **kw):
    return scanner.comp(*a, **kw)


class Zuordnung(unittest.TestCase):
    def test_os_paket_ueber_geladene_bibliothek(self):
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"}, maps={"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
        cron = proc(2, "/usr/sbin/cron", maps={"/lib/x86_64-linux-gnu/libssl.so.3"})
        ssl, zlib = C("os-paket", "libssl3", "3.0"), C("os-paket", "zlib1g", "1.2")
        scanner.mark_usage([ssl, zlib], {"1": nginx, "2": cron}, {"/lib/x86_64-linux-gnu/libssl.so.3": {"libssl3"}}, web())
        self.assertEqual((ssl["aktiv"], ssl["aktiv_ohne_port"]), (["nginx:80"], ["cron (ohne Port)"]))
        self.assertEqual((zlib["aktiv"], zlib["aktiv_ohne_port"]), ([], []))

    def test_npm_ueber_arbeitsverzeichnis_oder_skript(self):
        node = proc(1, "/usr/local/bin/node", ["node", "dist/server.js"], cwd="/app", ports={"3000": "alle"})
        worker = proc(2, "/usr/local/bin/node", ["node", "/srv/worker/index.js"])
        a = C("npm", "express", "4.0", "/app/node_modules/express")
        b = C("npm", "bull", "4.0", "/srv/worker/node_modules/bull")
        npm = C("npm", "npm", "10.0", "/usr/local/lib/node_modules/npm")
        andere = C("npm", "left-pad", "1.0", "/opt/other/node_modules/left-pad")
        scanner.mark_usage([a, b, npm, andere], {"1": node, "2": worker}, {}, web())
        self.assertEqual(a["aktiv"], ["node:3000"])
        self.assertEqual(b["aktiv_ohne_port"], ["node (ohne Port)"])
        self.assertEqual((npm["aktiv"], andere["aktiv"]), ([], []))

    def test_composer_und_js_ueber_docroot(self):
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        fpm = proc(2, "/usr/local/sbin/php-fpm", ports={"9000": "alle"})
        w = web(docroots={"/usr/sbin/nginx": ["/var/www/public"]}, backends={"/usr/sbin/nginx": ["127.0.0.1:9000"]})
        lara = C("composer", "laravel/framework", "10.0", "/var/www")
        jq = C("js-lib", "jquery", "1.10.2", "/var/www/public/js/jquery.min.js")
        fremd = C("composer", "x/y", "1.0", "/opt/tool")
        services = scanner.mark_usage([lara, jq, fremd], {"1": nginx, "2": fpm}, {}, w)
        self.assertEqual(set(lara["aktiv"]), {"nginx:80", "php-fpm:9000", "nginx:80 (über php-fpm)"})
        self.assertIn("nginx:80", jq["aktiv"])
        self.assertEqual(fremd["aktiv"], [])
        fpm_dienst = [s for s in services if s["name"] == "php-fpm"][0]
        self.assertIn("hinter nginx:80 (gleicher Container)", fpm_dienst["description"])

    def test_docroot_unbekannt(self):
        fpm = proc(1, "/usr/local/sbin/php-fpm", ports={"9000": "alle"})
        nginx = proc(2, "/usr/sbin/nginx", ports={"80": "alle"})
        lara = C("composer", "laravel/framework", "10.0", "/var/www")
        jq = C("js-lib", "jquery", "1.10.2", "/srv/jquery.js")
        scanner.mark_usage([lara, jq], {"1": fpm, "2": nginx}, {}, web())
        self.assertEqual(lara["aktiv"], ["php-fpm:9000 (Docroot unbekannt)"])
        self.assertEqual(jq["aktiv"], ["nginx:80 (Docroot unbekannt)"])

    def test_laufzeit_maven_go(self):
        java = proc(1, "/opt/java/bin/java", ports={"8080": "alle"}, files={"/app/lib/log4j-core.jar"})
        gosvc = proc(2, "/usr/local/bin/app", ports={"9090": "alle"})
        rt = C("runtime", "java", "17.0.1", "/opt/java/bin/java")
        log4j = C("maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "/app/lib/log4j-core.jar!/x.jar")
        gomod = C("go", "golang.org/x/net", "v0.1.0", "/usr/local/bin/app")
        scanner.mark_usage([rt, log4j, gomod], {"1": java, "2": gosvc}, {}, web())
        self.assertEqual((rt["aktiv"], log4j["aktiv"], gomod["aktiv"]), (["java:8080"], ["java:8080"], ["app:9090"]))

    def test_pypi_ueber_venv_path_und_systempfad(self):
        gunicorn = proc(1, "/usr/local/bin/python3.12", ["/opt/venv/bin/python", "-m", "gunicorn"], ports={"8000": "alle"})
        via_path = proc(2, "/usr/bin/python3.11", ["python", "app.py"],
                        env={"PATH": "/srv/env/bin:/usr/bin"}, ports={"8001": "alle"})
        system = proc(3, "/usr/local/bin/python3.12", ["python3", "job.py"])
        a = C("pypi", "django", "4.2", "/opt/venv/lib/python3.12/site-packages")
        b = C("pypi", "flask", "3.0", "/srv/env/lib/python3.11/site-packages")
        s = C("pypi", "requests", "2.0", "/usr/local/lib/python3.12/site-packages")
        scanner.mark_usage([a, b, s], {"1": gunicorn, "2": via_path, "3": system}, {}, web(venvs={"/srv/env"}))
        self.assertEqual(a["aktiv"], ["python3.12:8000"])
        self.assertEqual(b["aktiv"], ["python3.11:8001"])
        self.assertEqual(s["aktiv_ohne_port"], ["python3.12 (ohne Port)"])


class Dienste(unittest.TestCase):
    def dienst(self, p, **kw):
        return scanner.mark_usage([], {"1": p}, {}, web(**kw))[0]

    def test_erreichbarkeit(self):
        p = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        self.assertTrue(self.dienst(p, published={"80": ["0.0.0.0:8080"]})["exposed"])
        self.assertTrue(self.dienst(p, host_network=True)["exposed"])
        self.assertTrue(self.dienst(p, via_proxy={"80": ["nginx:443 in proxy"]})["exposed"])
        self.assertFalse(self.dienst(p)["exposed"])
        lokal = proc(1, "/usr/sbin/nginx", ports={"80": "localhost"})
        self.assertFalse(self.dienst(lokal, host_network=True)["exposed"])

    def test_endpunkte_und_backends_anderer_container(self):
        p = proc(1, "/usr/sbin/nginx", ports={"80": "alle", "53/udp": "alle"})
        s = self.dienst(p, published={"80": ["0.0.0.0:8080"], "53/udp": ["0.0.0.0:53"]},
                        backends={"/usr/sbin/nginx": ["http://app-api:8000", "http://gone:1", "unix:/run/x.sock"]},
                        containers={"app-api": "app-api"})
        self.assertEqual(s["endpoints"], ["tcp://0.0.0.0:8080", "udp://0.0.0.0:53"])
        self.assertEqual(s["backends"], [("app-api", "8000", "nginx:80,53/udp")])
        self.assertEqual(s["unresolved"], ["http://gone:1", "unix:/run/x.sock"])

    def test_nur_lokal_lauschend_nur_ueber_gemeinsames_loopback(self):
        # Proxy mit demselben Loopback (z.B. nginx auf dem Host vor einem Container im Host-Netzwerk mit
        # proxy_pass http://127.0.0.1:7777): erreichbar
        p = proc(1, "/usr/local/bin/node", ports={"7777": "localhost"})
        s = self.dienst(p, host_network=True, via_proxy={"7777": ["nginx:443 auf dem Host (über Loopback)"]})
        self.assertTrue(s["exposed"])
        self.assertIn("Port 7777/tcp (localhost) lauscht nur auf Loopback, öffentlich über nginx:443 auf dem Host "
                      "(über Loopback)", s["description"])
        s = self.dienst(p, via_proxy={"*": ["traefik:443 in proxy (über Loopback)"]})
        self.assertTrue(s["exposed"])
        self.assertIn("lauscht nur auf Loopback, möglicherweise öffentlich über", s["description"])
        # Datenbank als Ziel eines Aufrufs zählt auch über Loopback nicht
        db = proc(1, "/usr/sbin/mysqld", ports={"3306": "localhost"})
        self.assertFalse(self.dienst(db, via_proxy={"3306": ["node:3000 (offene Verbindung) in app (über Loopback)"]})
                         ["exposed"])

    def test_nur_lokal_lauschend_sonst_nie_erreichbar(self):
        # Docker-Portweiterleitung und Proxys ohne dasselbe Loopback erreichen Loopback nicht
        for addr in ("localhost", "127.0.0.11"):
            p = proc(1, "/usr/sbin/nginx", ports={"80": addr})
            self.assertFalse(self.dienst(p, host_network=True)["exposed"], addr)
            self.assertFalse(self.dienst(p, lan=["macvlan-Netz mv"])["exposed"], addr)
            self.assertFalse(self.dienst(p, via_proxy={"*": ["traefik:443 in proxy"]})["exposed"], addr)
            self.assertFalse(self.dienst(p, via_proxy={"80": ["nginx:443 in proxy"]})["exposed"], addr)
            s = self.dienst(p, published={"80": ["0.0.0.0:8080"]})
            self.assertFalse(s["exposed"], addr)
            self.assertIn("lauscht nur auf Loopback – von außen nicht erreichbar (obwohl veröffentlicht als "
                          "0.0.0.0:8080)", s["description"])

    def test_lan_netz_und_spender(self):
        p = proc(1, "/usr/local/bin/node", ports={"3000": "alle"})
        s = self.dienst(p, lan=["macvlan-Netz mv"])
        self.assertTrue(s["exposed"])
        self.assertIn("direkt erreichbar im macvlan-Netz mv", s["description"])
        s = self.dienst(p, published={"3000": ["0.0.0.0:3000"]}, spender="vpn")
        self.assertIn("veröffentlicht als 0.0.0.0:3000 (über Container vpn)", s["description"])

    def test_moeglicherweise_erreichbar_ueber_unklaren_proxy(self):
        p = proc(1, "/usr/local/bin/node", ports={"3000": "alle"})
        s = self.dienst(p, via_proxy={"*": ["traefik:443 in proxy"]})
        self.assertTrue(s["exposed"])
        self.assertIn("möglicherweise öffentlich über traefik:443 in proxy", s["description"])
        # genaue Zuordnung hat Vorrang
        s = self.dienst(p, via_proxy={"*": ["traefik:443 in proxy"], "3000": ["traefik:443 in proxy"]})
        self.assertIn("Port 3000/tcp (alle) öffentlich über", s["description"])

    def test_unbekannter_proxy_macht_nachbarn_erreichbar(self):
        traefik = proc(1, "/usr/local/bin/traefik", ports={"443": "alle"})
        s = self.dienst(traefik, published={"443": ["0.0.0.0:443"]}, nachbarn=["shop", "db"],
                        label_ziele={"traefik": [("shop", "8080")]})
        self.assertEqual(s["unklar"], ["traefik: Konfiguration wird nicht ausgewertet"])
        self.assertEqual(s["backends"], [("shop", "8080", "traefik:443"), ("shop", "*", "traefik:443"),
                                         ("db", "*", "traefik:443")])
        self.assertIn("Ziel aus Docker-Labels: Container shop, Port 8080", s["description"])
        # nicht erreichbar: keine Weitergabe
        s = self.dienst(traefik, nachbarn=["shop", "db"])
        self.assertEqual((s["unklar"], s["backends"]), ([], []))

    def test_variables_ziel_macht_nachbarn_erreichbar(self):
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        s = self.dienst(nginx, published={"80": ["0.0.0.0:80"]}, nachbarn=["shop"], containers={"api": "api"},
                        backends={"/usr/sbin/nginx": ["http://api:8000", "http://$host"]})
        self.assertEqual(s["unklar"], ["Ziel http://$host"])
        self.assertEqual(s["unresolved"], [])          # nicht zusätzlich als "keinem Container zuordenbar"
        self.assertEqual(s["backends"], [("api", "8000", "nginx:80"), ("shop", "*", "nginx:80")])
        # vollständig ausgewertet: nur die genauen Ziele
        s = self.dienst(nginx, published={"80": ["0.0.0.0:80"]}, nachbarn=["shop"], containers={"api": "api"},
                        backends={"/usr/sbin/nginx": ["http://api:8000"]})
        self.assertEqual((s["unklar"], s["backends"]), ([], [("api", "8000", "nginx:80")]))

    def test_nginx_konfiguration_unlesbar_macht_nachbarn_erreichbar(self):
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        s = self.dienst(nginx, published={"80": ["0.0.0.0:80"]}, nachbarn=["shop"], unlesbar={"/usr/sbin/nginx"})
        self.assertEqual(s["backends"], [("shop", "*", "nginx:80")])

    def test_tunnel_ohne_port_ist_erreichbar(self):
        tunnel = proc(1, "/usr/local/bin/cloudflared", ["cloudflared", "tunnel", "run"])
        s = self.dienst(tunnel, nachbarn=["shop"])
        self.assertTrue(s["exposed"])
        self.assertEqual(s["backends"], [("shop", "*", "cloudflared")])
        self.assertIn("Tunnel-Agent", s["description"])
        # seine Komponenten: P1, nicht P3 ("ohne Port")
        gomod = C("go", "golang.org/x/net", "v0.1.0", "/usr/local/bin/cloudflared")
        services = scanner.mark_usage([gomod], {"1": tunnel}, {}, web(nachbarn=["shop"]))
        self.assertEqual(gomod["aktiv"], ["cloudflared"])
        self.assertEqual(scanner.priority(gomod, {s["label"] for s in services if s["exposed"]}), 1)

    def test_unbekannter_proxy_hinter_webserver_im_selben_container(self):
        # nginx (erreichbar) -> HAProxy auf 127.0.0.1:8080 im selben Container: HAProxy-Ziele nicht bekannt
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        haproxy = proc(2, "/usr/sbin/haproxy", ports={"8080": "localhost"})
        w = web(published={"80": ["0.0.0.0:80"]}, backends={"/usr/sbin/nginx": ["http://127.0.0.1:8080"]},
                nachbarn=["shop"])
        services = scanner.mark_usage([], {"1": nginx, "2": haproxy}, {}, w)
        ha = [s for s in services if s["name"] == "haproxy"][0]
        self.assertFalse(ha["exposed"])
        self.assertEqual(ha["unklar"], ["haproxy: Konfiguration wird nicht ausgewertet"])
        self.assertEqual(ha["backends"], [("shop", "*", "haproxy:8080")])

    def test_mehrstufig_im_selben_container_bzw_host(self):
        # nginx (erreichbar) -> Apache auf 127.0.0.1:8080 -> php-fpm auf 127.0.0.1:9000: was php-fpm nutzt, ist
        # über nginx erreichbar (P1), nicht nur über den nicht erreichbaren Apache
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        apache = proc(2, "/usr/sbin/httpd-prefork", ports={"8080": "localhost"})
        fpm = proc(3, "/usr/sbin/php-fpm", ports={"9000": "localhost"}, maps={"/usr/lib64/libxml2.so.2"})
        w = web(published={"80": ["0.0.0.0:80"]}, backends={"/usr/sbin/nginx": ["http://127.0.0.1:8080"],
                                                            "/usr/sbin/httpd-prefork": ["fcgi://127.0.0.1:9000"]})
        xml = C("os-paket", "libxml2-2", "2.10")
        services = scanner.mark_usage([xml], {"1": nginx, "2": apache, "3": fpm},
                                      {"/lib64/libxml2.so.2": {"libxml2-2"}}, w)
        self.assertEqual(fpm["frontends"], ["httpd-prefork:8080", "nginx:80"])
        self.assertEqual(scanner.priority(xml, {s["label"] for s in services if s["exposed"]}), 1)
        self.assertIn("hinter httpd-prefork:8080, nginx:80 (gleicher Container)",
                      [s for s in services if s["name"] == "php-fpm"][0]["description"])
        self.assertEqual(scanner.nutzer_text(xml), "php-fpm:9000, httpd-prefork:8080 (über php-fpm), "
                                                   "nginx:80 (über php-fpm)")
        w["ist_host"] = True
        nginx.pop("frontends", None), apache.pop("frontends", None), fpm.pop("frontends", None)
        services = scanner.mark_usage([], {"1": nginx, "2": apache, "3": fpm}, {}, w)
        self.assertIn("(gleicher Host)", [s for s in services if s["name"] == "php-fpm"][0]["description"])

    def test_php_fpm_ueber_unix_socket(self):
        # php-fpm ohne TCP-Port hinter dem erreichbaren nginx: offene Verbindungen der Worker zählen
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        fpm = proc(2, "/usr/local/sbin/php-fpm", verbindungen=[("10.0.0.3", "8080")])
        w = web(published={"80": ["0.0.0.0:80"]}, backends={"/usr/sbin/nginx": ["unix:/run/php/php-fpm.sock"]},
                containers={"10.0.0.3": "intern"})
        services = scanner.mark_usage([], {"1": nginx, "2": fpm}, {}, w)
        self.assertEqual([b for s in services for b in s["backends"]], [("intern", "8080", "php-fpm (offene Verbindung)")])

    def test_ziel_urls_und_verbindungen_einer_erreichbaren_anwendung(self):
        # API-Gateway: Ziele in der Umgebung (nur HTTP/WS/gRPC, auch mit Zugangsdaten) und offene Verbindungen
        gw = proc(1, "/usr/local/bin/node", ["node", "/app/gw.js", "--upstream=http://orders:8080"],
                  ports={"3000": "alle"}, verbindungen=[("172.18.0.7", "9000"), ("172.18.0.9", "5432")])
        env = [("API_URL", "https://user:geheim@api:8443/v1"), ("DATABASE_URL", "mysql://db:3306/x"),
               ("EXTERN", "https://example.com"), ("SELBST", "http://localhost:3000"), ("ZWEI", "http://a:1,http://b")]
        containers = {"orders": "orders", "api": "api", "db": "db", "a": "a", "b": "b",
                      "172.18.0.7": "billing", "172.18.0.9": "db", "localhost": "app"}
        s = self.dienst(gw, published={"3000": ["0.0.0.0:3000"]}, env=env, containers=containers)
        self.assertEqual(s["backends"], [
            ("orders", "8080", "node:3000 (Ziel-URL in der Kommandozeile)"), ("api", "8443", "node:3000 (Ziel-URL API_URL)"),
            ("a", "1", "node:3000 (Ziel-URL ZWEI)"), ("b", "80", "node:3000 (Ziel-URL ZWEI)"),
            ("billing", "9000", "node:3000 (offene Verbindung)"), ("db", "5432", "node:3000 (offene Verbindung)")])
        self.assertIn("Aufruf: Container api, Port 8443 (Ziel-URL API_URL)", s["description"])
        self.assertNotIn("geheim", s["description"])
        # nicht erreichbar: keine Weitergabe
        self.assertEqual(self.dienst(gw, env=env, containers=containers)["backends"], [])

    def test_aufrufe_hinter_webserver_im_selben_container(self):
        # php-fpm hinter dem erreichbaren nginx: Verbindungen der Worker zählen; die Umgebung nur einmal
        nginx = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        master = proc(2, "/usr/local/sbin/php-fpm", ports={"9000": "alle"})
        worker = proc(3, "/usr/local/sbin/php-fpm", ports={"9000": "alle"}, verbindungen=[("10.0.0.3", "8080")], ppid=2)
        w = web(published={"80": ["0.0.0.0:80"]}, backends={"/usr/sbin/nginx": ["127.0.0.1:9000"]},
                containers={"10.0.0.3": "intern", "api": "api"}, env=[("API", "http://api:8000")])
        services = scanner.mark_usage([], {"1": nginx, "2": master, "3": worker}, {}, w)
        alle = [b for s in services for b in s["backends"]]
        self.assertEqual(alle, [("api", "8000", "nginx:80 (Ziel-URL API)"),
                                ("intern", "8080", "php-fpm:9000 (offene Verbindung)")])

    def test_datendienste_durch_aufrufe_nicht_erreichbar(self):
        for p in (proc(1, "/usr/bin/redis-server", ports={"6379": "alle"}),
                  proc(1, "/opt/java/bin/java", ["java", "-Dsolr.solr.home=/var/solr", "-jar", "start.jar"],
                       ports={"8983": "alle"})):
            port = list(p["ports"])[0]
            s = self.dienst(p, via_proxy={port: ["node:3000 (offene Verbindung) in gw"]})
            self.assertFalse(s["exposed"], p["base"])
            self.assertIn("aufgerufen von node:3000 (offene Verbindung) in gw", s["description"])
            # hinter einem Proxy weiterhin erreichbar
            self.assertTrue(self.dienst(p, via_proxy={port: ["nginx:80 in proxy"]})["exposed"])
        node = proc(1, "/usr/local/bin/node", ports={"8080": "alle"})
        self.assertTrue(self.dienst(node, via_proxy={"8080": ["node:3000 (Ziel-URL API_URL) in gw"]})["exposed"])

    def test_beschreibung(self):
        p = proc(1, "/usr/local/bin/node", ["node", "/app/server.js"], cwd="/app", ports={"3000": "alle"})
        s = self.dienst(p)
        self.assertIn("Anwendung: /app/server.js", s["description"])
        self.assertIn("Arbeitsverzeichnis: /app", s["description"])
        self.assertIn("Port 3000/tcp (alle) nicht veröffentlicht", s["description"])


class Prioritaet(unittest.TestCase):
    def test_stufen(self):
        c = C("npm", "a", "1")
        self.assertEqual(scanner.priority(c, {"nginx:80"}), 4)
        c["aktiv_ohne_port"].append("cron (ohne Port)")
        self.assertEqual(scanner.priority(c, {"nginx:80"}), 3)
        c["aktiv"].append("node:3000")
        self.assertEqual(scanner.priority(c, {"nginx:80"}), 2)
        c["aktiv"].append("nginx:80 (über php-fpm)")
        self.assertEqual(scanner.priority(c, {"nginx:80"}), 1)
        c["dev"] = True
        self.assertEqual(scanner.priority(c, {"nginx:80"}), 4)

    def test_nutzer_text(self):
        c = C("composer", "a", "1")
        c["aktiv"] = ["php-fpm:9000", "httpd:8080 (über php-fpm)", "nginx:80 (über php-fpm)", "httpd:8080",
                      "nginx:80 (über httpd)"]
        self.assertEqual(scanner.nutzer_text(c), "php-fpm:9000, nginx:80 (über php-fpm), httpd:8080")
        self.assertEqual(scanner.nutzer_text(C("npm", "b", "1")), "–")

    def test_npm_root(self):
        self.assertEqual(scanner.npm_root("/app/node_modules/express"), "/app")
        self.assertEqual(scanner.npm_root("/usr/local/lib/node_modules/npm/node_modules/semver"),
                         "/usr/local/lib/node_modules/npm")
        self.assertEqual(scanner.npm_root("/usr/lib/node_modules/@scope/cli"), "/usr/lib/node_modules/@scope/cli")
        self.assertEqual(scanner.npm_root("/app"), "/app")


if __name__ == "__main__":
    unittest.main()
