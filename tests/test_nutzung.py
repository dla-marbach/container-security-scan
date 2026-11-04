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

    def test_npm_root(self):
        self.assertEqual(scanner.npm_root("/app/node_modules/express"), "/app")
        self.assertEqual(scanner.npm_root("/usr/local/lib/node_modules/npm/node_modules/semver"),
                         "/usr/local/lib/node_modules/npm")
        self.assertEqual(scanner.npm_root("/usr/lib/node_modules/@scope/cli"), "/usr/lib/node_modules/@scope/cli")
        self.assertEqual(scanner.npm_root("/app"), "/app")


if __name__ == "__main__":
    unittest.main()
