"""Inventar: OS-Pakete, Anwendungspakete, eingebettete Bibliotheken, Java- und Go-Programme, tar-Strom."""
import io
import json
import os
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

from _laden import scanner

DPKG_STATUS = b"""Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.15-1~deb12u1)
Version: 3.0.15-1~deb12u1
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0-1

Package: curl
Status: install ok installed
Architecture: amd64
Version: 7.88.1-10+deb12u8
"""

APK_INSTALLED = b"""P:musl
V:1.2.5-r0
A:x86_64
o:musl
m:Timo Teras <timo.teras@iki.fi>
F:lib
R:ld-musl-x86_64.so.1

P:libcrypto3
V:3.3.2-r0
A:x86_64
o:openssl
F:usr/lib
R:libcrypto.so.3
"""

GEMFILE_LOCK = b"""GIT
  remote: https://github.com/example/redmine_git.git
  revision: 0123abc
  specs:
    redmine_git (0.3.0)
      rails (>= 7.0)

PATH
  remote: plugins/my_plugin
  specs:
    my_plugin (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    json (2.7.2)
    net-imap (0.4.10)
      date
    nokogiri (1.16.7)
      racc (~> 1.4)
    nokogiri (1.16.7-aarch64-linux-gnu)
    nokogiri (1.16.7-x86_64-linux-gnu)
    rack (3.1.7)
    rails (7.2.1)
      rack (>= 2.2.4)
    rubocop (1.66.1)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  nokogiri (~> 1.16.0)
  rails (= 7.2.1)

CHECKSUMS
  rack (3.1.7) sha256=abc

BUNDLED WITH
   2.5.18
"""


class OsRelease(unittest.TestCase):
    def test_debian_mit_punktversion(self):
        files = {"/etc/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
                 "/etc/debian_version": b"12.7\n"}
        self.assertEqual(scanner.os_release(files),
                         {"id": "debian", "version": "12.7", "pretty": "Debian GNU/Linux 12 (bookworm)"})

    def test_alpine_und_fallback(self):
        files = {"/usr/lib/os-release": b"ID=alpine\nVERSION_ID=3.20.3\n", "/etc/alpine-release": b"3.20.3\n"}
        self.assertEqual(scanner.os_release(files)["version"], "3.20.3")
        self.assertEqual(scanner.os_release({})["id"], "unbekannt")


class OsPakete(unittest.TestCase):
    def test_dpkg_mit_quellpaket_und_dateizuordnung(self):
        files = {"/var/lib/dpkg/status": DPKG_STATUS,
                 "/var/lib/dpkg/info/libssl3:amd64.list": b"/usr/lib/x86_64-linux-gnu/libssl.so.3\n"}
        pkgs, owners, how = scanner.os_packages(mock.Mock(), files)
        self.assertEqual(how, "dpkg")
        self.assertEqual([(p["name"], p["src"], p["srcver"]) for p in pkgs],
                         [("libssl3", "openssl", "3.0.15-1~deb12u1"), ("curl", "curl", "7.88.1-10+deb12u8")])
        # /usr/lib == /lib (usrmerge)
        self.assertEqual(owners["/lib/x86_64-linux-gnu/libssl.so.3"], {"libssl3"})

    def test_distroless_status_d(self):
        files = {"/var/lib/dpkg/status.d/libc6": b"Package: libc6\nVersion: 2.36-9+deb12u9\nSource: glibc\n",
                 "/var/lib/dpkg/status.d/libc6.md5sums": b"abc  lib/x86_64-linux-gnu/libc.so.6\n"}
        pkgs, owners, _ = scanner.os_packages(mock.Mock(), files)
        self.assertEqual([(p["name"], p["src"]) for p in pkgs], [("libc6", "glibc")])
        self.assertEqual(owners["/lib/x86_64-linux-gnu/libc.so.6"], {"libc6"})

    def test_apk(self):
        pkgs, owners, how = scanner.os_packages(mock.Mock(), {"/lib/apk/db/installed": APK_INSTALLED})
        self.assertEqual(how, "apk")
        self.assertEqual([(p["name"], p["version"], p["src"]) for p in pkgs],
                         [("musl", "1.2.5-r0", "musl"), ("libcrypto3", "3.3.2-r0", "openssl")])
        self.assertEqual(owners["/lib/libcrypto.so.3"], {"libcrypto3"})

    def test_rpm_im_container(self):
        c = mock.Mock()
        c.exec.return_value = (0, "openssl-libs\t1:3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n"
                                  "gpg-pubkey\t1.0-1\t(none)\t(none)\n"
                                  "bash\t5.1.8-9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n")
        pkgs, _, how = scanner.os_packages(c, {})
        self.assertEqual(how, "rpm (im Container)")
        self.assertEqual([(p["name"], p["src"], p["srcver"]) for p in pkgs],
                         [("openssl-libs", "openssl", "1:3.0.7-27.el9"), ("bash", "bash", "5.1.8-9.el9")])

    def test_rpm_besitzer_einmal_fuer_alle_pakete(self):
        # rpm 4.14 (RHEL/UBI 8, SLES 15) bricht mit [%{FILENAMES}\t%{NAME}] ab; %{=NAME} wiederholt den Einzelwert
        c = mock.Mock()
        c.exec.return_value = (0, "/usr/bin/php\tphp-cli\n/usr/lib64/libxml2.so.2\tlibxml2\n/usr/share/doc\tfilesystem\n")
        owners = scanner.rpm_owners(c, {"/usr/bin/php", "/usr/lib64/libxml2.so.2"})
        self.assertEqual(c.exec.call_args[0][0], ["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{=NAME}\n]"])
        self.assertEqual(dict(owners), {"/bin/php": {"php-cli"}, "/lib64/libxml2.so.2": {"libxml2"}})   # norm: ohne /usr
        c.exec.reset_mock()
        self.assertEqual(dict(scanner.rpm_owners(c, set())), {})
        c.exec.assert_not_called()

    def test_ohne_paketdatenbank(self):
        c = mock.Mock()
        c.exec.return_value = (127, "")
        with mock.patch.object(scanner, "run", return_value=(1, "")):
            pkgs, _, how = scanner.os_packages(c, {})
        self.assertEqual((pkgs, how), ([], "keine Paketdatenbank gefunden"))


class Anwendungspakete(unittest.TestCase):
    def test_npm_mit_dev_aus_lockfile(self):
        files = {
            "/app/package.json": json.dumps({"name": "app", "version": "1.0.0"}).encode(),
            "/app/node_modules/express/package.json": json.dumps({"name": "express", "version": "4.19.2"}).encode(),
            "/app/node_modules/jest/package.json": json.dumps({"name": "jest", "version": "29.0.0"}).encode(),
            "/app/node_modules/broken/package.json": b"{kein json",
            "/app/node_modules/noversion/package.json": json.dumps({"name": "x"}).encode(),
            "/app/node_modules/.package-lock.json": json.dumps(
                {"packages": {"node_modules/jest": {"dev": True}, "node_modules/express": {}}}).encode()}
        result = {c["name"]: c for c in scanner.npm_packages(files)}
        self.assertEqual(sorted(result), ["app", "express", "jest"])
        self.assertTrue(result["jest"]["dev"])
        self.assertFalse(result["express"]["dev"])
        self.assertEqual(result["express"]["ort"], "/app/node_modules/express")

    def test_composer_1_und_2(self):
        files = {
            "/var/www/vendor/composer/installed.json": json.dumps({
                "packages": [{"name": "laravel/framework", "version": "v10.48.0"},
                             {"name": "phpunit/phpunit", "version": "10.5.0"}],
                "dev-package-names": ["phpunit/phpunit"]}).encode(),
            "/old/vendor/composer/installed.json": json.dumps([{"name": "symfony/yaml", "version": "v3.4.0"}]).encode()}
        result = {c["name"]: c for c in scanner.composer_packages(files)}
        self.assertEqual(result["laravel/framework"]["ort"], "/var/www")
        self.assertTrue(result["phpunit/phpunit"]["dev"])
        self.assertEqual(result["symfony/yaml"]["version"], "v3.4.0")

    def test_composer_anderes_vendor_dir(self):
        # Nextcloud: 3rdparty/composer.json mit "vendor-dir": "." -> 3rdparty/composer/installed.json; Projektverzeichnis
        # ist dann das vendor-dir selbst. lib/composer/composer/installed.json (vendor-dir des Kerns) und die
        # composer/composer/installed.json der mitgelieferten Apps führen keine Pakete; jede Datei zählt nur einmal.
        ein = lambda *namen: json.dumps({"packages": [{"name": n, "version": v} for n, v in namen],
                                          "dev": False, "dev-package-names": []}).encode()
        files = {
            "/var/www/html/3rdparty/composer/installed.json": ein(("guzzlehttp/guzzle", "7.15.2"), ("sabre/dav", "4.7.0")),
            "/var/www/html/lib/composer/composer/installed.json": ein(),
            "/var/www/html/apps/dav/composer/composer/installed.json": ein(),
            "/var/www/html/apps/photos/vendor/composer/installed.json": ein(("hexogen/kdtree", "v0.2.5")),
            "/composer/installed.json": ein(("x/wurzel", "1.0")),
            "/var/www/html/3rdparty/composer/installed.json.bak": ein(("x/kopie", "1.0")),
            "/vendor/composer/installed.json": ein(("x/y", "1.0"))}
        result = sorted((c["name"], c["ort"], c["datei"]) for c in scanner.composer_packages(files))
        self.assertEqual(result, [
            ("guzzlehttp/guzzle", "/var/www/html/3rdparty", "/var/www/html/3rdparty/composer/installed.json"),
            ("hexogen/kdtree", "/var/www/html/apps/photos", "/var/www/html/apps/photos/vendor/composer/installed.json"),
            ("sabre/dav", "/var/www/html/3rdparty", "/var/www/html/3rdparty/composer/installed.json"),
            ("x/y", "/", "/vendor/composer/installed.json")])

    def test_composer_projektverzeichnis(self):
        # Projektverzeichnis (ort) aus installed.php (Composer 2, Root-Paket) bzw. der erkannten Nextcloud-Installation;
        # nie pauschal das Verzeichnis über einem beliebigen vendor-dir
        ein = lambda name: json.dumps({"packages": [{"name": name, "version": "1.0"}]}).encode()
        root = lambda pfad: ("<?php return array(\n    'root' => array(\n        'name' => '__root__',\n"
                             "        'install_path' => %s,\n        'aliases' => array(),\n        'dev' => true,\n"
                             "    ),\n    'versions' => array(\n        'x/y' => array(\n"
                             "            'install_path' => __DIR__ . '/../x/y',\n        ),\n    ),\n);\n" % pfad).encode()
        nc = b"<?php\n$OC_VersionString = '35.0.3';\n$vendor = 'nextcloud';\n"
        files = {
            # composer.json in /srv/app mit "vendor-dir": "deps"
            "/srv/app/deps/composer/installed.json": ein("a/relativ"),
            "/srv/app/deps/composer/installed.php": root("__DIR__ . '/../../'"),
            # Pfad ohne gemeinsame Basis schreibt Composer absolut
            "/opt/libs/composer/installed.json": ein("b/absolut"),
            "/opt/libs/composer/installed.php": root("'/srv/projekt'"),
            # Composer 1 bzw. unlesbare installed.php: das vendor-dir selbst
            "/srv/alt/deps/composer/installed.json": ein("c/ohne"),
            "/srv/kaputt/deps/composer/installed.json": ein("d/kaputt"),
            "/srv/kaputt/deps/composer/installed.php": b"<?php return array('versions' => array());",
            "/srv/quote/deps/composer/installed.json": ein("e/quote"),
            "/srv/quote/deps/composer/installed.php": root("__DIR__ . '/../\\'../'"),
            # Nextcloud: 3rdparty/ ist Root-Paket (vendor-dir "."), Projektverzeichnis die Installation
            "/var/www/html/version.php": nc,
            "/var/www/html/3rdparty/composer/installed.json": ein("f/nextcloud"),
            "/var/www/html/3rdparty/composer/installed.php": root("__DIR__ . '/../'"),
            "/usr/src/nextcloud/version.php": nc,
            "/usr/src/nextcloud/3rdparty/composer/installed.json": ein("g/kopie"),
            # 3rdparty ohne Nextcloud darüber: das vendor-dir
            "/srv/anders/3rdparty/composer/installed.json": ein("h/anders")}
        result = {c["name"]: c["ort"] for c in scanner.composer_packages(files)}
        self.assertEqual(result, {"a/relativ": "/srv/app", "b/absolut": "/srv/projekt", "c/ohne": "/srv/alt/deps",
                                  "d/kaputt": "/srv/kaputt/deps", "e/quote": "/srv/quote/deps",
                                  "f/nextcloud": "/var/www/html", "g/kopie": "/usr/src/nextcloud",
                                  "h/anders": "/srv/anders/3rdparty"})

    def test_nextcloud_version(self):
        nc = (b"<?php \n$OC_Version = array(35,0,3,2);\n$OC_VersionString = '35.0.3';\n$OC_Edition = '';\n"
              b"$OC_Channel = 'stable';\n$OC_VersionCanBeUpgradedFrom = array (\n  'nextcloud' => \n  array (\n"
              b"    '34.0' => true,\n  ),\n);\n$OC_Build = '2026-11-12T14:11:48+00:00 7764ef49';\n$vendor = 'nextcloud';\n")
        files = {
            "/var/www/html/version.php": nc,
            "/usr/src/nextcloud/version.php": nc.replace(b"'35.0.3'", b"'30.0.0 RC1'"),
            "/srv/owncloud/version.php": nc.replace(b"'nextcloud';", b"'owncloud';"),
            "/var/www/wp/wp-includes/version.php": b"<?php\n$wp_version = '6.8.1';\n",
            "/var/www/html/lib/version.php": b"<?php\n// $OC_VersionString = '1.0.0';\n$vendor = 'nextcloud';\n",
            "/var/www/html/3rdparty/x/version.php": b"<?php return '35.0.3';\n"}
        result = sorted((c["typ"], c["name"], c["version"], c["ort"], c["datei"]) for c in scanner.anwendungen(files))
        self.assertEqual(result, [
            ("anwendung", "nextcloud", "30.0.0-RC1", "/usr/src/nextcloud", "/usr/src/nextcloud/version.php"),
            ("anwendung", "nextcloud", "35.0.3", "/var/www/html", "/var/www/html/version.php")])

    def test_pypi(self):
        files = {
            "/opt/venv/lib/python3.12/site-packages/Django-4.2.1.dist-info/METADATA":
                b"Metadata-Version: 2.1\nName: Django\nVersion: 4.2.1\n\nName: nicht im Kopf\n",
            "/usr/lib/python3/dist-packages/requests-2.28.1.egg-info": b"Name: requests\nVersion: 2.28.1\n",
            "/x/foo.egg-info/PKG-INFO": b"Name: foo\n"}
        result = {c["name"]: c for c in scanner.pypi_packages(files)}
        self.assertEqual(sorted(result), ["Django", "requests"])
        self.assertEqual(result["Django"]["ort"], "/opt/venv/lib/python3.12/site-packages")
        self.assertIn("per OS-Paket installiert", result["requests"]["hinweise"])

    def test_rubygems_aus_gemfile_lock(self):
        lock = GEMFILE_LOCK
        bundle = "/home/redmine/redmine/vendor/bundle/ruby/3.3.0"
        files = {"/home/redmine/redmine/Gemfile.lock": lock,
                 # Gemfile.lock im Quellcode installierter Gems bzw. einer Git-Quelle: kein Projekt
                 bundle + "/gems/builder-3.3.0/Gemfile.lock": b"GEM\n  specs:\n    rake (10.0.0)\n",
                 bundle + "/bundler/gems/rails-0123abc/Gemfile.lock": b"GEM\n  specs:\n    rake (10.0.0)\n"}
        for spec in ("rails-7.2.1", "rack-3.1.7", "nokogiri-1.16.7-x86_64-linux-gnu", "net-imap-0.4.10"):
            files["%s/specifications/%s.gemspec" % (bundle, spec)] = b""
        files["/usr/local/lib/ruby/gems/3.3.0/specifications/default/json-2.7.2.gemspec"] = b""
        result = {c["name"]: c for c in scanner.rubygems_packages(files)}
        self.assertEqual(sorted(result), ["json", "my_plugin", "net-imap", "nokogiri", "rack", "rails", "redmine_git",
                                          "rubocop"])
        # Plattform abgetrennt, mehrere Plattformen derselben Version nur einmal
        self.assertEqual([(c["name"], c["version"]) for c in scanner.rubygems_packages(files)
                          if c["name"] == "nokogiri"], [("nokogiri", "1.16.7")])
        self.assertEqual({c["ort"] for c in result.values()}, {"/home/redmine/redmine"})
        self.assertEqual(result["rack"]["datei"], bundle + "/specifications/rack-3.1.7.gemspec")
        # ohne Spezifikation: development/test (P4); auch vorinstallierte Standard-Gems zählen als installiert
        self.assertTrue(result["rubocop"]["dev"])
        self.assertEqual(result["rubocop"]["datei"], "/home/redmine/redmine/Gemfile.lock")
        self.assertFalse(result["rack"]["dev"] or result["json"]["dev"] or result["nokogiri"]["dev"])
        # GIT und PATH: nie dev; PATH wird nicht abgeglichen
        self.assertEqual((result["redmine_git"]["quelle"], result["redmine_git"]["dev"]), ("GIT", False))
        self.assertEqual((result["my_plugin"]["quelle"], result["my_plugin"]["dev"]), ("PATH", False))
        self.assertIsNone(scanner.osv_target(result["my_plugin"], {"id": "debian", "version": "12"}))

    def test_rubygems_installation_nicht_erkennbar(self):
        # weniger als die Hälfte der Gems mit Spezifikation gefunden (anderer Ort): alle zählen als installiert
        files = {"/app/Gemfile.lock": GEMFILE_LOCK,
                 "/usr/local/bundle/specifications/rails-7.2.1.gemspec": b""}
        self.assertFalse(any(c["dev"] for c in scanner.rubygems_packages(files)))
        self.assertFalse(any(c["dev"] for c in scanner.rubygems_packages({"/app/Gemfile.lock": GEMFILE_LOCK})))

    def test_rubygems_aus_os_paket_ueber_das_paket_geprueft(self):
        # Spezifikation gehört einem OS-Paket (Debian ruby-rack): Abgleich über das Paket, das Fixes zurückportiert
        spec = "/usr/share/rubygems-integration/all/specifications/rack-3.1.7.gemspec"
        files = {"/etc/os-release": b"ID=debian\nVERSION_ID=12\n", "/app/Gemfile.lock": GEMFILE_LOCK, spec: b"",
                 "/var/lib/dpkg/status": b"Package: ruby-rack\nStatus: install ok installed\nVersion: 3.1.7-1\n",
                 "/var/lib/dpkg/info/ruby-rack.list": spec.encode() + b"\n"}
        with mock.patch.object(scanner, "collect_files", return_value=(files, [], "test", [])), \
                mock.patch.object(scanner, "collect_procs", return_value=({}, "test", {})), \
                mock.patch.object(scanner, "probe_runtimes", return_value=[]), \
                mock.patch.object(scanner, "host_components", return_value=[]):
            comps, how = scanner.inventar_erfassen(mock.Mock())[6:8]
        gems = sorted(c["name"] for c in comps if c["typ"] == "rubygems")
        self.assertNotIn("rack", gems)
        self.assertIn("rails", gems)
        self.assertEqual(how["os_owned"], 1)


class JavaScript(unittest.TestCase):
    def test_version_aus_kopf(self):
        c = scanner.js_library("/var/www/js/jquery.min.js", b"/*! jQuery v1.10.2 | (c) 2005, 2013 jQuery Foundation */")
        self.assertEqual((c["typ"], c["name"], c["version"]), ("js-lib", "jquery", "1.10.2"))
        c = scanner.js_library("/srv/vue.global.prod.js", b"/**\n* vue v3.4.0\n* Vue.js v3.4.0\n*/")
        self.assertEqual((c["name"], c["version"]), ("vue", "3.4.0"))

    def test_version_aus_dateiname_oder_unbekannt(self):
        c = scanner.js_library("/srv/jquery-ui-1.12.1.custom.min.js", b"minified")
        self.assertEqual(c["version"], "1.12.1")
        self.assertIn("Version aus Dateiname", c["hinweise"])
        c = scanner.js_library("/srv/moment.js", b"minified")
        self.assertEqual(c["version"], "unbekannt")

    def test_node_modules_und_fremde_dateien(self):
        self.assertIsNone(scanner.js_library("/app/node_modules/jquery/dist/jquery.js", b"jQuery v3.7.1"))
        self.assertIsNone(scanner.js_library("/srv/app.js", b"jQuery v3.7.1"))


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class Java(unittest.TestCase):
    def test_pom_properties_und_verschachtelt(self):
        inner = zip_bytes({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties":
                           "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"})
        war = zip_bytes({"WEB-INF/lib/log4j-core-2.14.1.jar": inner,
                         "META-INF/maven/com.example/app/pom.properties": "groupId=com.example\nartifactId=app\nversion=1.0\n"})
        result = scanner.java_archive("/opt/app.war", war)
        self.assertEqual([(c["name"], c["version"], c["ort"], c["datei"]) for c in result], [
            ("com.example:app", "1.0", "/opt/app.war", "/opt/app.war"),
            ("org.apache.logging.log4j:log4j-core", "2.14.1", "/opt/app.war!/WEB-INF/lib/log4j-core-2.14.1.jar",
             "/opt/app.war")])

    def test_tomcat_ohne_pom(self):
        jar = zip_bytes({"org/apache/catalina/util/ServerInfo.properties": "server.number=9.0.85.0\n"})
        result = scanner.java_archive("/usr/local/tomcat/lib/catalina.jar", jar)
        self.assertEqual([(c["name"], c["version"]) for c in result], [("org.apache.tomcat:tomcat-catalina", "9.0.85")])

    def test_dateiname_und_manifest_als_rueckfall(self):
        jar = zip_bytes({"META-INF/MANIFEST.MF": "Implementation-Version: 3.2.1\nImplementation-Vendor-Id: org.foo\n"})
        c = scanner.java_archive("/lib/foo-bar.jar", jar)[0]
        self.assertEqual((c["name"], c["version"], c["maven_key"]), ("foo-bar", "3.2.1", "*:foo-bar"))
        self.assertIn("Hersteller-ID org.foo", c["hinweise"])
        c = scanner.java_archive("/lib/commons-text-1.9.jar", zip_bytes({"a": "b"}))[0]
        self.assertEqual((c["name"], c["version"]), ("commons-text", "1.9"))

    def test_kein_archiv(self):
        self.assertEqual(scanner.java_archive("/x.jar", b"kein zip"), [])


def varint(n):
    out = b""
    while True:
        b, n = n & 0x7f, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def go_buildinfo(version, mod, flags=2):
    head = scanner.GO_MAGIC + bytes([8, flags]) + b"\0" * 16
    return b"\0" * 64 + head + varint(len(version)) + version + varint(len(mod)) + mod + b"\0" * 32


class Go(unittest.TestCase):
    def test_module_und_replace(self):
        mod = (b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6path\texample.com/app\n"
               b"mod\texample.com/app\t(devel)\t\n"
               b"dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n"
               b"dep\tgithub.com/old/lib\tv1.0.0\t\n=>\tgithub.com/new/lib\tv1.2.0\th1:def=\n"
               b"build\t-compiler=gc\n\xf92C1\x82B\x10A\x16\xd8\xf2")
        result = scanner.go_binary("/usr/local/bin/app", go_buildinfo(b"go1.21.3", mod))
        self.assertEqual([(c["name"], c["version"]) for c in result],
                         [("stdlib", "1.21.3"), ("golang.org/x/net", "v0.17.0"), ("github.com/new/lib", "v1.2.0")])

    def test_altes_format_und_kein_go(self):
        result = scanner.go_binary("/bin/old", go_buildinfo(b"", b"", flags=0))
        self.assertEqual([(c["name"], c["version"]) for c in result], [("Go-Programm (vor Go 1.18)", "unbekannt")])
        self.assertEqual(scanner.go_binary("/bin/x", b"\x7fELF" + b"\0" * 100), [])


class TarStrom(unittest.TestCase):
    def test_metadaten_archive_und_hardlinks(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            def add(name, data, mode=0o644):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), mode
                tf.addfile(info, io.BytesIO(data))
            add("etc/os-release", b"ID=debian\n")
            add("app/package.json", json.dumps({"name": "app", "version": "2.0.0"}).encode())
            add("app/public/jquery.min.js", b"/*! jQuery v3.4.1 */")
            add("app/lib/x.jar", zip_bytes({"META-INF/maven/g/a/pom.properties": "groupId=g\nartifactId=a\nversion=1\n"}))
            add("app/README.md", b"ignoriert")
            add("nc/3rdparty/composer/installed.json", b"{}")
            add("nc/3rdparty/composer/installed.php", b"<?php")
            add("nc/version.php", b"<?php")
            link = tarfile.TarInfo("app2/package.json")
            link.type, link.linkname = tarfile.LNKTYPE, "app/package.json"
            tf.addfile(link)
        buf.seek(0)
        files, extra = {}, []
        scanner.read_tar(buf, files, extra, prefix="/")
        self.assertEqual(sorted(files), ["/app/package.json", "/app2/package.json", "/etc/os-release",
                                         "/nc/3rdparty/composer/installed.json", "/nc/3rdparty/composer/installed.php",
                                         "/nc/version.php"])
        self.assertEqual(files["/app2/package.json"], files["/app/package.json"])
        self.assertEqual(sorted((c["typ"], c["name"]) for c in extra), [("js-lib", "jquery"), ("maven", "g:a")])

    def test_kaputter_strom(self):
        files, extra = {}, []
        scanner.read_tar(io.BytesIO(b"kein tar"), files, extra)
        self.assertEqual((files, extra), ({}, []))



@unittest.skipUnless(all(shutil.which(t) for t in ("sh", "find", "tar", "sort", "xargs", "grep")), "POSIX-Werkzeuge fehlen")
class Dateisuche(unittest.TestCase):
    """FIND_SH (läuft im Container) mit einem Testverzeichnis statt der Wurzel."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "app"))
        with open(os.path.join(self.tmp, "app", "package.json"), "w") as f:
            f.write("{}")

    def suche(self, *wurzeln, tar=None):
        """FIND_SH ausführen; tar: Inhalt eines Ersatz-tar (sh-Skript). Liefert (Exit-Code, package.json, stderr)."""
        skript = scanner.FIND_SH.replace('for r in / "$@"', 'for r in "$@"')
        self.assertNotEqual(skript, scanner.FIND_SH)
        if tar:
            pfad = os.path.join(self.tmp, "ersatz-tar")
            with open(pfad, "w") as f:
                f.write("#!/bin/sh\ncat >/dev/null\n" + tar)
            os.chmod(pfad, 0o755)
            skript = skript.replace("| tar -cf", "| %s -cf" % pfad)
        p = subprocess.run(["sh", "-s", "--"] + list(wurzeln), input=skript.encode(), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60)
        namen, self.alle = [], []
        if not tar:
            with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tf:
                self.alle = tf.getnames()
                namen = [n for n in self.alle if n.endswith("package.json")]
        return p.returncode, namen, p.stderr.decode()

    def test_vollstaendig(self):
        rc, namen, err = self.suche(self.tmp)
        self.assertEqual((rc, len(namen), err), (0, 1, ""))

    def test_gemfile_lock_und_spezifikationen(self):
        for pfad in ("app/Gemfile.lock", "app/vendor/bundle/ruby/3.3.0/specifications/rack-3.1.7.gemspec",
                     "ruby/gems/3.3.0/specifications/default/json-2.7.2.gemspec", "app/rack.gemspec"):
            os.makedirs(os.path.join(self.tmp, posixpath.dirname(pfad)), exist_ok=True)
            with open(os.path.join(self.tmp, pfad), "w") as f:
                f.write("x")
        self.assertEqual(self.suche(self.tmp)[0], 0)
        gefunden = sorted(n for n in self.alle if scanner.WANTED.search("/" + n.lstrip("/")))
        self.assertEqual([posixpath.basename(n) for n in gefunden],
                         ["Gemfile.lock", "package.json", "rack-3.1.7.gemspec", "json-2.7.2.gemspec"])

    def test_verschwundene_dateien_sind_kein_fehler(self):
        # während der Suche gelöschte Dateien/Verzeichnisse (wie ein fehlender Pfad): nichts geht verloren
        rc, namen, _ = self.suche(self.tmp, os.path.join(self.tmp, "fehlt"))
        self.assertEqual((rc, len(namen)), (0, 1))
        self.assertEqual(self.suche(self.tmp, tar='echo "tar: /x: Cannot stat: No such file or directory" >&2\n'
                                                  'echo "tar: Exiting with failure status due to previous errors" >&2\n'
                                                  'exit 2\n')[0], 0)

    def test_andere_fehler_der_suche_ergeben_fehlercode(self):
        # nicht durchsuchbarer Pfad (wie ein unlesbares Verzeichnis): Strom bleibt nutzbar, Ergebnis unvollständig
        rc, namen, err = self.suche(self.tmp, os.path.join(self.tmp, "app", "package.json", "x"))
        self.assertEqual((rc, len(namen)), (3, 1))
        self.assertIn("Not a directory", err)

    def test_fehler_von_tar_ergeben_fehlercode(self):
        rc, _, err = self.suche(self.tmp, tar='echo "tar: /x: Cannot open: Permission denied" >&2\nexit 2\n')
        self.assertEqual(rc, 3)
        self.assertIn("Permission denied", err)
        rc, _, err = self.suche(self.tmp, tar="exit 2\n")
        self.assertEqual((rc, err), (3, "tar: Fehler ohne Meldung\n"))

    def test_leeres_archiv_von_busybox_ist_kein_fehler(self):
        # BusyBox-tar ohne gefundene Dateien (reiner Daten-Container): "tar: empty archive" mit Fehlercode 1
        self.assertEqual(self.suche(self.tmp, tar='echo "tar: empty archive" >&2\nexit 1\n')[:3:2], (0, ""))
        self.assertEqual(self.suche(self.tmp, tar='echo "tar: empty archive: x" >&2\nexit 1\n')[0], 3)

    def test_nextcloud_3rdparty_und_version(self):
        # Composer mit anderem vendor-dir (Nextcloud 3rdparty/) und version.php werden übertragen
        for pfad in ("nc/3rdparty/composer/installed.json", "nc/3rdparty/composer/installed.php",
                     "nc/lib/composer/composer/installed.json", "nc/version.php", "nc/3rdparty/composer/autoload_real.php"):
            os.makedirs(os.path.dirname(os.path.join(self.tmp, pfad)), exist_ok=True)
            with open(os.path.join(self.tmp, pfad), "w") as f:
                f.write("{}")
        rc, _, err = self.suche(self.tmp)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(sorted(n[len(self.tmp.lstrip("/")):] for n in self.alle if "/nc/" in n),
                         ["/nc/3rdparty/composer/installed.json", "/nc/3rdparty/composer/installed.php",
                          "/nc/lib/composer/composer/installed.json", "/nc/version.php"])

    def test_nextcloud_nutzerdaten_nicht_ausgewertet(self):
        # hochgeladene Dateien im Datenverzeichnis (.ocdata) verlassen den Container nicht; daneben alles wie bisher
        for pfad in ("nc/data/.ocdata", "nc/data/admin/files/package.json", "nc/data/admin/files/x/lib.jar",
                     "nc/data2/package.json", "nc/apps/package.json"):
            os.makedirs(os.path.dirname(os.path.join(self.tmp, pfad)), exist_ok=True)
            with open(os.path.join(self.tmp, pfad), "w") as f:
                f.write("{}")
        rc, namen, err = self.suche(self.tmp)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(sorted(n[len(self.tmp.lstrip("/")):] for n in namen),
                         ["/app/package.json", "/nc/apps/package.json", "/nc/data2/package.json"])
        self.assertIn(self.tmp.lstrip("/") + "/nc/data/.ocdata", [n.lstrip("/") for n in self.alle])
        self.assertFalse([n for n in self.alle if "/nc/data/admin" in n])
        # neuere Nextcloud-Versionen: .ncdata statt .ocdata (auch Papierkorb und alte Versionen der Nutzer)
        for pfad in ("nc2/data/.ncdata", "nc2/data/u/files_trashbin/files/x.d1/package.json",
                     "nc2/data/u/files/alt.jar", "nc2/apps/package.json"):
            os.makedirs(os.path.dirname(os.path.join(self.tmp, pfad)), exist_ok=True)
            with open(os.path.join(self.tmp, pfad), "w") as f:
                f.write("# Nextcloud data directory\n" if pfad.endswith(".ncdata") else "{}")
        rc, namen, err = self.suche(self.tmp)
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("/nc2/apps/package.json", [n[len(self.tmp.lstrip("/")):] for n in namen])
        self.assertFalse([n for n in self.alle if "/nc2/data/u" in n])
        # Lesen von außen (docker export, docker cp) liefert die Nutzerdaten mit: im Ergebnis entfernt, vermerkt
        c = mock.Mock(has_find_tar=False, user="0", id="abc", mounts=[])

        def stream(cmd, files, extra, input=None, meldungen=None, prefix="", **kw):
            files.update({"/var/www/html/data/.ocdata": b"", "/var/www/html/data/u/files/package.json": b"{}",
                          "/var/www/html/package.json": b"{}"})
            extra += [{"datei": "/var/www/html/data/u/files/a.jar"}, {"datei": "/var/www/html/lib/b.jar"}]
            return True
        with mock.patch.object(scanner, "stream_tar", side_effect=stream):
            files, extra, how, problems = scanner.collect_files(c)
        self.assertEqual((sorted(files), extra, problems),
                         (["/var/www/html/package.json"], [{"datei": "/var/www/html/lib/b.jar"}], []))
        self.assertTrue(how.endswith("; Nutzerdaten nicht ausgewertet (Nextcloud: /var/www/html/data)"), how)
        files = {"/srv/nc/data/.ncdata": b"# Nextcloud data directory", "/srv/nc/data/u/files_trashbin/package.json": b"{}",
                 "/srv/nc/package.json": b"{}"}
        extra = [{"datei": "/srv/nc/data/appdata_x/a.jar"}]
        self.assertEqual(scanner.nutzerdaten_entfernen(files, extra), ["/srv/nc/data"])
        self.assertEqual((sorted(files), extra), (["/srv/nc/package.json"], []))

    def test_meldungen_im_bericht(self):
        meldungen = []
        cmd = ["sh", "-c", "echo 'find: /root: Permission denied' >&2; echo 'find: /root: Permission denied' >&2; exit 3"]
        self.assertFalse(scanner.stream_tar(cmd, {}, [], meldungen=meldungen))
        self.assertEqual(len(meldungen), 2)
        c = mock.Mock(has_find_tar=True, user="0", id="abc", mounts=[])

        def stream(cmd, files, extra, input=None, meldungen=None, **kw):
            meldungen.extend(["find: /root: Permission denied"] * 2 + ["find: /a: x", "find: /b: x", "find: /c: x"])
            return False
        with mock.patch.object(scanner, "stream_tar", side_effect=stream):
            problems = scanner.collect_files(c)[3]
        self.assertEqual(problems, ["Dateien im Container nicht vollständig lesbar (find: /root: Permission denied; "
                                    "find: /a: x; find: /b: x … und 1 weitere)"])

    def lesen_ohne_rechte(self, export_ok=True, cp_ok=True):
        """find/tar scheitert nur an fehlenden Rechten (cap_drop: ALL): Liefert (Ergebnis, Aufrufe)."""
        c = mock.Mock(has_find_tar=True, user="0", id="abc", mounts=["/app/config.json", "/app/keys"])
        aufrufe = []

        def stream(cmd, files, extra, input=None, meldungen=None, prefix="", **kw):
            aufrufe.append((cmd, prefix))
            if cmd[:2] == ["docker", "exec"]:
                files["/teil/package.json"] = b"{}"
                meldungen.extend(["find: /home/node: Permission denied", "tar: /x: Cannot open: Permission denied"])
                return False
            if cmd[:2] == ["docker", "export"]:
                files["/home/node/app/package.json"] = b"{}"
                return export_ok
            files[prefix + "/" + posixpath.basename(cmd[3].split(":", 1)[1])] = b"x"
            return cp_ok
        with mock.patch.object(scanner, "stream_tar", side_effect=stream):
            return scanner.collect_files(c), aufrufe

    def test_ohne_rechte_passiv_von_aussen(self):
        (files, extra, how, problems), aufrufe = self.lesen_ohne_rechte()
        self.assertEqual(problems, [])
        self.assertEqual([x[0][:2] for x in aufrufe], [["docker", "exec"], ["docker", "export"], ["docker", "cp"],
                                                     ["docker", "cp"]])
        self.assertEqual([x[1] for x in aufrufe[2:]], ["/app", "/app"])
        # Teilergebnis aus dem Container verworfen, Volumes einzeln gelesen
        self.assertEqual(sorted(files), ["/app/config.json", "/app/keys", "/home/node/app/package.json"])
        self.assertTrue(how.startswith("docker export und docker cp (2 Volumes), da find/tar im Container ohne "
                                       "Leserechte (2 Meldungen, z. B. find: /home/node: Permission denied)"), how)

    def test_passiv_ohne_vom_mount_verdeckte_dateien(self):
        # docker export enthält Dateien des Images unter einem Mount, die im laufenden Container verdeckt sind
        for werkzeuge in (False, True):
            c = mock.Mock(has_find_tar=werkzeuge, user="0", id="abc", mounts=["/app/keys", "/app"])
            reihenfolge = []

            def stream(cmd, files, extra, input=None, meldungen=None, prefix="", **kw):
                if cmd[:2] == ["docker", "exec"]:
                    meldungen.append("find: /home/node: Permission denied")
                    return False
                if cmd[:2] == ["docker", "export"]:
                    files.update({"/app/node_modules/alt/package.json": b"{}", "/app/keys/x.json": b"{}",
                                  "/apple/package.json": b"{}", "/app": b"{}"})
                    extra += [{"datei": "/app/js/jquery.js"}, {"datei": "/apple/jquery.js"}]
                    return True
                dest = cmd[3].split(":", 1)[1]
                reihenfolge.append(dest)
                files[dest + "/package.json"] = b"{}"
                extra.append({"datei": dest + "/lib.jar"})
                return True
            with mock.patch.object(scanner, "stream_tar", side_effect=stream):
                files, extra, _, problems = scanner.collect_files(c)
            self.assertEqual(problems, [])
            self.assertEqual(reihenfolge, ["/app", "/app/keys"])        # äußere vor inneren
            self.assertEqual(sorted(files), ["/app/keys/package.json", "/app/package.json", "/apple/package.json"])
            self.assertEqual(sorted(x["datei"] for x in extra), ["/app/keys/lib.jar", "/app/lib.jar", "/apple/jquery.js"])

    def test_ohne_rechte_und_export_fehlgeschlagen(self):
        problems = self.lesen_ohne_rechte(export_ok=False, cp_ok=False)[0][3]
        self.assertEqual(problems, ["docker export fehlgeschlagen", "Volume /app/config.json nicht lesbar",
                                    "Volume /app/keys nicht lesbar"])

    def test_andere_fehler_ohne_passives_lesen(self):
        # nicht nur fehlende Rechte (z.B. Zeitüberschreitung, andere Meldungen): kein Rückgriff, unvollständig
        c = mock.Mock(has_find_tar=True, user="0", id="abc", mounts=[])
        for zusatz in (["find: /a: Input/output error"], []):
            aufrufe = []

            def stream(cmd, files, extra, input=None, meldungen=None, **kw):
                aufrufe.append(cmd)
                meldungen.extend(zusatz + (["find: /root: Permission denied"] if zusatz else []))
                return False
            with mock.patch.object(scanner, "stream_tar", side_effect=stream):
                problems = scanner.collect_files(c)[3]
            self.assertEqual(len(aufrufe), 1)
            self.assertEqual(len(problems), 1)
            self.assertIn("nicht vollständig lesbar", problems[0])

if __name__ == "__main__":
    unittest.main()
