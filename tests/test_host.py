"""Scan des Hosts (--host): Prozesse aus /proc, Verzeichnisse, Kernel, Schnittstellen, firewalld, Gesamtlauf."""
import argparse
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from _laden import scanner, proc, web, schreibe_jsonl, eintrag

# Ausgabe von firewalld 2.0 (SLES 15 SP7), gekürzt
ZONEN = """docker
  target: ACCEPT
  interfaces: docker0
  sources:
  services:
  ports:
  rich rules:

intern (active)
  target: default
  interfaces: eth1
  sources:
  services: ssh
  ports: 9000-9100/tcp
  rich rules:

partner (active)
  target: default
  interfaces:
  sources: 198.51.100.0/24
  services:
  ports: 8444/tcp
  rich rules:

public (default, active)
  target: default
  ingress-priority: 0
  icmp-block-inversion: no
  interfaces:
  sources:
  services: dhcpv6-client http https ssh
  ports: 8443/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
\tport=8081:proto=tcp:toport=8080:toaddr=
  source-ports:
  icmp-blocks:
  rich rules:
\trule family="ipv4" source address="10.0.0.0/8" port port="9100" protocol="tcp" accept
\trule family="ipv4" service name="postgresql" accept
"""
POLICIES = """allow-host-ipv6 (active)
  priority: -15000
  target: CONTINUE
  ingress-zones: ANY
  egress-zones: HOST
  services:
  ports:
  rich rules:
\trule family="ipv6" icmp-type name="neighbour-advertisement" accept
"""
DIENSTE = {"http": "http\n  ports: 80/tcp\n  protocols: \n  includes: \n",
           "https": "https\n  ports: 443/tcp\n  includes: \n",
           "ssh": "ssh\n  ports: 22/tcp\n", "dhcpv6-client": "dhcpv6-client\n  ports: 546/udp\n",
           "postgresql": "postgresql\n  ports: 5432/tcp\n"}


def firewall_run(cmd, *a, **kw):
    """Nachgebildetes firewall-cmd (läuft)."""
    if cmd[0] != "firewall-cmd":
        return 1, ""
    arg = cmd[1]
    if arg == "--state":
        return 0, "running\n"
    if arg == "--get-default-zone":
        return 0, "public\n"
    if arg == "--list-all-zones":
        return 0, ZONEN
    if arg == "--list-all-policies":
        return 0, POLICIES
    if arg.startswith("--info-service="):
        return 0, DIENSTE[arg.split("=", 1)[1]]
    if arg == "--direct":
        return 0, ""
    return 1, ""


IFACES = [("lo", "127.0.0.1"), ("eth0", "203.0.113.10"), ("eth0", "2001:db8::10"), ("eth1", "10.20.0.11"),
          ("docker0", "172.17.0.1"), ("br-0123456789ab", "172.18.0.1")]


class Firewalld(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(scanner, "run", side_effect=firewall_run):
            self.fw = scanner.firewall_lesen()
        self.web = web(ist_host=True, interfaces=IFACES, firewall=self.fw)

    def test_lesen(self):
        self.assertEqual(self.fw["default"], "public")
        self.assertEqual(self.fw["zuordnung"], {"docker0": "docker", "eth1": "intern"})
        self.assertEqual(self.fw["quellen"], {"partner": ["198.51.100.0/24"]})
        self.assertEqual(self.fw["zonen"]["public"]["forward-ports"], ["port=8081:proto=tcp:toport=8080:toaddr="])
        self.assertEqual(len(self.fw["zonen"]["public"]["rich rules"]), 2)
        self.assertEqual(self.fw["dienste"]["https"]["ports"], ["443/tcp"])
        self.assertIn("postgresql", self.fw["dienste"])          # aus einer Rich Rule
        self.assertEqual(self.fw["policies"]["allow-host-ipv6"]["egress-zones"], ["HOST"])
        self.assertEqual(self.fw["hinweis"], "")

    def test_nicht_aktiv_oder_nicht_abfragbar(self):
        def nicht_da(cmd, *a, **kw):
            return (127, "") if cmd[0] == "firewall-cmd" else (0, "")
        with mock.patch.object(scanner, "run", side_effect=nicht_da):
            self.assertEqual(scanner.firewall_lesen(), {"aktiv": False, "hinweis": ""})
        # ohne firewalld, aber mit nftables-Regeln: Hinweis
        def nft(cmd, *a, **kw):
            return {"firewall-cmd": (252, "not running"), "nft": (0, "table inet filter {\n chain input {\n"
                                                                       "  tcp dport 22 accept\n }\n}\n")}.get(cmd[0], (1, ""))
        with mock.patch.object(scanner, "run", side_effect=nft), \
                mock.patch.object(scanner, "_prozesse_namens", return_value=[]):
            self.assertIn("nicht ausgewertet", scanner.firewall_lesen()["hinweis"])
        # firewalld läuft, ist aber nicht abfragbar (z.B. D-Bus): im Zweifel erreichbar
        with mock.patch.object(scanner, "run", return_value=(252, "not running")), \
                mock.patch.object(scanner, "_prozesse_namens", return_value=["812"]):
            fw = scanner.firewall_lesen()
        self.assertTrue(fw["aktiv"] and fw["fehler"])
        p = proc(1, "/usr/sbin/nginx", ports={"80": "alle"})
        desc, offen = scanner.port_erreichbar(p, "80", "alle", web(ist_host=True, interfaces=IFACES, firewall=fw))
        self.assertTrue(offen)
        self.assertIn("firewalld nicht abfragbar", desc)

    def test_freigaben(self):
        fw, zone = self.fw, self.fw["zonen"]["public"]
        self.assertEqual(scanner.firewalld_block_offen(zone, "443", "tcp", fw), "Dienst https")
        self.assertEqual(scanner.firewalld_block_offen(zone, "8443", "tcp", fw), "Port 8443/tcp freigegeben")
        self.assertEqual(scanner.firewalld_block_offen(zone, "8080", "tcp", fw), "Weiterleitung von Port 8081")
        self.assertEqual(scanner.firewalld_block_offen(zone, "9100", "tcp", fw), "Rich Rule (Quelle 10.0.0.0/8)")
        self.assertEqual(scanner.firewalld_block_offen(zone, "5432", "tcp", fw), "Rich Rule")
        self.assertEqual(scanner.firewalld_block_offen(zone, "8000", "tcp", fw), "")
        self.assertEqual(scanner.firewalld_block_offen(zone, "443", "udp", fw), "")
        self.assertEqual(scanner.firewalld_block_offen(fw["zonen"]["intern"], "9050", "tcp", fw),
                         "Port 9050/tcp freigegeben")      # Portbereich
        self.assertEqual(scanner.firewalld_block_offen({"target": ["ACCEPT"]}, "1", "tcp", fw), "Target ACCEPT")
        self.assertIn("Quellports", scanner.firewalld_block_offen({"source-ports": ["53/udp"]}, "1", "tcp", fw))
        # Policy nur mit ICMP-Regeln öffnet nichts
        self.assertEqual(scanner.firewalld_block_offen(fw["policies"]["allow-host-ipv6"], "8000", "tcp", fw), "")

    def test_port_erreichbar(self):
        w = self.web

        def pruefe(port, bindungen, base="nginx"):
            p = proc(1, "/usr/sbin/" + base, ports={port: "alle"})
            p["bindungen"] = {port: bindungen}
            return scanner.host_port_pruefen(p, port, "alle", w)
        desc, offen, frei = pruefe("443", ["0.0.0.0"])
        self.assertTrue(offen and frei)
        self.assertIn("eth0: Zone public, Dienst https", desc)
        desc, offen, frei = pruefe("8000", ["0.0.0.0", "::"])
        self.assertEqual((offen, frei), (False, False))
        self.assertIn("von firewalld gesperrt (Zone intern, public)", desc)
        # nur über eth1 (Zone intern) frei; an der Adresse von eth0 gebunden: gesperrt
        self.assertTrue(pruefe("9050", ["0.0.0.0"])[1])
        self.assertFalse(pruefe("9050", ["203.0.113.10"])[1])
        # nur für bestimmte Quellen frei: erreichbar, aber nicht für jede Quelle
        desc, offen, frei = pruefe("9100", ["203.0.113.10"])
        self.assertEqual((offen, frei), (True, False))
        desc, offen, frei = pruefe("8444", ["203.0.113.10"])
        self.assertEqual((offen, frei), (True, False))
        self.assertIn("Zone partner für 198.51.100.0/24", desc)
        # nur an der Docker-Bridge: von außen nicht erreichbar; unbekannte Adresse: im Zweifel erreichbar
        self.assertFalse(pruefe("8000", ["172.17.0.1"])[1])
        desc, offen, frei = pruefe("8000", ["192.0.2.99"])
        self.assertTrue(offen)
        self.assertIn("keiner Schnittstelle zugeordnet", desc)
        # docker-proxy: Docker leitet an der Firewall vorbei weiter
        self.assertTrue(pruefe("8000", ["0.0.0.0"], base="docker-proxy")[1])
        # ohne Firewall bzw. Schnittstellen nicht lesbar: erreichbar
        w["firewall"] = {"aktiv": False, "hinweis": ""}
        self.assertEqual(pruefe("8000", ["0.0.0.0"])[:2][1], True)
        w["interfaces"] = None
        self.assertTrue(pruefe("8000", ["0.0.0.0"])[1])

    def test_loopback_bleibt_lokal(self):
        p = proc(1, "/usr/sbin/httpd-prefork", ports={"8080": "localhost"})
        desc, offen = scanner.port_erreichbar(p, "8080", "localhost", self.web)
        self.assertFalse(offen)
        self.assertIn("nur auf Loopback", desc)

    def test_schnittstellen(self):
        out = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
               "2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever\n"
               "2: eth0    inet6 2001:db8::10/64 scope global \\       valid_lft forever\n"
               "5: vlan10@eth0    inet 10.0.10.5/24 scope global vlan10\n")
        with mock.patch.object(scanner, "run", return_value=(0, out)):
            self.assertEqual(scanner.schnittstellen(), [("lo", "127.0.0.1"), ("eth0", "203.0.113.10"),
                                                        ("eth0", "2001:db8::10"), ("vlan10", "10.0.10.5")])
        with mock.patch.object(scanner, "run", return_value=(127, "")):
            self.assertIsNone(scanner.schnittstellen())


class ProzesseDesHosts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def prozess(self, pid, exe, argv, uid="0", ppid="1", fds=(), maps=(), env=b"PATH=/usr/bin\0HOME=/root\0"):
        d = os.path.join(self.tmp, pid)
        os.makedirs(os.path.join(d, "fd"))
        os.symlink(exe, os.path.join(d, "exe"))
        os.symlink("/", os.path.join(d, "cwd"))
        with open(os.path.join(d, "status"), "w") as f:
            f.write("Name:\tx\nPPid:\t%s\nUid:\t%s\t%s\t%s\t%s\nGid:\t%s\t%s\t%s\t%s\n" % ((ppid,) + (uid,) * 8))
        with open(os.path.join(d, "cmdline"), "wb") as f:
            f.write(b"\0".join(a.encode() for a in argv) + b"\0")
        with open(os.path.join(d, "environ"), "wb") as f:
            f.write(env)
        with open(os.path.join(d, "maps"), "w") as f:
            for m in maps:
                f.write("7f00-7f01 r-xp 00000000 08:01 1234   %s\n" % m)
        for i, ziel in enumerate(fds):
            os.symlink(ziel, os.path.join(d, "fd", str(i)))
        return d

    def test_proc_lesen(self):
        # wie PROC_SH, aber ohne awk/sed (fehlen im SLES-Basisimage): Benutzer, Ports, Bibliotheken, Umgebung
        d = self.prozess("10", "/usr/sbin/nginx", ["nginx: master process nginx"],
                         fds=["socket:[111]", "socket:[112]", "/var/log/nginx/access.log", "/dev/null"],
                         maps=["/usr/sbin/nginx", "/usr/lib64/libssl.so.3", "/usr/lib64/libssl.so.3"])
        self.prozess("11", "/usr/sbin/nginx", ["nginx: worker process"], uid="478", ppid="10",
                     fds=["socket:[111]", "socket:[112]"])
        self.prozess("12", "/usr/sbin/httpd-prefork", ["/usr/sbin/httpd-prefork", "-DSYSCONFIG", "-C",
                                                      "Include /etc/apache2/sysconfig.d//loadmodule.conf"],
                     fds=["socket:[113]", "socket:[114]"])
        os.makedirs(os.path.join(d, "net"))
        kopf = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        with open(os.path.join(d, "net", "tcp"), "w") as f:
            f.write(kopf + "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 111 1\n"
                           "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 113 1\n"
                           "   2: 0B00140A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 114 1\n")
        with open(os.path.join(d, "net", "tcp6"), "w") as f:
            f.write(kopf + "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A "
                           "00000000:00000000 00:00000000 00000000 0 0 112 1\n")
        with mock.patch.object(scanner.os, "getpid", return_value=99999):
            procs, fremd = scanner.procs_auswerten(scanner.proc_lesen(["10", "11", "12", "13"], proc=self.tmp))
        self.assertEqual(sorted(procs), ["10", "11", "12"])
        self.assertEqual(procs["11"]["user"], "478:478")
        self.assertEqual(procs["10"]["ppid"], "1")
        self.assertEqual(procs["10"]["ports"], {"80": "alle"})
        self.assertEqual(procs["10"]["bindungen"], {"80": ["0.0.0.0", "::"]})
        self.assertEqual(procs["10"]["maps"], {"/usr/sbin/nginx", "/usr/lib64/libssl.so.3"})
        self.assertEqual(procs["10"]["files"], {"/var/log/nginx/access.log"})
        self.assertEqual(procs["10"]["env"], {"PATH": "/usr/bin"})
        self.assertEqual(procs["12"]["argv"][2:4], ["-C", "Include /etc/apache2/sysconfig.d//loadmodule.conf"])
        # an 127.0.0.1 und 10.20.0.11 gebunden: die weiteste Bindung zählt, nicht die letzte
        self.assertEqual(procs["12"]["ports"], {"8080": "10.20.0.11"})
        self.assertEqual(procs["12"]["bindungen"], {"8080": ["127.0.0.1", "10.20.0.11"]})
        # dieser Prozess selbst zählt nicht
        with mock.patch.object(scanner.os, "getpid", return_value=11):
            procs, _ = scanner.procs_auswerten(scanner.proc_lesen(["10", "11"], proc=self.tmp))
        self.assertEqual(sorted(procs), ["10"])

    def test_alle_prozesse_des_hosts_ohne_container(self):
        anderes = os.path.join(self.tmp, "rootfs")
        os.mkdir(anderes)
        for pid, exe, root, cgroup in (("10", "/usr/sbin/sshd", "/", "0::/system.slice/sshd.service\n"),
                                       ("11", "/usr/bin/node", anderes, "0::/system.slice/docker-x.scope\n"),
                                       ("12", "/usr/bin/node", "/", "0::/system.slice/docker-abc123.scope\n"),
                                       ("13", "/usr/bin/python3", "/", "0::/user.slice\n")):
            os.mkdir(os.path.join(self.tmp, pid))
            os.symlink(exe, os.path.join(self.tmp, pid, "exe"))
            os.symlink(root, os.path.join(self.tmp, pid, "root"))
            with open(os.path.join(self.tmp, pid, "cgroup"), "w") as f:
                f.write(cgroup)
        with mock.patch.object(scanner.os, "getpid", return_value=13):
            self.assertEqual(scanner.host_proxy_pids([{"Id": "abc123"}], proc=self.tmp, alle=True), (["10"], 0))
            self.assertEqual(scanner.host_proxy_pids([{"Id": "abc123"}], proc=self.tmp), ([], 0))


class Verzeichnisse(unittest.TestCase):
    def test_host_wurzeln(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        for d in ("srv/www/app/public", "daten/app", "var/lib/docker/x"):
            os.makedirs(os.path.join(tmp, d))
        w = web(docroots={"/usr/sbin/nginx": [os.path.join(tmp, "srv/www/app/public"), os.path.join(tmp, "fehlt/public")]})
        procs = {"1": proc(1, "/usr/bin/node", cwd=os.path.join(tmp, "daten/app"), ports={"3000": "alle"}),
                 "2": proc(2, "/usr/bin/bash", cwd=os.path.join(tmp, "daten")),       # ohne Port: nicht
                 "3": proc(3, "/usr/bin/x", cwd=os.path.join(tmp, "var/lib/docker/x"), ports={"1": "alle"})}
        # (das temporäre Verzeichnis liegt unter /tmp, das sonst nie durchsucht wird)
        aus = mock.patch.object(scanner, "HOST_AUSGENOMMEN", ("/proc", os.path.join(tmp, "var/lib/docker")))
        aus.start()
        self.addCleanup(aus.stop)
        with mock.patch.object(scanner, "HOST_WURZELN", (os.path.join(tmp, "srv"), "/gibt/es/nicht")), \
                mock.patch.object(scanner, "geraet", return_value=1):
            wurzeln = scanner.host_wurzeln(procs, w)
        # alles liegt auf einem Dateisystem (nachgebildet): unterhalb von "/" schon erfasst (find -xdev)
        self.assertEqual(wurzeln, [])
        with mock.patch.object(scanner, "HOST_WURZELN", (os.path.join(tmp, "srv"),)), \
                mock.patch.object(scanner, "geraet", side_effect=lambda p: p.count("/")):
            wurzeln = scanner.host_wurzeln(procs, w)
        # je Verzeichnis ein eigenes Dateisystem (nachgebildet); nicht: fehlende, /var/lib/docker, ohne Port
        self.assertEqual(wurzeln, [os.path.join(tmp, "srv"), os.path.join(tmp, "srv/www/app/public"),
                                   os.path.join(tmp, "srv/www/app"), os.path.join(tmp, "daten/app")])

    def test_find_auf_dem_host(self):
        # nie: Daten der Container, Snapshots; Go-Programme nicht in den Verzeichnissen der Distribution
        teile = scanner.HOST_FIND_SH.split("-prune")
        self.assertEqual(len(teile), 3)
        for p in ("/var/lib/docker", "/var/lib/containerd", "/.snapshots", "/proc"):
            self.assertIn("-path %s " % p, teile[0])
            self.assertIn("-path %s " % p, teile[1])
        self.assertNotIn("-path /usr/lib64 ", teile[0])
        self.assertIn("-path /usr/lib64 ", teile[1])

    def test_host_dateien(self):
        with mock.patch.object(scanner, "stream_tar", return_value=True) as st:
            files, extra, how, problems = scanner.host_dateien(["/srv", "/opt"])
        self.assertEqual(st.call_args[0][0], ["env", "-i", "PATH=" + scanner.SAFE_PATH, "sh", "-s", "--", "/srv", "/opt"])
        self.assertEqual(st.call_args[1]["input"], scanner.HOST_FIND_SH)
        self.assertEqual((how, problems), ("find/tar auf dem Host (/ /srv /opt)", []))

        def fehler(cmd, files, extra, input=None, meldungen=None):
            meldungen.append("find: '/srv/geheim': Permission denied")
            return False
        with mock.patch.object(scanner, "stream_tar", side_effect=fehler):
            self.assertIn("Permission denied", scanner.host_dateien(["/srv"])[3][0])


class Kernel(unittest.TestCase):
    def C(self, name, version):
        return scanner.comp("os-paket", name, version, src=name, srcver=version)

    def test_sles(self):
        alt, laeuft, neu = (self.C("kernel-default", "6.4.0-150600.23.22.1"),
                            self.C("kernel-default", "6.4.0-150600.23.25.1"),
                            self.C("kernel-default", "6.4.0-150600.23.30.1"))
        devel = self.C("kernel-default-devel", "6.4.0-150600.23.25.1")
        warnungen = scanner.kernel_markieren([alt, laeuft, neu, devel], release="6.4.0-150600.23.25-default")
        self.assertEqual(laeuft["aktiv"], ["Kernel (läuft)"])
        self.assertEqual((alt["aktiv"], neu["aktiv"], devel["aktiv"]), ([], [], []))
        self.assertEqual(scanner.priority(laeuft, set()), 2)
        self.assertEqual(scanner.priority(alt, set()), 4)
        self.assertEqual(len(warnungen), 1)
        self.assertIn("Neuerer Kernel installiert (kernel-default 6.4.0-150600.23.30.1), läuft noch "
                      "6.4.0-150600.23.25-default – Neustart nötig", warnungen[0])
        # Live-Patches: Kernel-Funde können schon behoben sein
        lp = self.C("kernel-livepatch-6_4_0-150600_23_25-default", "3-150600.2.1")
        self.assertIn("Live-Patches", scanner.kernel_markieren([laeuft, lp], release="6.4.0-150600.23.25-default")[0])

    def test_rhel_und_debian(self):
        k = self.C("kernel-core", "5.14.0-362.8.1.el9_3")
        self.assertEqual(scanner.kernel_markieren([k], release="5.14.0-362.8.1.el9_3.x86_64"), [])
        self.assertEqual(k["aktiv"], ["Kernel (läuft)"])
        d = self.C("linux-image-6.1.0-18-amd64", "6.1.76-1")
        scanner.kernel_markieren([d], release="6.1.0-18-amd64", cmp=scanner.cmp_dpkg)
        self.assertEqual(d["aktiv"], ["Kernel (läuft)"])

    def test_kernel_wird_auf_dem_host_geprueft(self):
        k = self.C("kernel-default", "6.4.0-150600.23.25.1")
        sles = {"id": "sles", "version": "15.6"}
        self.assertIsNone(scanner.osv_target(k, sles))                     # Container: Kernel des Hosts
        self.assertEqual(scanner.osv_target(k, dict(sles, host=True))[2], {"kernel-default"})


class Pakete(unittest.TestCase):
    def test_rpm_auf_dem_host(self):
        h = scanner.Host()
        with mock.patch.object(scanner.Host, "exec", return_value=(0, "nginx\t1.21.5-150600.10.27.1\tx86_64\t"
                                                                       "nginx-1.21.5-150600.10.27.1.src.rpm\n")) as ex:
            pkgs, owners, how = scanner.os_packages(h, {})
        self.assertEqual(ex.call_args[0][0][:2], ["rpm", "-qa"])
        self.assertEqual(ex.call_args[1].get("user"), None)          # Host.exec: ohne Angabe nobody
        self.assertEqual((how, pkgs[0]["src"], pkgs[0]["srcver"]), ("rpm (Host)", "nginx", "1.21.5-150600.10.27.1"))
        # kein Ergebnis: nie docker cp wie bei Containern
        with mock.patch.object(scanner.Host, "exec", return_value=(1, "")), mock.patch.object(scanner, "run") as run:
            pkgs, owners, how = scanner.os_packages(h, {})
        run.assert_not_called()
        self.assertEqual(pkgs, [])
        self.assertIn("keine Paketdatenbank", how)

    def test_rpm_owners_eine_abfrage(self):
        c = mock.Mock()
        c.exec.return_value = (0, "/usr/sbin/nginx\tnginx\n/etc/nginx\tnginx\n/lib64/libc.so.6\tglibc\n")
        owners = scanner.rpm_owners(c, {"/usr/sbin/nginx", "/usr/lib64/libc.so.6", "/opt/x"})
        # %{=NAME}: rpm 4.14 (SLES 15) lehnt "[%{FILENAMES}\t%{NAME}\n]" ab
        self.assertEqual(c.exec.call_args[0][0], ["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{=NAME}\n]"])
        self.assertEqual(dict(owners), {"/sbin/nginx": {"nginx"}, "/lib64/libc.so.6": {"glibc"}})


class Docker(unittest.TestCase):
    def test_docker_vorhanden(self):
        with mock.patch.object(scanner.shutil, "which", return_value=None):
            self.assertFalse(scanner.docker_vorhanden())
        with mock.patch.object(scanner.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(scanner, "_prozesse_namens", return_value=[]), \
                mock.patch.object(scanner.os.path, "exists", return_value=False), \
                mock.patch.dict(scanner.os.environ, {}, clear=True):
            self.assertFalse(scanner.docker_vorhanden())         # nur der Befehl, kein Daemon
            with mock.patch.object(scanner.os.path, "exists", side_effect=lambda p: p == "/run/docker.sock"):
                self.assertTrue(scanner.docker_vorhanden())


NGINX_T = """# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/vhosts.d/*.conf;
}
# configuration file /etc/nginx/vhosts.d/www.conf:
server {
    listen 80; listen 443 ssl;
    server_name www.example.org;
    root /srv/www/htdocs;
    location /app/ { proxy_pass http://127.0.0.1:8080/; }
    location /nginx_status { stub_status; }
}
"""


class Gesamtlauf(unittest.TestCase):
    """scan_host mit nachgebildetem Host: SLES mit nginx (öffentlich) vor Apache (Loopback) vor php-fpm."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = os.path.join(self.tmp, "db")
        schreibe_jsonl(self.db, "SUSE", [
            dict(eintrag("SUSE-SU-2026:1-1", "SUSE:Linux Enterprise Module for Basesystem 15 SP7", "openssl-3",
                         [{"introduced": "0"}, {"fixed": "3.1.4-150600.5.40.1"}]), binaries=["libopenssl3"],
                 upstream=["CVE-2026-0001"])])
        schreibe_jsonl(self.db, "Packagist", [eintrag("GHSA-x", "Packagist", "guzzlehttp/guzzle", [
            {"introduced": "0"}, {"fixed": "7.4.3"}], severity=[{"type": "CVSS_V3",
                                                                 "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}])])
        with open(os.path.join(self.db, "stand.json"), "w") as f:
            json.dump({e: {"geprueft": scanner.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")} for e in ("SUSE", "Packagist")}, f)
        with open(os.path.join(self.db, "suse-schweregrad.json"), "w") as f:
            json.dump({"geprueft": scanner.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "cves": {"CVE-2026-0001": [7.5, "3"]}}, f)

    def lauf(self, nginx_rc=0):
        out = ("P\t10\t/usr/sbin/nginx\t/\tnginx: master process nginx\t0:0\t1\nS\t10\t1\nS\t10\t2\n"
               "M\t10\t/usr/lib64/libssl.so.3\n"
               "P\t11\t/usr/sbin/httpd-prefork\t/\t/usr/sbin/httpd-prefork\x1f-DSYSCONFIG\x1f-f\x1f/etc/apache2/httpd.conf\t0:0\t1\n"
               "S\t11\t3\n"
               "P\t12\t/usr/sbin/php-fpm\t/\tphp-fpm: master process\t0:0\t1\nS\t12\t4\n"
               "T\t1\t00000000:0050\ttcp\nT\t2\t00000000:01BB\ttcp\nT\t3\t0100007F:1F90\ttcp\nT\t4\t0100007F:2328\ttcp\n")
        rpm = ("libopenssl3\t3.1.4-150600.5.30.1\tx86_64\topenssl-3-3.1.4-150600.5.30.1.src.rpm\n"
               "nginx\t1.21.5-150600.10.27.1\tx86_64\tnginx-1.21.5-150600.10.27.1.src.rpm\n")
        dateien = {"/usr/lib/os-release": b'ID="sles"\nVERSION_ID="15.7"\nPRETTY_NAME="SUSE Linux Enterprise Server 15 SP7"\n',
                   "/srv/www/app/vendor/composer/installed.json":
                       b'{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.4.0"}]}'}
        apache_s = ("VirtualHost configuration:\n127.0.0.1:8080         app.example.org (/etc/apache2/vhosts.d/app.conf:1)\n"
                    'Main DocumentRoot: "/srv/www/htdocs"\n')
        conf = {"/etc/apache2/httpd.conf": "Listen 127.0.0.1:8080\n",
                "/etc/apache2/vhosts.d/app.conf": "<VirtualHost 127.0.0.1:8080>\n ServerName app.example.org\n"
                                                  " DocumentRoot /srv/www/app/public\n <FilesMatch \\.php$>\n"
                                                  '  SetHandler "proxy:fcgi://127.0.0.1:9000"\n </FilesMatch>\n</VirtualHost>\n'}

        def exec_(self_, cmd, **kw):
            if cmd[:2] == ["rpm", "-qa"] and "FILENAMES" in cmd[-1]:
                return 0, "/usr/lib64/libssl.so.3\tlibopenssl3\n/usr/sbin/nginx\tnginx\n"
            if cmd[:2] == ["rpm", "-qa"]:
                return 0, rpm
            if cmd[-1] == "-T":
                return nginx_rc, NGINX_T if nginx_rc == 0 else ""
            if "-S" in cmd:
                return 0, apache_s
            if "-M" in cmd:
                return 0, " proxy_fcgi_module (shared)\n status_module (shared)\n"
            if "DUMP_INCLUDES" in cmd:
                return 0, "Included configuration files:\n  (*) /etc/apache2/httpd.conf\n    (1) /etc/apache2/vhosts.d/app.conf\n"
            if cmd[:2] == ["env", "OPENSSL_CONF=/dev/null"]:
                return 0, json.dumps({"TLSv1": "abgelehnt", "TLSv1.1": "abgelehnt"})
            return 1, ""
        a = argparse.Namespace(ausgabe=os.path.join(self.tmp, "berichte"), dbdirs=[self.db], alle=False,
                               nur_behebbare=True, ausnahmen_liste=[])
        fw = {"aktiv": True, "default": "public", "zonen": {"public": {"services": ["http", "https"]}}, "policies": {},
              "zuordnung": {}, "quellen": {}, "dienste": {"http": {"ports": ["80/tcp"]}, "https": {"ports": ["443/tcp"]}},
              "hinweis": ""}
        with mock.patch.object(scanner, "host_proxy_pids", return_value=(["10", "11", "12"], 0)), \
                mock.patch.object(scanner, "proc_lesen", return_value=out), \
                mock.patch.object(scanner, "host_dateien", return_value=(dateien, [], "find/tar auf dem Host", [])), \
                mock.patch.object(scanner, "schnittstellen", return_value=[("lo", "127.0.0.1"), ("eth0", "203.0.113.10")]), \
                mock.patch.object(scanner, "firewall_lesen", return_value=fw), \
                mock.patch.object(scanner.Host, "exec", exec_), \
                mock.patch.object(scanner.Host, "read_file", lambda self_, p: conf.get(p, "")), \
                mock.patch.object(scanner.Host, "name", "web01.example.com"), \
                mock.patch.object(scanner.os, "geteuid", return_value=0), \
                mock.patch.object(scanner, "log"), mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            code, ziele, base = scanner.scan_host(a)
        return code, ziele, base, stdout.getvalue()

    def test_scan_host(self):
        code, ziele, base, out = self.lauf()
        self.assertEqual((code, ziele), (1, []))
        self.assertTrue(os.path.basename(base).startswith("host_web01_"))
        with open(base + ".md", encoding="utf-8") as f:
            bericht = f.read()
        self.assertIn("# Host-Scan: web01.example.com", bericht)
        self.assertIn("- Firewall: firewalld aktiv (Runtime), Standardzone public", bericht)
        # Abgleich über das Quellpaket openssl-3, genutzt vom öffentlichen nginx -> P1; Schweregrad von SUSE
        self.assertIn("| 1 | HIGH | CVE-2026-0001 | libopenssl3 |", bericht)
        # Composer im Docroot der Apache-Website hinter nginx: öffentliche Webadresse der Kette
        self.assertIn("**GHSA-x** (CRITICAL) in guzzlehttp/guzzle 7.4.0 – behoben in 7.4.3 – genutzt von "
                      "httpd-prefork:8080, nginx:80,443 (über httpd-prefork), php-fpm:9000 – Webadressen: "
                      "http://www.example.org/app/, https://www.example.org/app/\n", bericht)
        self.assertIn("| http://app.example.org:8080/ | nein | httpd-prefork:8080 | httpd-prefork:8080 | "
                      "/etc/apache2/vhosts.d/app.conf:1 | /srv/www/app/public |", bericht)
        self.assertIn("| http://www.example.org/app/ (\\.php$) | ja | php-fpm:9000 | nginx:80,443 → httpd-prefork:8080 → "
                      "php-fpm:9000 | (weitergeleitet) | – |", bericht)
        self.assertIn("**WEB-STATUS**: nginx: stub_status in location /nginx_status", bericht)
        self.assertIn("Host: RELEVANTE SCHWACHSTELLEN und EINSTELLUNGEN DER WEBSERVER", out)
        self.assertIn("Host:   Webadressen nginx:80,443: erreichbar: http://www.example.org/, https://www.example.org/", out)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "berichte", "bekannt-host.json")))
        with open(base + ".cdx.json", encoding="utf-8") as f:
            bom = json.load(f)
        self.assertEqual(bom["metadata"]["component"]["type"], "device")
        nginx = next(s for s in bom["services"] if s["name"] == "nginx")
        self.assertIn("https://www.example.org/", nginx["endpoints"])

    def test_konfiguration_nicht_lesbar_ist_unvollstaendig(self):
        code, ziele, base, out = self.lauf(nginx_rc=1)
        self.assertEqual(code, 2)
        self.assertIn("Host: UNVOLLSTÄNDIG: /usr/sbin/nginx -T fehlgeschlagen", out)


if __name__ == "__main__":
    unittest.main()
