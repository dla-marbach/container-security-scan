"""Prozesse aus /proc: Programm, Ports, geladene Dateien, Umgebung – je Prozess-Benutzer gelesen."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from _laden import scanner, proc

SAFE = ["-e", "PATH=" + scanner.SAFE_PATH]


def enthaelt(liste, teil):
    return any(liste[i:i + len(teil)] == teil for i in range(len(liste)))


class Adressen(unittest.TestCase):
    def test_decode_addr(self):
        self.assertEqual(scanner.decode_addr("00000000"), "alle")
        self.assertEqual(scanner.decode_addr("00000000000000000000000000000000"), "alle")
        self.assertEqual(scanner.decode_addr("0100007F"), "localhost")
        self.assertEqual(scanner.decode_addr("0100A8C0"), "192.168.0.1")
        self.assertEqual(scanner.decode_addr("000080FE00000000FF0F00000100A8C0"), "IPv6")
        self.assertEqual(scanner.decode_addr("0000000000000000FFFF00000100007F"), "localhost")   # ::ffff:127.0.0.1
        self.assertEqual(scanner.decode_addr("0000000000000000FFFF00000100A8C0"), "192.168.0.1")
        self.assertTrue(scanner.nur_lokal("127.0.0.11"))     # Dockers DNS im Container
        self.assertFalse(scanner.nur_lokal("alle"))
        # Verbindungsziele vollständig, auch IPv6
        self.assertEqual(scanner.decode_ip("050012AC"), "172.18.0.5")
        self.assertEqual(scanner.decode_ip("0000000000000000FFFF0000050012AC"), "172.18.0.5")
        self.assertEqual(scanner.decode_ip("000000FD000000000000000002000000"), "fd00::2")


class Prozesse(unittest.TestCase):
    def test_je_benutzer_gelesen_und_ports_zugeordnet(self):
        c = mock.Mock(has_sh=True, has_proc_tools=True)
        ausgaben = {
            "0:0": "P\t1\t/usr/sbin/nginx\t/\tnginx: master process nginx\x1f-g\x1fdaemon off;\t0:0\t0\n"
                   "S\t1\t111\nS\t1\t333\nM\t1\t/usr/lib/x86_64-linux-gnu/libssl.so.3\n"
                   "T\t111\t00000000:0050\ttcp\nT\t333\t00000000:0035\tudp\n"
                   # ohne Prozess: Container mit gemeinsamem Netzwerk-Namespace bzw. Dockers DNS (nur lokal)
                   "T\t999\t00000000:1F90\ttcp\nT\t998\t0B00007F:811D\ttcp\n"
                   # eingehend (lokaler Port 80 lauscht) und ausgehend zu 172.18.0.5:3000
                   "S\t1\t444\nC\t444\t020012AC:0050\t090012AC:D431\n"
                   "S\t1\t555\nC\t555\t020012AC:D432\t050012AC:0BB8\n"
                   "S\t1\t666\nC\t666\t000000FD000000000000000003000000:D433\t000000FD000000000000000002000000:1F90\n",
            "33:33": "P\t7\t/usr/local/bin/node (deleted)\t/app\tnode\x1fserver.js\t33:33\t1\n"
                     "E\t7\tPATH=/usr/local/bin:/usr/bin\nF\t7\t/app/data.db\nS\t7\t222\n"
                     "T\t222\t0100007F:0BB8\ttcp\n"}
        aufrufe = []

        def sh(script, binary=False, user=None, args=()):
            aufrufe.append((user, list(args)))
            if user is None:
                return 0, "1 0:0\n7 33:33\n9 33:33\n"
            return 0, ausgaben[user]
        c.sh.side_effect = sh
        procs, how, fremd = scanner.collect_procs(c)
        self.assertEqual(how, "im Container (je Prozess-Benutzer)")
        self.assertEqual(fremd, {"8080": ("alle", "999")})
        self.assertEqual(list(procs["1"]["verbindungen"]), [("172.18.0.5", "3000"), ("fd00::2", "8080")])
        self.assertIn(("33:33", ["7", "9"]), aufrufe)
        self.assertEqual(procs["1"]["ports"], {"80": "alle", "53/udp": "alle"})
        self.assertEqual(procs["1"]["argv"], ["nginx: master process nginx", "-g", "daemon off;"])
        node = procs["7"]
        self.assertEqual((node["exe"], node["base"], node["cwd"], node["user"]), ("/usr/local/bin/node", "node", "/app", "33:33"))
        self.assertEqual(node["ports"], {"3000": "localhost"})
        self.assertEqual(node["label"], "node:3000")
        self.assertEqual(node["env"], {"PATH": "/usr/local/bin:/usr/bin"})
        self.assertEqual(node["files"], {"/app/data.db"})
        self.assertEqual((procs["1"]["ppid"], node["ppid"]), ("0", "1"))

    def test_mehrere_sockets_am_selben_port(self):
        # 0.0.0.0:8080 und [::1]:8080 bzw. 127.0.0.1:9000 und 10.0.0.5:9000: die weiteste Bindung zählt, gleich in
        # welcher Reihenfolge /proc/net/tcp und tcp6 die Sockets liefern
        for reihe in ((1, 2, 3, 4), (2, 1, 4, 3)):
            sockets = {1: "T\t1\t00000000:1F90\ttcp\n", 2: "T\t2\t00000000000000000000000001000000:1F90\ttcp\n",
                       3: "T\t3\t0100007F:2328\ttcp\n", 4: "T\t4\t0500000A:2328\ttcp\n"}
            out = "P\t1\t/usr/bin/app\t/\tapp\t0:0\t0\n" + "".join("S\t1\t%d\n" % i for i in reihe) + \
                "".join(sockets[i] for i in reihe)
            procs, _ = scanner.procs_auswerten(out)
            self.assertEqual(procs["1"]["ports"], {"8080": "alle", "9000": "10.0.0.5"}, reihe)

    def test_unix_sockets_dem_besitzer_zugeordnet(self):
        # U: lauschende Unix-Sockets des Netzwerk-Namespace; zugeordnet über die Socket-Inode der Prozesse
        out = ("P\t1\t/usr/sbin/nginx\t/\tnginx\t0:0\t0\nP\t7\t/usr/bin/ruby\t/\tpuma\t999:999\t1\n"
               "S\t7\t4711\nS\t1\t4712\nU\t4711\t/home/redmine/tmp/redmine.socket\nU\t4713\t/run/fremd mit leer.sock\n")
        procs, _ = scanner.procs_auswerten(out)
        self.assertEqual((procs["7"]["unix"], procs["1"]["unix"]), ({"/home/redmine/tmp/redmine.socket"}, set()))

    def test_kinder_ohne_lesbares_exe(self):
        # N: Worker nach dem Wechsel des Benutzers nicht "dumpable" (Apache, php-fpm): nur Benutzer, Eltern, Name
        out = ("P\t1\t/usr/sbin/apache2\t/\tapache2\t0:0\t0\nS\t1\t5\nT\t5\t00000000:0050\ttcp\n"
               "N\t7\t33:33\t1\tapache2\nN\t8\t33:33\t1\tapache2\nN\t9\t0:0\t99\tanderes\n")
        procs, _ = scanner.procs_auswerten(out)
        self.assertEqual(list(procs), ["1"])
        self.assertEqual([(k["pid"], k["user"], k["name"]) for k in procs["1"]["kinder"]],
                         [("7", "33:33", "apache2"), ("8", "33:33", "apache2")])

    @unittest.skipUnless(os.path.exists("/proc/self/net/unix"), "nur unter Linux")
    def test_proc_sh_liest_lauschende_unix_sockets(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        pfad = os.path.join(tmp, "app mit leer.sock")
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(pfad)
        s.listen(1)
        p = subprocess.run(["sh", "-s", "--", str(os.getpid())], input=scanner.PROC_SH, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        procs, _ = scanner.procs_auswerten(p.stdout)
        self.assertIn(pfad, procs[str(os.getpid())]["unix"])

    def test_ohne_shell_ueber_proc_des_hosts(self):
        c = mock.Mock(has_sh=False, id="abc")
        with mock.patch.object(scanner, "run", side_effect=[(0, "PID\n4242\n"), (0, "P\t4242\t/app\t/\tapp\t:\n")]) as run:
            procs, how, _ = scanner.collect_procs(c)
        self.assertEqual(how, "über /proc des Hosts")
        self.assertEqual(run.call_args_list[1][0][0], ["sh", "-s", "--", "4242"])
        self.assertEqual((procs["4242"]["exe"], procs["4242"]["user"]), ("/app", ""))

    def test_ohne_pids_keine_host_prozesse(self):
        # docker top fehlgeschlagen: nie /proc des ganzen Hosts lesen (Kommandozeilen im Bericht)
        c = mock.Mock(has_sh=False, id="abc")
        for antwort in ((1, ""), (0, "PID\n"), (0, "PID\nkeine-pid\n")):
            with mock.patch.object(scanner, "run", side_effect=[antwort]) as run:
                with self.assertRaisesRegex(scanner.ScanError, "nicht ermittelbar"):
                    scanner.collect_procs(c)
            self.assertEqual(run.call_count, 1)

    def test_proc_sh_ohne_argumente_liest_nichts(self):
        p = subprocess.run(["sh", "-s", "--"], input=scanner.PROC_SH, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        self.assertEqual(p.stdout, "")


class Versionsabfrage(unittest.TestCase):
    def test_benutzer_und_suchpfad(self):
        c = mock.Mock(user="0")
        c.probe.return_value = (1, "")
        procs = {"1": proc(1, "/usr/local/bin/node", user="1000:1000"), "2": proc(2, "/usr/bin/php", user="")}
        scanner.probe_runtimes(c, procs, {})
        calls = {cmd[0]: (user, kw["path"]) for (cmd, user), kw in c.probe.call_args_list}
        # laufendes Programm: mit dessen Benutzer, Befehle (timeout) über SAFE_PATH
        self.assertEqual(calls["/usr/local/bin/node"], ("1000:1000", scanner.SAFE_PATH))
        self.assertEqual(calls["/usr/bin/php"], (scanner.NOBODY, scanner.SAFE_PATH))   # Benutzer unbekannt
        # Name ohne Pfad: PATH des Images, aber nur als nobody
        for name in ("node", "php", "python3", "nginx", "java"):
            self.assertEqual(calls[name], (scanner.NOBODY, None))

    def test_httpd_nie_mit_v(self):
        # BusyBox-httpd startet mit -v ("ausführlich") einen Webserver im Hintergrund; -V lehnt es ab
        c = mock.Mock(user="0")
        c.probe.return_value = (0, "Server version: Apache/2.4.71 (Unix)\n")
        comps = scanner.probe_runtimes(c, {"1": proc(1, "/usr/local/apache2/bin/httpd")}, {})
        aufrufe = [cmd for (cmd, user), kw in c.probe.call_args_list if cmd[0].endswith(("httpd", "apache2"))]
        self.assertEqual(sorted(aufrufe), [["/usr/local/apache2/bin/httpd", "-V"], ["apache2", "-V"], ["httpd", "-V"]])
        self.assertIn(("apache-httpd", "2.4.71"), [(x["name"], x["version"]) for x in comps])


class Zeitlimit(unittest.TestCase):
    """Versionsabfragen im Container über PROBE_SH statt timeout (BusyBox-timeout hinterlässt Zombies an PID 1)."""

    def sh(self, *cmd, sekunden=50, zombies=False):
        p = subprocess.Popen(["sh", "-c", scanner.PROBE_SH, "sh", str(sekunden)] + list(cmd), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True, start_new_session=True)
        out = p.communicate(timeout=30)[0]
        if zombies:
            # beim Zeitlimit beendete Enkel fallen an PID 1 und bleiben dort Zombies, wenn er nicht aufräumt (Job-
            # Container der Action: tail -f /dev/null) – es darf aber nichts mehr laufen
            self.assertEqual(self.laufend(p.pid), [])
        else:
            # nichts bleibt zurück: kein Prozess mehr in der eigenen Prozessgruppe (Programm, Wächter, dessen sleep)
            with self.assertRaises(ProcessLookupError):
                os.killpg(p.pid, 0)
        return p.returncode, out

    @staticmethod
    def laufend(pgid):
        """Prozesse der Gruppe, die keine Zombies sind (aus /proc/*/stat: Zustand und Gruppe nach dem Namen)."""
        ergebnis = []
        for d in os.listdir("/proc"):
            try:
                with open("/proc/%s/stat" % d) as f:
                    felder = f.read().rpartition(")")[2].split()
            except (OSError, ValueError):
                continue
            if d.isdigit() and len(felder) > 2 and felder[2] == str(pgid) and felder[0] != "Z":
                ergebnis.append((d, felder[0]))
        return ergebnis

    def test_ausgabe_und_rueckgabewert(self):
        start = time.time()
        self.assertEqual(self.sh("sh", "-c", "echo 'Apache/2.4.71 (Unix)'; echo fehler >&2; exit 3"),
                         (3, "Apache/2.4.71 (Unix)\nfehler\n"))
        self.assertLess(time.time() - start, 1)          # schnelle Abfrage wartet nicht auf den Wächter
        rc, out = self.sh("programm-gibt-es-nicht", "-v")
        self.assertEqual(rc, 127)

    def test_zeitlimit(self):
        start = time.time()
        rc, _ = self.sh("sleep", "20", sekunden=1)
        self.assertEqual(rc, 128 + 9)
        self.assertLess(time.time() - start, 5)

    @unittest.skipUnless(os.path.isdir("/proc/self"), "Nachkommen werden über /proc ermittelt (Linux)")
    def test_zeitlimit_beendet_nachkommen(self):
        # Programm mit Kind (Wrapper): bei Ablauf beide beendet, sonst hielte das Kind die Ausgabe offen
        start = time.time()
        rc, _ = self.sh("sh", "-c", "sleep 20 & sleep 20 & wait", sekunden=1, zombies=True)
        self.assertEqual(rc, 128 + 9)
        self.assertLess(time.time() - start, 5)

    def test_probe_ueber_shell(self):
        c = mock.Mock(has_sh=True, spec=["has_sh", "exec"])
        c.exec.return_value = (0, "")
        scanner.Container.probe(c, ["/usr/bin/node", "-v"], "33:33")
        cmd = c.exec.call_args[0][0]
        self.assertEqual(cmd, ["sh", "-c", scanner.PROBE_SH, "sh", "50", "/usr/bin/node", "-v"])
        self.assertEqual((c.exec.call_args[1]["user"], c.exec.call_args[1]["timeout"]), ("33:33", 60))
        c.has_sh = False                                    # ohne Shell: direkt, nur Zeitlimit von docker exec
        scanner.Container.probe(c, ["/usr/bin/node", "-v"], "33:33")
        self.assertEqual(c.exec.call_args[0][0], ["/usr/bin/node", "-v"])


class Container_(unittest.TestCase):
    def test_befehle_im_container_ueber_sicheren_pfad(self):
        # sonst könnte die Anwendung z.B. ein "sh" in /opt/venv/bin ablegen, das der Scan als root startet
        info = {"Id": "abc", "Name": "/web", "State": {"Running": True}}
        aufrufe = []

        def run(cmd, *a, **kw):
            aufrufe.append(cmd)
            return (0, scanner.json.dumps([info])) if cmd[:2] == ["docker", "inspect"] else (0, "find\ntar\n")
        with mock.patch.object(scanner, "run", side_effect=run):
            c = scanner.Container("web", "0")
            c.exec(["rpm", "-qa"])
            c.probe(["/usr/bin/node", "-v"], "33:33")
            c.probe(["node", "-v"], scanner.NOBODY, path=None)
        execs = [x for x in aufrufe if x[:2] == ["docker", "exec"]]
        self.assertEqual(len(execs), 5)          # sh -c exit 0, Werkzeuge, rpm, zwei Versionsabfragen
        for cmd in execs[:4]:
            self.assertTrue(enthaelt(cmd, SAFE), cmd)
            self.assertLess(cmd.index("-e"), cmd.index("abc"))       # Option vor dem Container
        self.assertFalse(any(x.startswith("PATH=") for x in execs[4]))
        with mock.patch.object(scanner, "stream_tar", return_value=True) as st:
            scanner.collect_files(c)
        self.assertTrue(enthaelt(st.call_args[0][0], SAFE))
        self.assertTrue(enthaelt(st.call_args[0][0], ["-w", "/"]))

    def test_volumes_ohne_systempfade(self):
        info = {"Id": "abc", "Name": "/web", "State": {"Running": True}, "Mounts": [
            {"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/var/www"},
            {"Type": "bind", "Source": "/srv/app", "Destination": "/app"},
            {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
            {"Type": "bind", "Source": "/", "Destination": "/host"},
            {"Type": "bind", "Source": "/srv/proc", "Destination": "/proc/x"}]}

        def run(cmd, *a, **kw):
            if cmd[:2] == ["docker", "inspect"]:
                return 0, scanner.json.dumps([info])
            return 0, "find\ntar\nawk\nsed\ntr\nsort\nreadlink\n"
        with mock.patch.object(scanner, "run", side_effect=run):
            c = scanner.Container("web", "0")
        self.assertEqual((c.name, c.mounts), ("web", ["/app", "/var/www"]))
        self.assertTrue(c.has_find_tar and c.has_proc_tools and c.has_sh)

    def test_nicht_gefunden_oder_gestoppt(self):
        with mock.patch.object(scanner, "run", return_value=(1, "")):
            with self.assertRaises(scanner.ScanError):
                scanner.Container("fehlt", "0")
        info = {"Id": "abc", "Name": "/x", "State": {"Running": False}}
        with mock.patch.object(scanner, "run", return_value=(0, scanner.json.dumps([info]))):
            with self.assertRaisesRegex(scanner.ScanError, "läuft nicht"):
                scanner.Container("x", "0")


if __name__ == "__main__":
    unittest.main()
