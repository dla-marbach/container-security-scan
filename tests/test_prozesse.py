"""Prozesse aus /proc: Programm, Ports, geladene Dateien, Umgebung – je Prozess-Benutzer gelesen."""
import subprocess
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
                   "S\t1\t555\nC\t555\t020012AC:D432\t050012AC:0BB8\n",
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
        self.assertEqual(fremd, {"8080": "alle"})
        self.assertEqual(list(procs["1"]["verbindungen"]), [("172.18.0.5", "3000")])
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
        self.assertFalse(c.has_timeout)

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
