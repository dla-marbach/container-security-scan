"""Prozesse aus /proc: Programm, Ports, geladene Dateien, Umgebung – je Prozess-Benutzer gelesen."""
import unittest
from unittest import mock

from _laden import scanner


class Adressen(unittest.TestCase):
    def test_decode_addr(self):
        self.assertEqual(scanner.decode_addr("00000000"), "alle")
        self.assertEqual(scanner.decode_addr("00000000000000000000000000000000"), "alle")
        self.assertEqual(scanner.decode_addr("0100007F"), "localhost")
        self.assertEqual(scanner.decode_addr("0100A8C0"), "192.168.0.1")
        self.assertEqual(scanner.decode_addr("000080FE00000000FF0F00000100A8C0"), "IPv6")


class Prozesse(unittest.TestCase):
    def test_je_benutzer_gelesen_und_ports_zugeordnet(self):
        c = mock.Mock(has_sh=True, has_proc_tools=True)
        ausgaben = {
            "0:0": "P\t1\t/usr/sbin/nginx\t/\tnginx: master process nginx\x1f-g\x1fdaemon off;\t0:0\n"
                   "S\t1\t111\nS\t1\t333\nM\t1\t/usr/lib/x86_64-linux-gnu/libssl.so.3\n"
                   "T\t111\t00000000:0050\ttcp\nT\t333\t00000000:0035\tudp\n",
            "33:33": "P\t7\t/usr/local/bin/node (deleted)\t/app\tnode\x1fserver.js\t33:33\n"
                     "E\t7\tPATH=/usr/local/bin:/usr/bin\nF\t7\t/app/data.db\nS\t7\t222\n"
                     "T\t222\t0100007F:0BB8\ttcp\n"}
        aufrufe = []

        def sh(script, binary=False, user=None, args=()):
            aufrufe.append((user, list(args)))
            if user is None:
                return 0, "1 0:0\n7 33:33\n9 33:33\n"
            return 0, ausgaben[user]
        c.sh.side_effect = sh
        procs, how = scanner.collect_procs(c)
        self.assertEqual(how, "im Container (je Prozess-Benutzer)")
        self.assertIn(("33:33", ["7", "9"]), aufrufe)
        self.assertEqual(procs["1"]["ports"], {"80": "alle", "53/udp": "alle"})
        self.assertEqual(procs["1"]["argv"], ["nginx: master process nginx", "-g", "daemon off;"])
        node = procs["7"]
        self.assertEqual((node["exe"], node["base"], node["cwd"], node["user"]), ("/usr/local/bin/node", "node", "/app", "33:33"))
        self.assertEqual(node["ports"], {"3000": "localhost"})
        self.assertEqual(node["label"], "node:3000")
        self.assertEqual(node["env"], {"PATH": "/usr/local/bin:/usr/bin"})
        self.assertEqual(node["files"], {"/app/data.db"})

    def test_ohne_shell_ueber_proc_des_hosts(self):
        c = mock.Mock(has_sh=False, id="abc")
        with mock.patch.object(scanner, "run", side_effect=[(0, "PID\n4242\n"), (0, "P\t4242\t/app\t/\tapp\t:\n")]) as run:
            procs, how = scanner.collect_procs(c)
        self.assertEqual(how, "über /proc des Hosts")
        self.assertEqual(run.call_args_list[1][0][0], ["sh", "-s", "--", "4242"])
        self.assertEqual((procs["4242"]["exe"], procs["4242"]["user"]), ("/app", ""))


class Container_(unittest.TestCase):
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
