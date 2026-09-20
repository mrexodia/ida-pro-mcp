"""Registry entries must stay discoverable when the server bound a wildcard.

A bind address is not necessarily a connectable one: connect("0.0.0.0") /
connect("::") fail with WSAEADDRNOTAVAIL on Windows, and discover_instances()
read that as "instance dead" and deleted the registration of a live server.
"""

import os
import pathlib
import socket
import sys
import tempfile
import threading
import unittest

_DISCOVERY_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_DISCOVERY_SRC))
try:
    import discovery
finally:
    sys.path.remove(str(_DISCOVERY_SRC))


class ConnectableHostTests(unittest.TestCase):
    def test_wildcard_binds_map_to_loopback(self):
        self.assertEqual(discovery._connectable_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(discovery._connectable_host("::"), "::1")

    def test_other_hosts_pass_through(self):
        for host in ("127.0.0.1", "::1", "192.168.1.10", "localhost", ""):
            self.assertEqual(discovery._connectable_host(host), host)


class DiscoverWildcardInstanceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._original_dir = discovery.get_instances_dir
        discovery.get_instances_dir = lambda: self._tmp.name

        self._stop = threading.Event()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(5)
        self._port = self._listener.getsockname()[1]
        self._acceptor = threading.Thread(target=self._accept_forever, daemon=True)
        self._acceptor.start()

    def tearDown(self):
        discovery.get_instances_dir = self._original_dir
        self._stop.set()
        self._listener.close()
        self._acceptor.join(timeout=2)
        self._tmp.cleanup()

    def _accept_forever(self):
        self._listener.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            connection.close()

    def test_live_instance_registered_on_wildcard_host_survives(self):
        path = discovery.register_instance(
            "0.0.0.0", self._port, os.getpid(), "wild.bin", "wild.idb"
        )
        found = discovery.discover_instances()
        self.assertEqual(len(found), 1, "live instance was pruned as unreachable")
        self.assertTrue(os.path.isfile(path), "registration file was deleted")
        self.assertEqual(
            found[0]["host"], "127.0.0.1", "consumers got an address they cannot connect to"
        )

    def test_loopback_instance_still_discovered(self):
        discovery.register_instance(
            "127.0.0.1", self._port, os.getpid(), "ok.bin", "ok.idb"
        )
        found = discovery.discover_instances()
        self.assertEqual([i["host"] for i in found], ["127.0.0.1"])

    def test_dead_instance_on_wildcard_host_is_still_pruned(self):
        discovery.register_instance("0.0.0.0", 1, os.getpid(), "dead.bin", "dead.idb")
        self.assertEqual(discovery.discover_instances(), [])


if __name__ == "__main__":
    unittest.main()
