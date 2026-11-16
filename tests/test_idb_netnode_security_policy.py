import os
import pathlib
import sys
import unittest
from unittest import mock
from importlib.machinery import ModuleSpec

_SRC_PATH = pathlib.Path(__file__).resolve().parents[1] / "src"


class TestIdbNetnodeSecurityPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_sys_modules = dict(sys.modules)
        cls._orig_sys_path = list(sys.path)
        cls._orig_meta_path = list(sys.meta_path)

        if str(_SRC_PATH) not in sys.path:
            sys.path.insert(0, str(_SRC_PATH))

        class _IdaImporter:
            def find_spec(self, fullname, path, target=None):
                if (
                    fullname.startswith("ida_") and not fullname.startswith("ida_pro_mcp")
                ) or fullname in ("idaapi", "idc", "idautils"):
                    if fullname not in sys.modules:
                        m = mock.MagicMock()
                        if fullname == "idaapi":
                            m.get_kernel_version.return_value = "9.0"
                            m.execute_sync = lambda fn, req: fn()
                        sys.modules[fullname] = m
                    spec = ModuleSpec(fullname, None)
                    spec.loader = mock.MagicMock()
                    return spec
                return None

        cls._importer = _IdaImporter()
        sys.meta_path.insert(0, cls._importer)

        import idaapi

        idaapi.get_kernel_version.return_value = "9.0"
        idaapi.execute_sync = lambda fn, req: fn()
        sys.modules["idaapi"] = idaapi

        from ida_pro_mcp.ida_mcp import http

        cls.http = http

        import importlib.util

        _ida_mcp_path = _SRC_PATH / "ida_pro_mcp" / "ida_mcp.py"
        spec = importlib.util.spec_from_file_location("ida_mcp_plugin", str(_ida_mcp_path))
        cls.ida_mcp_plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.ida_mcp_plugin)

    @classmethod
    def tearDownClass(cls):
        sys.meta_path[:] = cls._orig_meta_path
        sys.path[:] = cls._orig_sys_path
        # Clean up any mocked modules added during testing
        added_mods = [k for k in sys.modules if k not in cls._orig_sys_modules]
        for k in added_mods:
            sys.modules.pop(k, None)

    def setUp(self):
        os.environ.pop("IDA_MCP_TRUST_IDB_CONFIG", None)

    def tearDown(self):
        os.environ.pop("IDA_MCP_TRUST_IDB_CONFIG", None)

    def test_autostart_disabled_when_stored_in_idb_without_trust_env(self):
        fake_node = mock.MagicMock()
        fake_node.altval.return_value = 2  # autostart explicitly set to on in IDB netnode

        with mock.patch.object(self.ida_mcp_plugin.ida_netnode, "netnode", return_value=fake_node):
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertFalse(self.ida_mcp_plugin.is_idb_config_trusted())
                self.assertFalse(self.ida_mcp_plugin._get_autostart())

    def test_autostart_enabled_when_stored_in_idb_with_trust_env(self):
        fake_node = mock.MagicMock()
        fake_node.altval.return_value = 2

        with mock.patch.object(self.ida_mcp_plugin.ida_netnode, "netnode", return_value=fake_node):
            with mock.patch.dict(os.environ, {"IDA_MCP_TRUST_IDB_CONFIG": "1"}):
                self.assertTrue(self.ida_mcp_plugin.is_idb_config_trusted())
                self.assertTrue(self.ida_mcp_plugin._get_autostart())

    def test_autostart_off_when_explicitly_disabled_in_idb(self):
        fake_node = mock.MagicMock()
        fake_node.altval.return_value = 1  # 1 = off

        with mock.patch.object(self.ida_mcp_plugin.ida_netnode, "netnode", return_value=fake_node):
            with mock.patch.dict(os.environ, {"IDA_MCP_TRUST_IDB_CONFIG": "1"}):
                self.assertFalse(self.ida_mcp_plugin._get_autostart())

    def test_cors_unrestricted_rejected_without_trust_env(self):
        with mock.patch.object(self.http, "config_json_get", return_value="unrestricted"):
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertFalse(self.http.is_idb_config_trusted())
                self.assertEqual(self.http.get_cors_policy(13337), "127.0.0.1 localhost")

    def test_cors_unrestricted_accepted_with_trust_env(self):
        with mock.patch.object(self.http, "config_json_get", return_value="unrestricted"):
            for truthy_val in ("1", "true", "yes", "True", "YES"):
                with mock.patch.dict(os.environ, {"IDA_MCP_TRUST_IDB_CONFIG": truthy_val}):
                    self.assertTrue(self.http.is_idb_config_trusted())
                    self.assertEqual(self.http.get_cors_policy(13337), "*")

    def test_handler_update_cors_policy_falls_back_when_untrusted(self):
        fake_mcp_server = mock.MagicMock()
        fake_mcp_server.cors_localhost = "127.0.0.1 localhost"
        fake_mcp_server.cors_allowed_origins = None

        handler = mock.MagicMock()
        handler.mcp_server = fake_mcp_server

        with mock.patch.object(self.http, "config_json_get", return_value="unrestricted"):
            with mock.patch.dict(os.environ, {}, clear=True):
                self.http.IdaMcpHttpRequestHandler.update_cors_policy(handler)
                self.assertEqual(fake_mcp_server.cors_allowed_origins, "127.0.0.1 localhost")


if __name__ == "__main__":
    unittest.main()
