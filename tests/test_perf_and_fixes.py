"""Unit tests covering performance optimizations and bug fixes in PR branch."""

import hashlib
import importlib
import os
import pathlib
import sys
import tempfile
import threading
import types
import unittest
import zlib
from contextlib import contextmanager

_REPO_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"


def _make_ida_stubs(overrides: dict[str, types.ModuleType] | None = None) -> dict[str, types.ModuleType]:
    """Build minimal fake IDA Pro modules so ida_mcp submodules import offline."""
    names = (
        "idaapi",
        "idautils",
        "idc",
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_bytes",
        "ida_dbg",
        "ida_dirtree",
        "ida_diskio",
        "ida_entry",
        "ida_enum",
        "ida_expr",
        "ida_fixup",
        "ida_fpro",
        "ida_frame",
        "ida_funcs",
        "ida_gdl",
        "ida_graph",
        "ida_hexrays",
        "ida_ida",
        "ida_idaapi",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_kernwin",
        "ida_libfuncs",
        "ida_lines",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_nalt",
        "ida_name",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_regfinder",
        "ida_registry",
        "ida_search",
        "ida_segment",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_typeinf",
        "ida_ua",
        "ida_undo",
        "ida_xref",
    )
    stubs = {name: types.ModuleType(name) for name in names}

    # Common attributes expected at import time by ida_mcp modules.
    stubs["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["idaapi"].SDK_VERSION = 900
    stubs["idaapi"].o_void = 0
    stubs["idaapi"].o_reg = 1
    stubs["idaapi"].o_mem = 2
    stubs["idaapi"].o_phrase = 3
    stubs["idaapi"].o_displ = 4
    stubs["idaapi"].o_imm = 5
    stubs["idaapi"].o_far = 6
    stubs["idaapi"].o_near = 7
    stubs["idaapi"].o_idpspec0 = 8
    stubs["idaapi"].o_idpspec1 = 9
    stubs["idaapi"].o_idpspec2 = 10
    stubs["idaapi"].o_idpspec3 = 11
    stubs["idaapi"].o_idpspec4 = 12
    stubs["idaapi"].o_idpspec5 = 13
    stubs["idaapi"].insn_t = type("insn_t", (), {"itype": 0, "ops": ()})
    stubs["ida_ua"].insn_t = stubs["idaapi"].insn_t
    stubs["ida_dbg"].bpt_t = type("bpt_t", (), {})
    stubs["ida_hexrays"].cfunc_t = type("cfunc_t", (), {})
    stubs["ida_hexrays"].lvar_saved_info_t = type("lvar_saved_info_t", (), {})
    stubs["ida_idd"].regval_t = type("regval_t", (), {})
    stubs["ida_idd"].regvals_t = type("regvals_t", (), {})
    stubs["ida_kernwin"].simpleline_t = type("simpleline_t", (), {})
    stubs["ida_typeinf"].til_t = type("til_t", (), {})
    stubs["ida_typeinf"].udm_t = type("udm_t", (), {})
    stubs["ida_xref"].xrefblk_t = type("xrefblk_t", (), {})
    stubs["idaapi"].NN_call = 16
    stubs["idaapi"].NN_callfi = 17
    stubs["idaapi"].NN_callni = 18
    stubs["idaapi"].ITP_SEMI = 0
    stubs["idaapi"].ITP_COLON = 2
    stubs["idaapi"].BWN_PSEUDOCODE = 48
    stubs["idaapi"].SEGPERM_EXEC = 1

    stubs["idaapi"].get_kernel_version = lambda: "9.0"
    stubs["ida_pro"].IDA_SDK_VERSION = 900
    stubs["ida_pro"].get_inf_version = lambda: "9.0"

    class _DefaultNetnode:
        def __init__(self, _name="", _idx=0, _create=False):
            pass

        def getblob(self, _idx, _tag):
            return None

        def setblob(self, _blob, _idx, _tag):
            pass

        def altval(self, _idx):
            return 0

        def altset(self, _idx, _val):
            pass

    stubs["ida_netnode"].netnode = _DefaultNetnode
    stubs["ida_nalt"].get_input_file_path = lambda: ""
    stubs["ida_loader"].get_path = lambda _t: ""

    stubs["ida_lines"].SCOLOR_REGCMT = "\x01"
    stubs["ida_lines"].SCOLOR_RPTCMT = "\x02"
    stubs["ida_lines"].SCOLOR_AUTOCMT = "\x03"
    stubs["ida_lines"].SCOLOR_COLLAPSED = "\x04"
    stubs["ida_lines"].COLOR_ON = "\x01"
    stubs["ida_lines"].tag_remove = lambda s: s

    stubs["ida_nalt"].STRTYPE_C = 0
    stubs["ida_dbg"].DBG_Hooks = type("DBG_Hooks", (), {})
    stubs["ida_idp"].IDB_Hooks = type("IDB_Hooks", (), {"hook": lambda self: False, "unhook": lambda self: True})
    stubs["ida_hexrays"].DECOMP_WARNINGS = 0
    stubs["ida_hexrays"].user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
    stubs["ida_kernwin"].execute_sync = lambda fn, flags: fn()
    stubs["ida_kernwin"].MFF_READ = 0
    stubs["ida_kernwin"].MFF_WRITE = 1
    stubs["ida_kernwin"].MFF_NOWAIT = 2
    stubs["ida_kernwin"].user_cancelled = lambda: False
    stubs["ida_kernwin"].clr_cancelled = lambda: None
    stubs["ida_kernwin"].set_cancelled = lambda: None
    stubs["idaapi"].execute_sync = lambda fn, flags: fn()
    stubs["idaapi"].MFF_READ = 0
    stubs["idaapi"].MFF_WRITE = 1
    stubs["idaapi"].MFF_NOWAIT = 2
    stubs["idc"].batch = lambda _v: 0

    stubs["ida_dirtree"].DIRTREE_FUNCS = 1
    stubs["ida_dirtree"].DTE_OK = 0
    stubs["ida_dirtree"].DTE_ALREADY_EXISTS = 1

    stubs["ida_typeinf"].TINFO_DEFINITE = 1
    stubs["ida_typeinf"].tinfo_t = type(
        "tinfo_t", (), {"get_udm": lambda self, name: (-1, None)}
    )
    stubs["ida_funcs"].func_t = type(
        "func_t",
        (),
        {"get_name": lambda self: "", "get_prototype": lambda self: ""},
    )
    stubs["ida_entry"].get_entry_qty = lambda: 0
    stubs["ida_entry"].get_entry_ordinal = lambda _idx: 0
    stubs["ida_entry"].get_entry = lambda _ord: 0
    stubs["ida_entry"].get_entry_name = lambda _ord: None
    stubs["ida_loader"].PATH_TYPE_IDB = 0
    stubs["ida_loader"].DBFL_COMP = 1
    stubs["ida_bytes"].FF_0NUMH = 0x1
    stubs["ida_bytes"].FF_0NUMD = 0x2
    stubs["ida_bytes"].FF_0CHAR = 0x3
    stubs["ida_bytes"].FF_0NUMB = 0x4
    stubs["ida_bytes"].FF_0NUMO = 0x5

    if overrides:
        stubs.update(overrides)
    return stubs


@contextmanager
def _mocked_ida_env(extra_stubs: dict[str, types.ModuleType] | None = None):
    """Install temporary IDA stubs and restore sys.modules completely on exit."""
    src_str = str(_REPO_SRC)
    added_path = False
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
        added_path = True

    saved = dict(sys.modules)
    try:
        # Force clean re-import of ida_pro_mcp modules under mocks so they don't reuse
        # partially stubbed modules from elsewhere and never leak back into sys.modules.
        for key in list(sys.modules.keys()):
            if (
                key == "ida_pro_mcp"
                or key.startswith(("ida_pro_mcp.", "ida"))
                or key in ("idc", "idautils")
            ):
                sys.modules.pop(key, None)

        stubs = _make_ida_stubs(extra_stubs)
        sys.modules.update(stubs)
        yield stubs
    finally:
        trace_mod = sys.modules.get("ida_pro_mcp.ida_mcp.trace")
        if trace_mod is not None and hasattr(trace_mod, "shutdown"):
            trace_mod.shutdown()
        for key in list(sys.modules.keys()):
            if key not in saved:
                del sys.modules[key]
        sys.modules.update(saved)
        if added_path and src_str in sys.path:
            sys.path.remove(src_str)


class DiscoveryPidTests(unittest.TestCase):
    def test_is_pid_alive_rejects_invalid_and_bool(self):
        with _mocked_ida_env():
            from ida_pro_mcp.ida_mcp import discovery

            self.assertFalse(discovery.is_pid_alive(True))
            self.assertFalse(discovery.is_pid_alive(False))
            self.assertFalse(discovery.is_pid_alive(0))
            self.assertFalse(discovery.is_pid_alive(-42))
            self.assertFalse(discovery.is_pid_alive("123"))  # type: ignore[arg-type]
            self.assertTrue(discovery.is_pid_alive(os.getpid()))

    @unittest.skipUnless(sys.platform == "win32", "Windows-specific handle check")
    def test_is_pid_alive_checks_still_active_and_closes_handle(self):
        import ctypes
        from ctypes import wintypes

        with _mocked_ida_env():
            from ida_pro_mcp.ida_mcp import discovery

            closed_handles: list[int] = []

            class FakeKernel32:
                def __init__(self, open_handle: int, exit_code: int, get_exit_ok: bool = True):
                    self._open_handle = open_handle
                    self._exit_code = exit_code
                    self._get_exit_ok = get_exit_ok

                def OpenProcess(self, access, inherit, pid):
                    return self._open_handle

                def GetExitCodeProcess(self, handle, out_ptr):
                    if not self._get_exit_ok:
                        return 0
                    ptr_type = ctypes.POINTER(wintypes.DWORD)
                    ctypes.cast(out_ptr, ptr_type)[0] = self._exit_code
                    return 1

                def CloseHandle(self, handle):
                    closed_handles.append(handle)
                    return 1

            orig_windll = ctypes.windll
            try:
                fake_windll = types.SimpleNamespace(kernel32=FakeKernel32(101, 0))
                ctypes.windll = fake_windll
                self.assertFalse(discovery.is_pid_alive(99999))
                self.assertEqual(closed_handles, [101])

                closed_handles.clear()
                fake_windll.kernel32 = FakeKernel32(202, 259)
                self.assertTrue(discovery.is_pid_alive(99999))
                self.assertEqual(closed_handles, [202])

                closed_handles.clear()
                fake_windll.kernel32 = FakeKernel32(0, 259)
                self.assertFalse(discovery.is_pid_alive(99999))
                self.assertEqual(closed_handles, [])
            finally:
                ctypes.windll = orig_windll


class CompatTests(unittest.TestCase):
    def test_ida_85_imports_ida_ida(self):
        with _mocked_ida_env() as stubs:
            stubs["idaapi"].SDK_VERSION = 850
            stubs["idaapi"].get_kernel_version = lambda: "8.5"
            stubs["ida_pro"].IDA_SDK_VERSION = 850
            stubs["ida_pro"].get_inf_version = lambda: "8.5"
            stubs["ida_ida"].inf_get_min_ea = lambda: 0x1000
            stubs["ida_ida"].inf_get_max_ea = lambda: 0x2000

            compat = importlib.import_module("ida_pro_mcp.ida_mcp.compat")
            self.assertTrue(compat.IDA_GE_85)
            self.assertFalse(compat.IDA_GE_90)
            self.assertEqual(compat.inf_get_min_ea(), 0x1000)


class RpcAndHttpCacheTests(unittest.TestCase):
    def test_output_cache_lru_eviction_and_thread_safety(self):
        with _mocked_ida_env():
            from ida_pro_mcp.ida_mcp import rpc

            rpc._output_cache.clear()
            try:
                for i in range(rpc.OUTPUT_CACHE_MAX_SIZE):
                    rpc._cache_output(f"k{i}", i)

                # Touch k0 so it becomes most-recently-used; k1 becomes oldest.
                self.assertEqual(rpc.get_cached_output("k0"), 0)
                rpc._cache_output("k_new", 999)

                self.assertIsNone(rpc.get_cached_output("k1"))
                self.assertEqual(rpc.get_cached_output("k0"), 0)
                self.assertEqual(rpc.get_cached_output("k_new"), 999)

                # Concurrent hammering stays bounded and exception-free.
                errors: list[Exception] = []

                def worker(tid: int):
                    try:
                        for j in range(150):
                            key = f"t{tid}_{j}"
                            rpc._cache_output(key, j)
                            rpc.get_cached_output(key)
                    except (RuntimeError, LookupError, TypeError, ValueError) as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
                for th in threads:
                    th.start()
                for th in threads:
                    th.join(timeout=5)
                self.assertEqual(errors, [])
                self.assertLessEqual(len(rpc._output_cache), rpc.OUTPUT_CACHE_MAX_SIZE)
            finally:
                rpc._output_cache.clear()

    def test_cors_policy_cached_and_applied_during_setup(self):
        with _mocked_ida_env() as stubs:
            calls = {"get": 0, "set": 0}

            netnode_store: dict[str, bytes] = {}

            class FakeNetnode:
                def __init__(self, name, _idx=0, _create=False):
                    self.name = name

                def getblob(self, _idx, _tag):
                    return netnode_store.get(self.name)

                def setblob(self, blob, _idx, _tag):
                    netnode_store[self.name] = blob

            stubs["ida_netnode"].netnode = FakeNetnode

            http_mod = importlib.import_module("ida_pro_mcp.ida_mcp.http")
            api_core = importlib.import_module("ida_pro_mcp.ida_mcp.api_core")
            mainthread_mod = importlib.import_module("ida_pro_mcp.ida_mcp.mainthread")
            http_mod.invalidate_cors_policy_cache()

            entered_fetch = threading.Event()
            release_fetch = threading.Event()
            block_next_fetch = False

            def fake_get(key, default=None):
                calls["get"] += 1
                if block_next_fetch:
                    entered_fetch.set()
                    release_fetch.wait(timeout=2)
                    return "unrestricted"
                return "unrestricted" if calls["get"] == 1 else "direct"

            http_mod.config_json_get = fake_get

            class DummyServer:
                mcp_server = types.SimpleNamespace(
                    cors_allowed_origins=None,
                    cors_localhost=lambda origin: origin == "http://localhost",
                    _register_http_connection=lambda _req: None,
                    _unregister_http_connection=lambda _req: None,
                )

            errors_sent: list[tuple[int, str]] = []
            orig_setup = http_mod.McpHttpRequestHandler.setup
            orig_handle = http_mod.McpHttpRequestHandler.handle
            orig_finish = http_mod.McpHttpRequestHandler.finish
            orig_check = http_mod.McpHttpRequestHandler._check_api_request
            orig_send_error = http_mod.McpHttpRequestHandler.send_error
            pump = mainthread_mod.get_pump()
            orig_current_job = pump._current
            try:
                http_mod.McpHttpRequestHandler.setup = lambda self: None
                http_mod.McpHttpRequestHandler.handle = lambda self: None
                http_mod.McpHttpRequestHandler.finish = lambda self: None
                http_mod.McpHttpRequestHandler._check_api_request = lambda self: True
                http_mod.McpHttpRequestHandler.send_error = (
                    lambda self, code, message=None, explain=None: errors_sent.append(
                        (code, str(message))
                    )
                )

                handler = http_mod.IdaMcpHttpRequestHandler(object(), ("127.0.0.1", 1234), DummyServer())
                handler.headers = {}

                # Non-Origin requests (ping, server_health, cancel) must NOT block on IDA even during idb_open.
                pump._current = mainthread_mod._Job(lambda: None, "idb_open")
                self.assertTrue(handler._check_api_request())
                self.assertEqual(calls["get"], 0)

                # Browser Origin requests fail fast with 503 when cache is empty and pump is busy.
                handler.headers = {"Origin": "http://example.com"}
                self.assertFalse(handler._check_api_request())
                self.assertEqual(errors_sent[-1][0], 503)
                self.assertEqual(calls["get"], 0)
                pump._current = orig_current_job

                # When idle, first Origin request loads policy once; subsequent requests hit cache.
                self.assertTrue(handler._check_api_request())
                self.assertTrue(handler._check_api_request())
                self.assertEqual(DummyServer.mcp_server.cors_allowed_origins, "*")
                self.assertEqual(calls["get"], 1)

                # DB switch via invalidate_strings_cache leaves CORS invalid until next open/Origin request.
                api_core.invalidate_strings_cache()
                self.assertIsNone(http_mod._cached_cors_policy)
                self.assertTrue(handler._check_api_request())
                self.assertEqual(calls["get"], 2)
                self.assertIsNone(DummyServer.mcp_server.cors_allowed_origins)

                # Failed netnode persistence must NOT publish the requested policy.
                orig_setblob = FakeNetnode.setblob
                FakeNetnode.setblob = lambda self, _b, _i, _t: False
                try:
                    self.assertFalse(
                        http_mod._save_and_publish_cors_policy.__wrapped__(
                            DummyServer.mcp_server, "unrestricted"
                        )
                    )
                    self.assertIsNone(DummyServer.mcp_server.cors_allowed_origins)
                finally:
                    FakeNetnode.setblob = orig_setblob

                # Concurrent slow refresh reading stale "unrestricted" must not overwrite newer "direct".
                block_next_fetch = True
                refresher = threading.Thread(
                    target=handler.update_cors_policy, kwargs={"refresh": True}
                )
                refresher.start()
                self.assertTrue(entered_fetch.wait(timeout=2))
                self.assertTrue(
                    http_mod._save_and_publish_cors_policy.__wrapped__(
                        DummyServer.mcp_server, "direct"
                    )
                )
                release_fetch.set()
                refresher.join(timeout=2)
                self.assertIsNone(DummyServer.mcp_server.cors_allowed_origins)
                saved_blob = netnode_store.get("$ ida_mcp.cors_policy")
                self.assertEqual(saved_blob, b'"direct"')

                # IDP/IDB hooks update/invalidate MCP_SERVER policy on ev_newfile / ev_oldfile / closebase.
                class RecordingIdbHook:
                    def hook(self):
                        return True

                class RecordingIdpHook:
                    def hook(self):
                        return True

                stubs["ida_idp"].IDB_Hooks = RecordingIdbHook
                stubs["ida_idp"].IDP_Hooks = RecordingIdpHook
                http_mod._cors_idb_hook = None
                http_mod._cors_idp_hook = None
                http_mod._install_cors_idb_hook()
                self.assertIsNotNone(http_mod._cors_idb_hook)
                self.assertIsNotNone(http_mod._cors_idp_hook)
                block_next_fetch = False
                http_mod._cors_idp_hook.ev_newfile()
                self.assertIsNone(http_mod.MCP_SERVER.cors_allowed_origins)
                http_mod._cors_idb_hook.closebase()
                self.assertIsNone(http_mod._cached_cors_policy)

                # Mid-read IDB invalidation retries and enforces new IDB's policy.
                retry_reads = 0

                def switching_get(_key, _default=None):
                    nonlocal retry_reads
                    retry_reads += 1
                    if retry_reads == 1:
                        http_mod.invalidate_cors_policy_cache()
                        return "unrestricted"
                    return "direct"

                http_mod.invalidate_cors_policy_cache()
                http_mod.config_json_get = switching_get
                http_mod._sync_cors_policy(DummyServer.mcp_server)
                self.assertEqual(retry_reads, 2)
                self.assertIsNone(DummyServer.mcp_server.cors_allowed_origins)
            finally:
                pump._current = orig_current_job
                http_mod.McpHttpRequestHandler.setup = orig_setup
                http_mod.McpHttpRequestHandler.handle = orig_handle
                http_mod.McpHttpRequestHandler.finish = orig_finish
                http_mod.McpHttpRequestHandler._check_api_request = orig_check
                http_mod.McpHttpRequestHandler.send_error = orig_send_error


class HashingAndSurveyTests(unittest.TestCase):
    def test_chunked_file_hashing_matches_full_hashes(self):
        payload = (b"IDA-MCP-CHUNK-TEST" * 100_000)  # > 1.8 MB (> 1 MB chunk size)
        expected_md5 = hashlib.md5(payload).hexdigest()
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        expected_crc32 = hex(zlib.crc32(payload) & 0xFFFFFFFF)
        expected_size = hex(len(payload))

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = pathlib.Path(tmpdir) / "sample.bin"
            sample.write_bytes(payload)

            with _mocked_ida_env() as stubs:
                stubs["idc"].get_idb_path = lambda: str(sample) + ".idb"
                stubs["ida_nalt"].get_input_file_path = lambda: str(sample)
                stubs["ida_nalt"].get_root_filename = lambda: "sample.bin"
                stubs["ida_loader"].get_path = lambda _t: str(sample) + ".idb"
                stubs["idaapi"].get_imagebase = lambda: 0x400000
                stubs["ida_ida"].inf_get_procname = lambda: "metapc"
                stubs["ida_ida"].inf_is_64bit = lambda: True
                stubs["ida_ida"].inf_is_32bit_exactly = lambda: False
                stubs["ida_ida"].inf_get_min_ea = lambda: 0x400000
                stubs["ida_ida"].inf_get_max_ea = lambda: 0x401000
                stubs["ida_ida"].inf_get_omin_ea = lambda: 0x400000
                stubs["ida_ida"].inf_get_omax_ea = lambda: 0x401000
                stubs["ida_ida"].inf_is_be = lambda: False
                stubs["ida_segment"].get_segm_qty = lambda: 0
                stubs["idautils"].Segments = list
                stubs["idautils"].Functions = list
                stubs["idautils"].Entries = list
                stubs["idautils"].peutils_t = lambda: types.SimpleNamespace(header=lambda: b"")

                api_res = importlib.import_module("ida_pro_mcp.ida_mcp.api_resources")
                meta_res = api_res.idb_metadata_resource.__wrapped__()
                self.assertEqual(meta_res["md5"], expected_md5)
                self.assertEqual(meta_res["sha256"], expected_sha256)
                self.assertEqual(meta_res["crc32"], expected_crc32)
                self.assertEqual(meta_res["filesize"], expected_size)

                api_survey = importlib.import_module("ida_pro_mcp.ida_mcp.api_survey")
                survey_meta = api_survey._build_metadata()
                self.assertEqual(survey_meta["md5"], expected_md5)
                self.assertEqual(survey_meta["sha256"], expected_sha256)

    def test_interesting_functions_streams_xrefs_generator(self):
        with _mocked_ida_env() as stubs:
            stubs["idaapi"].FUNC_LIB = 1
            stubs["idaapi"].FUNC_THUNK = 2
            stubs["idaapi"].fl_CF = 17
            stubs["idaapi"].fl_CN = 19
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(
                start_ea=ea, end_ea=ea + 0x20, flags=0, size=lambda: 0x20
            )
            stubs["idaapi"].get_func_name = lambda ea: f"sub_{ea:x}"
            stubs["idc"].get_name = lambda ea, _flags=0: f"sub_{ea:x}"
            stubs["idautils"].Functions = lambda: [0x1000]
            stubs["idautils"].FuncItems = lambda ea: [ea]
            stubs["idautils"].XrefsFrom = lambda _ea, _f=0: iter(())
            stubs["ida_nalt"].get_str_type = lambda _ea: -1

            xref_iter_calls = 0

            def fake_xrefs_to(_ea, _flags=0):
                nonlocal xref_iter_calls
                xref_iter_calls += 1
                yield types.SimpleNamespace(frm=0x2000)
                yield types.SimpleNamespace(frm=0x3000)

            stubs["idautils"].XrefsTo = fake_xrefs_to
            api_survey = importlib.import_module("ida_pro_mcp.ida_mcp.api_survey")
            found = api_survey._build_interesting_functions([0x1000], False)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["xref_count"], 2)
            self.assertEqual(xref_iter_calls, 1)


class UtilsAndPythonTests(unittest.TestCase):
    def test_utils_reuse_and_caching(self):
        with _mocked_ida_env() as stubs:
            insn_inits = 0
            ctree_inits = 0

            class FakeInsn:
                def __init__(self):
                    nonlocal insn_inits
                    insn_inits += 1
                    self.itype = 0
                    self.ops = []

            class FakeCtreeItem:
                def __init__(self):
                    nonlocal ctree_inits
                    ctree_inits += 1

                def dstr(self):
                    return "0x401000: return 0"

            stubs["idaapi"].insn_t = FakeInsn
            stubs["ida_hexrays"].ctree_item_t = FakeCtreeItem
            stubs["ida_hexrays"].init_hexrays_plugin = lambda: True

            def fake_decode(insn, ea):
                if ea == 0x1000:
                    insn.itype = stubs["idaapi"].NN_call
                    insn.ops = [types.SimpleNamespace(type=stubs["idaapi"].o_imm, value=0x1234)]
                    return 2
                # Decode failure must NOT trigger NN_call from stale insn.itype
                return 0

            stubs["idaapi"].decode_insn = fake_decode
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
            stubs["ida_funcs"].get_func_name = lambda _ea: "f_test"
            stubs["idaapi"].getseg = lambda _ea: None
            stubs["idc"].find_func_end = lambda _ea: 0x1008
            stubs["idc"].next_head = lambda ea, _end: ea + 4
            stubs["idc"].get_operand_type = lambda _ea, _n: stubs["idaapi"].o_near if _n == 0 else stubs["idaapi"].o_void
            stubs["idc"].get_operand_value = lambda _ea, _n: 0x2000
            stubs["idc"].get_name = lambda ea: "callee_fn" if ea == 0x2000 else None
            stubs["idc"].print_insn_mnem = lambda _ea: "nop"
            stubs["idc"].print_operand = lambda _ea, _n: ""
            stubs["idautils"].FuncItems = lambda _ea: [0x1000, 0x1004]
            stubs["idautils"].CodeRefsTo = lambda _ea, _f=0: [0x1000, 0x1004]

            str_type_calls = 0
            str_content_calls = 0

            def fake_str_type(ea):
                nonlocal str_type_calls
                str_type_calls += 1
                return 0 if ea == 0x5000 else -1

            def fake_str_content(ea):
                nonlocal str_content_calls
                str_content_calls += 1
                return b"hello" if ea == 0x5000 else None

            stubs["ida_nalt"].get_str_type = fake_str_type
            stubs["idc"].get_strlit_contents = fake_str_content
            stubs["idautils"].XrefsFrom = lambda _ea, _f=0: [
                types.SimpleNamespace(iscode=False, to=0x5000),
                types.SimpleNamespace(iscode=False, to=0x6000),
            ]

            utils = importlib.import_module("ida_pro_mcp.ida_mcp.utils")

            # pattern_filter correctness across modes (including Windows slash normalization)
            items = [{"name": "Foo_Bar"}, {"name": "baz_qux"}, {"name": "FooBaz"}]
            self.assertEqual([x["name"] for x in utils.pattern_filter(items, "foo*z", "name")], ["FooBaz"])
            self.assertEqual([x["name"] for x in utils.pattern_filter(items, "foo", "name")], ["Foo_Bar", "FooBaz"])
            self.assertEqual([x["name"] for x in utils.pattern_filter(items, "/bar$/i", "name")], ["Foo_Bar"])
            self.assertEqual(
                len(utils.pattern_filter([{"name": "\u039f\u03a3_test"}], "\u03bf\u03c2*", "name")),
                1,
            )
            if os.name == "nt":
                win_paths = [{"path": r"C:\Program Files\app\bin.exe"}]
                self.assertEqual(len(utils.pattern_filter(win_paths, "C:/Program Files/*", "path")), 1)

            # get_callees, get_callers, extract_function_constants reuse insn_t & guard decode_insn <= 0
            callees = utils.get_callees("0x1000")
            self.assertEqual(len(callees), 1)
            callers = utils.get_callers("0x2000")
            self.assertEqual(len(callers), 1)
            consts = utils.extract_function_constants(0x1000)
            self.assertEqual(consts, [{"addr": "0x1000", "value": "0x1234", "decimal": 0x1234}])
            self.assertEqual(insn_inits, 3)

            # extract_function_strings caches repeated target EAs cleanly
            strs = utils.extract_function_strings(0x1000)
            self.assertEqual(len(strs), 2)
            self.assertEqual(str_type_calls, 2)
            self.assertEqual(str_content_calls, 1)
            strs[0]["string"] = "mutated"
            self.assertEqual(strs[1]["string"], "hello")

            # get_assembly_lines list-join formatting
            asm = utils.get_assembly_lines(0x1000)
            self.assertIn("f_test (UNKNOWN @ 0x1000):\n1000  nop\n1004  nop", asm)

            # decompile_function_safe reuses ctree_item_t and skips when include_addresses=False
            fake_cfunc = types.SimpleNamespace(
                get_pseudocode=lambda: [
                    types.SimpleNamespace(line="int a;"),
                    types.SimpleNamespace(line="return 0;"),
                ],
                get_line_item=lambda *_args: True,
            )
            utils.decompile_checked = lambda _ea: fake_cfunc
            code, err = utils.decompile_function_safe(0x1000, include_addresses=False)
            self.assertIsNone(err)
            self.assertEqual(code, "int a;\nreturn 0;")
            self.assertEqual(ctree_inits, 0)
            code_addr, err_addr = utils.decompile_function_safe(0x1000, include_addresses=True)
            self.assertIsNone(err_addr)
            self.assertEqual(code_addr, "int a; /*0x401000*/\nreturn 0; /*0x401000*/")
            self.assertEqual(ctree_inits, 3)

    def test_py_eval_caches_lazy_imports_and_preserves_stdout_on_error(self):
        with _mocked_ida_env():
            api_python = importlib.import_module("ida_pro_mcp.ida_mcp.api_python")
            import builtins

            import_calls = 0
            real_import = builtins.__import__

            def counting_import(name, *args, **kwargs):
                nonlocal import_calls
                if name == "idautils" or name.startswith("ida_"):
                    import_calls += 1
                return real_import(name, *args, **kwargs)

            orig_import = builtins.__import__
            builtins.__import__ = counting_import
            try:
                api_python._CACHED_LAZY_MODULES.clear()
                api_python._PENDING_LAZY_MODULES[:] = api_python._LAZY_EXEC_MODULES
                res1 = api_python.py_eval.__wrapped__("1 + 1", new_locals=True)
                first_imports = import_calls
                res2 = api_python.py_eval.__wrapped__("2 + 2")
                self.assertEqual(res1["result"], "2")
                self.assertEqual(res2["result"], "4")
                self.assertEqual(import_calls, first_imports)

                err_res = api_python.py_eval.__wrapped__(
                    "print('before crash')\n1 / 0", new_locals=True
                )
                self.assertEqual(err_res["stdout"], "before crash\n")
                self.assertIn("ZeroDivisionError", err_res["stderr"])

                err_no_out = api_python.py_eval.__wrapped__("1 / 0", new_locals=True)
                self.assertEqual(err_no_out["stdout"], "")
                self.assertIn("ZeroDivisionError", err_no_out["stderr"])

                err_closed = api_python.py_eval.__wrapped__(
                    "import sys; sys.stdout.close(); 1 / 0", new_locals=True
                )
                self.assertEqual(err_closed["stdout"], "")
                self.assertIn("ZeroDivisionError", err_closed["stderr"])

                # Previously failed lazy imports retry once the module becomes importable.
                api_python._CACHED_LAZY_MODULES.pop("ida_enum", None)
                api_python._PENDING_LAZY_MODULES[:] = ["ida_enum"]
                saved_enum = sys.modules.pop("ida_enum", None)
                try:
                    missing = api_python.py_eval.__wrapped__(
                        "ida_enum is None", new_locals=True
                    )
                    self.assertEqual(missing["result"], "True")
                    sys.modules["ida_enum"] = saved_enum  # type: ignore[assignment]
                    restored = api_python.py_eval.__wrapped__(
                        "ida_enum is not None", new_locals=True
                    )
                    self.assertEqual(restored["result"], "True")
                finally:
                    if saved_enum is not None:
                        sys.modules["ida_enum"] = saved_enum
            finally:
                builtins.__import__ = orig_import
                api_python._CACHED_LAZY_MODULES.clear()
                api_python._PENDING_LAZY_MODULES[:] = api_python._LAZY_EXEC_MODULES


class ModifyBatchAndRefreshTests(unittest.TestCase):
    def test_set_comments_caches_cfunc_and_isolates_refresh_errors(self):
        with _mocked_ida_env() as stubs:
            init_calls = 0
            decompile_calls = 0
            eamap_calls = 0
            refresh_calls: list[int] = []
            saved_cmts: dict[int, str] = {}

            def fake_init_hexrays():
                nonlocal init_calls
                init_calls += 1
                return True

            stubs["ida_hexrays"].init_hexrays_plugin = fake_init_hexrays
            stubs["idaapi"].set_cmt = lambda _ea, _cmt, _rpt: True
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(
                start_ea=0x1000 if ea < 0x2000 else 0x2000
            )
            stubs["idc"].set_func_cmt = lambda ea, cmt, _rpt: saved_cmts.setdefault(ea, cmt) or True

            class FakeTreeloc:
                ea = 0
                itp = 0

            stubs["idaapi"].treeloc_t = FakeTreeloc

            class FakeCfunc:
                def __init__(self, entry_ea: int, fail_refresh: bool):
                    self.entry_ea = entry_ea
                    self._fail_refresh = fail_refresh

                def get_eamap(self):
                    nonlocal eamap_calls
                    eamap_calls += 1
                    return {
                        self.entry_ea + 4: [types.SimpleNamespace(ea=self.entry_ea + 4)]
                    }

                def has_orphan_cmts(self):
                    return False

                def del_orphan_cmts(self):
                    pass

                def set_user_cmt(self, tl, cmt):
                    saved_cmts[tl.ea] = cmt

                def save_user_cmts(self):
                    pass

                def refresh_func_ctext(self):
                    refresh_calls.append(self.entry_ea)
                    if self._fail_refresh:
                        raise RuntimeError("refresh exploded")

            cfuncs = {
                0x1000: FakeCfunc(0x1000, fail_refresh=False),
                0x2000: FakeCfunc(0x2000, fail_refresh=True),
            }

            api_modify = importlib.import_module("ida_pro_mcp.ida_mcp.api_modify")
            api_modify.parse_address = lambda s: int(s, 0)

            def fake_decompile_checked(ea: int):
                nonlocal decompile_calls
                decompile_calls += 1
                return cfuncs[0x1000 if ea < 0x2000 else 0x2000]

            api_modify.decompile_checked = fake_decompile_checked

            # Batch of 3 comments: two on 0x1000 (entry + body), one on 0x2000 (refresh throws)
            res = api_modify.set_comments.__wrapped__(
                [
                    {"addr": "0x1000", "comment": "func1 cmt"},
                    {"addr": "0x1004", "comment": "body1 cmt"},
                    {"addr": "0x2000", "comment": "func2 cmt"},
                ]
            )
            self.assertEqual(len(res), 3)
            # Both 0x1000 and 0x2000 comments were persisted; 0x1000 has no error,
            # while 0x2000 reports isolated refresh_error without dropping batch results.
            self.assertEqual(saved_cmts[0x1000], "func1 cmt")
            self.assertEqual(saved_cmts[0x1004], "body1 cmt")
            self.assertEqual(saved_cmts[0x2000], "func2 cmt")
            self.assertEqual(res[0], {"addr": "0x1000"})
            self.assertEqual(res[1], {"addr": "0x1004"})
            self.assertNotIn("error", res[2])
            self.assertIn("refresh exploded", res[2]["refresh_error"])
            # init_hexrays cached once, decompile cached once per function, eamap once.
            self.assertEqual(init_calls, 1)
            self.assertEqual(decompile_calls, 2)
            self.assertEqual(eamap_calls, 1)
            # 0x1000 refreshed once (during 0x1004, clearing duplicate pending refresh)
            self.assertEqual(refresh_calls.count(0x1000), 1)
            self.assertEqual(refresh_calls.count(0x2000), 1)

            # Body comment refresh failure must report placement error (cannot verify orphan).
            res_body_fail = api_modify.set_comments.__wrapped__(
                [{"addr": "0x2004", "comment": "body2 cmt"}]
            )
            self.assertIn("error", res_body_fail[0])

            # Commenting across > _COMMENT_CFUNC_CACHE_MAX distinct functions flushes evicted refreshes.
            seen_distinct_refresh: list[int] = []
            distinct_eas = [0x10000 + i * 0x10 for i in range(10)]
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea)

            class SmallCfunc:
                def __init__(self, entry_ea: int):
                    self.entry_ea = entry_ea

                def refresh_func_ctext(self):
                    seen_distinct_refresh.append(self.entry_ea)

            api_modify.decompile_checked = lambda ea: SmallCfunc(ea)
            many_res = api_modify.set_comments.__wrapped__(
                [{"addr": hex(ea), "comment": f"c_{i}"} for i, ea in enumerate(distinct_eas)]
            )
            self.assertEqual(len(many_res), 10)
            self.assertEqual(seen_distinct_refresh, distinct_eas)

    def test_rename_batches_dirtree_and_dedupes_refresh(self):
        with _mocked_ida_env() as stubs:
            dirtree_stats = {"load": 0, "save": 0, "linked": []}

            class FakeDirtree:
                def __init__(self):
                    self.cwd = "/"

                def load(self):
                    dirtree_stats["load"] += 1
                    return True

                def isdir(self, _p):
                    return True

                def mkdir(self, _p):
                    return 0

                def getcwd(self):
                    return self.cwd

                def chdir(self, path):
                    self.cwd = path
                    return 0

                def link(self, ea):
                    dirtree_stats["linked"].append(ea)
                    return 0

                def save(self):
                    dirtree_stats["save"] += 1
                    return True

            fake_tree = FakeDirtree()
            stubs["ida_dirtree"].get_std_dirtree = lambda _kind: fake_tree
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea & ~0xF)
            stubs["idaapi"].get_name = lambda ea: f"sub_{ea:x}"
            stubs["idaapi"].get_flags = lambda _ea: 0
            stubs["idaapi"].is_loaded = lambda _ea: True
            stubs["ida_bytes"].get_full_flags = lambda _ea: 0
            stubs["ida_name"].is_uname = lambda _name: False
            stubs["idaapi"].get_name_ea = lambda _bad, _n: stubs["idaapi"].BADADDR
            stubs["idaapi"].set_name = lambda _ea, _name, _flags=0: True
            stubs["idaapi"].SN_CHECK = 0
            stubs["ida_hexrays"].init_hexrays_plugin = lambda: True
            stubs["ida_hexrays"].rename_lvar = lambda _ea, _old, _new: True

            refresh_eas: list[int] = []

            api_modify = importlib.import_module("ida_pro_mcp.ida_mcp.api_modify")
            api_modify.parse_address = lambda s: int(s, 0)

            def fake_refresh(ea: int):
                refresh_eas.append(ea)
                if ea == 0x2000:
                    raise RuntimeError("ctext error")

            api_modify.refresh_decompiler_ctext = fake_refresh

            out = api_modify.rename.__wrapped__(
                {
                    "func": [
                        {"addr": "0x1000", "name": "fn_a"},
                        {"addr": "0x2000", "name": "fn_b"},
                    ],
                    "local": [
                        {"func_addr": "0x1000", "old": "v1", "new": "x1"},
                        {"func_addr": "0x1000", "old": "v2", "new": "x2"},
                    ],
                }
            )
            self.assertEqual(dirtree_stats["load"], 1)
            self.assertEqual(dirtree_stats["save"], 1)
            self.assertEqual(dirtree_stats["linked"], [0x1000, 0x2000])
            # 0x1000 renamed function + 2 locals -> refreshed ONCE!
            self.assertEqual(refresh_eas, [0x1000, 0x2000])
            self.assertEqual(out["func"][0]["dir"], "vibe")
            self.assertNotIn("error", out["func"][1])
            self.assertIn("ctext error", out["func"][1]["refresh_error"])
            self.assertEqual(out["summary"]["ok"], 4)
            self.assertEqual(out["summary"]["failed"], 0)

            # Dry-run previews planned /vibe/ placement without loading dirtree.
            dirtree_stats["load"] = 0
            out_dry = api_modify.rename.__wrapped__(
                {"func": [{"addr": "0x1000", "name": "fn_dry"}], "dry_run": True}
            )
            self.assertEqual(out_dry["func"][0]["dir"], "vibe")
            self.assertEqual(dirtree_stats["load"], 0)

            # Dirtree exception preserves applied rename results and sets dir_error.
            fake_tree.load = lambda: (_ for _ in ()).throw(RuntimeError("dirtree crashed"))
            out_err = api_modify.rename.__wrapped__(
                {"func": [{"addr": "0x1000", "name": "fn_a2"}]}
            )
            self.assertEqual(out_err["func"][0]["name"], "fn_a2")
            self.assertIn("dirtree crashed", out_err["func"][0]["dir_error"])
            self.assertNotIn("error", out_err["func"][0])


class QueryAnalysisAndCompositeTests(unittest.TestCase):
    def test_lazy_core_queries_and_find_regex_error(self):
        with _mocked_ida_env() as stubs:
            fn_lookup_calls = 0
            tinfo_calls = 0
            seg_calls = 0

            func_addrs = [0x1000, 0x1100, 0x1200, 0x1300]
            stubs["idautils"].Functions = lambda: list(func_addrs)
            stubs["idautils"].Names = lambda: [(0x3000, "g_a"), (0x3010, "g_b"), (0x3020, "g_c")]
            stubs["idaapi"].get_func = lambda ea: (
                types.SimpleNamespace(start_ea=ea, end_ea=ea + (ea - 0x0FF0))
                if ea in func_addrs
                else None
            )

            def fake_get_func_name(ea):
                nonlocal fn_lookup_calls
                fn_lookup_calls += 1
                return f"fn_{ea:x}"

            def fake_get_tinfo(_tif, _ea):
                nonlocal tinfo_calls
                tinfo_calls += 1
                return False

            def fake_getseg(_ea):
                nonlocal seg_calls
                seg_calls += 1

            stubs["ida_funcs"].get_func_name = fake_get_func_name
            stubs["ida_nalt"].get_tinfo = fake_get_tinfo
            stubs["idaapi"].getseg = fake_getseg
            stubs["ida_segment"].get_segm_name = lambda _s: ".text"

            api_core = importlib.import_module("ida_pro_mcp.ida_mcp.api_core")
            api_core.get_function = lambda ea, raise_error=True: (
                fn_lookup_calls.__class__  # noop
                and {
                    "addr": hex(ea),
                    "name": fake_get_func_name(ea),
                    "size": hex(ea - 0x0FF0),
                }
            )

            # list_funcs unfiltered page of 1 -> only 1 get_function call instead of 4
            fn_lookup_calls = 0
            lf = api_core.list_funcs.__wrapped__({"offset": 1, "count": 1})
            self.assertEqual(len(lf[0]["data"]), 1)
            self.assertEqual(lf[0]["data"][0]["addr"], "0x1100")
            self.assertEqual(lf[0]["next_offset"], 2)
            self.assertEqual(fn_lookup_calls, 1)

            # count=0 still returns all, and multiple queries in one batch reuse func_cache.
            fn_lookup_calls = 0
            lf_all = api_core.list_funcs.__wrapped__(
                [{"offset": 0, "count": 0}, {"offset": 0, "count": 2}]
            )
            self.assertEqual(len(lf_all[0]["data"]), 4)
            self.assertEqual(len(lf_all[1]["data"]), 2)
            self.assertIsNone(lf_all[0]["next_offset"])
            self.assertEqual(fn_lookup_calls, 4)

            # func_query without has_type calls get_tinfo ONLY on returned slice (1 instead of 4)
            tinfo_calls = 0
            fn_lookup_calls = 0
            fq = api_core.func_query.__wrapped__({"offset": 1, "count": 1, "sort_by": "addr"})
            self.assertEqual(len(fq[0]["data"]), 1)
            self.assertEqual(tinfo_calls, 1)
            self.assertEqual(fn_lookup_calls, 1)

            # entity_query respects count=0 and skips get_tinfo/segm when fields=["addr", "name"]
            tinfo_calls = 0
            seg_calls = 0
            eq = api_core.entity_query.__wrapped__(
                {"kind": "functions", "offset": 1, "count": 1, "fields": ["addr", "name"]}
            )
            self.assertEqual(eq[0]["total"], 4)
            self.assertEqual(eq[0]["data"], [{"kind": "function", "addr": "0x1100", "name": "fn_1100"}])
            self.assertEqual(tinfo_calls, 0)
            self.assertEqual(seg_calls, 0)

            eq_all = api_core.entity_query.__wrapped__({"kind": "functions", "offset": 0, "count": 0})
            self.assertEqual(len(eq_all[0]["data"]), 4)
            self.assertIsNone(eq_all[0]["next_offset"])

            # Empty / whitespace-only projection preserves full function fields (matches _apply_projection).
            eq_empty_proj = api_core.entity_query.__wrapped__(
                {"kind": "functions", "offset": 0, "count": 1, "fields": []}
            )
            self.assertIn("segment", eq_empty_proj[0]["data"][0])
            self.assertIn("has_type", eq_empty_proj[0]["data"][0])
            eq_ws_proj = api_core.entity_query.__wrapped__(
                {"kind": "functions", "offset": 0, "count": 1, "fields": ["   "]}
            )
            self.assertIn("segment", eq_ws_proj[0]["data"][0])
            self.assertIn("has_type", eq_ws_proj[0]["data"][0])

            # list_globals count=1 offset=1
            lg = api_core.list_globals.__wrapped__({"offset": 1, "count": 1})
            self.assertEqual(lg[0]["data"], [{"addr": "0x3010", "name": "g_b"}])

            # find_regex handles invalid pattern gracefully
            stubs["ida_pro"].get_inf_version = lambda: "9.0"
            bad_rx = api_core.find_regex.__wrapped__("[unclosed")
            self.assertEqual(bad_rx["n"], 0)
            self.assertEqual(bad_rx["matches"], [])
            self.assertIn("Invalid regex", bad_rx["error"])

    def test_analysis_and_composite_optimizations(self):
        with _mocked_ida_env() as stubs:
            stubs["ida_bytes"].is_mapped = lambda _ea: True
            stubs["idaapi"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 0x10)
            stubs["idaapi"].get_func_name = lambda ea: f"fn_{ea:x}"
            stubs["ida_funcs"].get_func_name = lambda ea: f"fn_{ea:x}"
            stubs["idautils"].XrefsTo = lambda _ea, _f=0: [
                types.SimpleNamespace(frm=0x1000, iscode=True),
                types.SimpleNamespace(frm=0x1000, iscode=True),  # duplicate
                types.SimpleNamespace(frm=0x1010, iscode=True),
                types.SimpleNamespace(frm=0x1020, iscode=True),
            ]
            stubs["idautils"].XrefsFrom = lambda _ea, _f=0: []

            succ_calls = 0

            class FakeBlock:
                def __init__(self, start_ea):
                    self.start_ea = start_ea
                    self.end_ea = start_ea + 4
                    self.type = 0

                def succs(self):
                    nonlocal succ_calls
                    succ_calls += 1
                    return []

                def preds(self):
                    return []

            stubs["idaapi"].FlowChart = lambda _func: [
                FakeBlock(0x1000),
                FakeBlock(0x1004),
                FakeBlock(0x1008),
                FakeBlock(0x100C),
            ]

            api_analysis = importlib.import_module("ida_pro_mcp.ida_mcp.api_analysis")
            api_analysis.parse_address = lambda s: int(s, 0)

            get_fn_calls = 0

            def counting_get_fn(ea, raise_error=True):
                nonlocal get_fn_calls
                get_fn_calls += 1
                return {"addr": hex(ea), "name": f"fn_{ea:x}", "size": "0x10"}

            api_analysis.get_function = counting_get_fn
            xq = api_analysis.xref_query.__wrapped__(
                {"addr": "0x5000", "direction": "to", "count": 1, "offset": 1}
            )
            self.assertEqual(xq[0]["total"], 3)
            self.assertEqual(len(xq[0]["data"]), 1)
            self.assertEqual(get_fn_calls, 1)

            bb = api_analysis.basic_blocks.__wrapped__("0x1000", max_blocks=1, offset=2)
            self.assertEqual(bb[0]["total_blocks"], 4)
            self.assertEqual(bb[0]["data"] if "data" in bb[0] else bb[0]["blocks"], [{"start": "0x1008", "end": "0x100c", "size": 4, "type": 0, "successors": [], "predecessors": []}])
            self.assertEqual(succ_calls, 1)

            # export_funcs skips get_all_comments in c_header and prototypes modes
            cmt_calls = 0
            api_analysis.get_prototype = lambda _fn: "void foo(void)"

            def fail_if_called(_ea):
                nonlocal cmt_calls
                cmt_calls += 1
                return {}

            api_analysis.get_all_comments = fail_if_called
            hdr = api_analysis.export_funcs.__wrapped__("0x1000", format="c_header")
            self.assertIn("void foo(void);", hdr["content"])
            proto = api_analysis.export_funcs.__wrapped__("0x1000", format="prototypes")
            self.assertEqual(len(proto["functions"]), 1)
            self.assertEqual(cmt_calls, 0)

            # api_composite: _filter_constants + analyze_component single-pass caching
            stubs["idautils"].Heads = lambda _s, _e: []
            api_comp = importlib.import_module("ida_pro_mcp.ida_mcp.api_composite")
            filtered = api_comp._filter_constants(
                [
                    {"addr": "0x100", "value": "0x4", "decimal": 4},
                    {"addr": "0x104", "value": "0xdeadbeef", "decimal": 0xDEADBEEF},
                    {"addr": "0x108", "value": "0xffffffff", "decimal": 0xFFFFFFFF},
                ]
            )
            self.assertEqual([c["value"] for c in filtered], ["0xdeadbeef"])

            callee_calls = 0
            string_calls = 0
            api_comp._resolve_addr = lambda s: int(s, 0)
            api_comp.get_prototype = lambda _f: "void fn()"
            api_comp._basic_block_info = lambda _ea: {"count": 1, "cyclomatic_complexity": 1}
            api_comp.get_callers = lambda _s: []

            def count_callees(_s):
                nonlocal callee_calls
                callee_calls += 1
                return [{"addr": "0x1000", "name": "fn_1000", "type": "internal"}]

            def count_strings(_ea):
                nonlocal string_calls
                string_calls += 1
                return [{"addr": "0x5000", "length": 3, "string": "abc"}]

            api_comp.get_callees = count_callees
            api_comp.extract_function_strings = count_strings
            comp = api_comp.analyze_component.__wrapped__(["0x1000", "0x2000"])
            self.assertEqual(callee_calls, 2)
            self.assertEqual(string_calls, 2)
            self.assertEqual(comp["string_usage"], {"abc": ["fn_1000", "fn_2000"]})


if __name__ == "__main__":
    unittest.main()
