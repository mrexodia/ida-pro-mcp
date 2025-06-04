import importlib.util
from pathlib import Path
from unittest import mock
import types
import sys
import os
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT))

for name in [
    "ida_hexrays",
    "ida_kernwin",
    "ida_funcs",
    "ida_gdl",
    "ida_lines",
    "ida_idaapi",
    "idc",
    "idaapi",
    "idautils",
    "ida_nalt",
    "ida_bytes",
    "ida_typeinf",
    "ida_xref",
    "ida_entry",
    "ida_idd",
    "ida_dbg",
    "ida_name",
    "ida_ida",
]:
    sys.modules.setdefault(name, types.ModuleType(name))

ida_kernwin = sys.modules["ida_kernwin"]
ida_kernwin.MFF_READ = 0
ida_kernwin.MFF_WRITE = 1
ida_kernwin.MFF_FAST = 2
ida_kernwin.add_dock_widget = lambda *a, **k: None
ida_kernwin.create_dockable_window = lambda *a, **k: None

ida_funcs = sys.modules["ida_funcs"]
class func_t: ...
ida_funcs.func_t = func_t

ida_hexrays = sys.modules["ida_hexrays"]
class cfunc_t: ...
ida_hexrays.cfunc_t = cfunc_t
ida_hexrays.hexrays_failure_t = type("hexrays_failure_t", (), {})
ida_hexrays.DECOMP_WARNINGS = 0
ida_hexrays.OPF_REUSE = 0
ida_hexrays.ctree_item_t = type("ctree_item_t", (), {})
ida_hexrays.user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
ida_hexrays.lvar_saved_info_t = type("lvar_saved_info_t", (), {})
ida_hexrays.init_hexrays_plugin = lambda: True
ida_hexrays.decompile_func = lambda *a, **k: cfunc_t()
ida_hexrays.get_widget_vdui = lambda w: None
ida_hexrays.rename_lvar = lambda *a, **k: True
ida_hexrays.modify_user_lvars = lambda *a, **k: True
ida_hexrays.open_pseudocode = lambda *a, **k: None

ida_typeinf = sys.modules["ida_typeinf"]
ida_typeinf.tinfo_t = type("tinfo_t", (), {})

idaapi = sys.modules["idaapi"]
idaapi.plugin_t = type("plugin_t", (), {})
idaapi.PLUGIN_KEEP = 0
idaapi.enable_bpt = lambda *a, **k: True

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "plugin/__init__.py"

spec = importlib.util.spec_from_file_location("mcp_plugin", PLUGIN_PATH)
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def test_get_metadata():
    with mock.patch.object(plugin, "get_image_size", return_value=0x2000), \
         mock.patch.object(plugin, "idaapi") as idaapi, \
         mock.patch.object(plugin, "ida_nalt") as ida_nalt:
        idaapi.get_input_file_path.return_value = "/tmp/a.exe"
        idaapi.get_root_filename.return_value = "a.exe"
        idaapi.get_imagebase.return_value = 0x401000
        ida_nalt.retrieve_input_file_md5.return_value = b"\x00" * 16
        ida_nalt.retrieve_input_file_sha256.return_value = b"\x00" * 32
        ida_nalt.retrieve_input_file_crc32.return_value = 0x1234
        ida_nalt.retrieve_input_file_size.return_value = 1024

        result = plugin.get_metadata.__wrapped__()

    assert result["module"] == "a.exe"
    assert result["size"] == hex(0x2000)


def test_plugin_run_spawns_core():
    with mock.patch.object(plugin, "Server") as Server, \
         mock.patch.object(plugin.subprocess, "Popen") as Popen:
        Popen.return_value.poll.return_value = None
        instance = Server.return_value
        p = plugin.MCP()
        p.init()
        p.run(None)
        instance.start.assert_called_once()
        Popen.assert_called_once()
        args = Popen.call_args[0][0]
        assert args[1:4] == ["-m", "ida_pro_mcp.server.core", "--socket-fd"]


def reset_core_state():
    plugin._core_proc = None
    plugin._core_socket = None


class StubLLM:
    def __init__(self, *a, **k):
        pass

    def chat(self, messages, stream=False):
        if stream:
            def gen():
                yield "pong"
            return gen()
        return "pong"


class StubPrompt:
    def __init__(self):
        self._text = ""

    def text(self):
        return self._text

    def clear(self):
        self._text = ""


class StubDock:
    def __init__(self, plugin):
        self.plugin = plugin
        self.history = []
        self.prompt = StubPrompt()

    def winId(self):
        return 0

    def on_send(self):
        text = self.prompt.text().strip()
        if not text:
            return
        self.history.append(f"> {text}")
        self.prompt.clear()
        reply = self.plugin.send_prompt(text)
        if reply:
            self.history.append(reply)


class DummyPopen:
    def __init__(self, args, pass_fds=(), **kwargs):
        fd = int(args[args.index("--socket-fd") + 1])
        self.fd = os.dup(fd)
        self.thread = threading.Thread(target=self._run, args=(self.fd,), daemon=True)
        self.thread.start()

    def _run(self, fd):
        import ida_pro_mcp.server.core as core
        with mock.patch.object(core, "LocalLLM", StubLLM):
            core.main(["--socket-fd", str(fd)])
        print("core exited")

    def poll(self):
        return None if self.thread.is_alive() else 0


def test_prompt_through_dock():
    reset_core_state()
    with mock.patch.object(plugin, "Server"), \
         mock.patch.object(plugin.subprocess, "Popen", DummyPopen), \
         mock.patch.object(plugin.MCP, "_show_dock", lambda self: setattr(self, "dock", StubDock(self))):
        p = plugin.MCP()
        p.init()
        p.run(None)
        import time; time.sleep(0.05)
        p.dock.prompt._text = "ping"
        p.dock.on_send()
        assert p.dock.history[-1] == "pong"
