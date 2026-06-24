"""Headless pytest support for the pure-logic ida_pro_mcp tests.

The ``ida_pro_mcp.ida_mcp`` package imports IDA's native modules (``idaapi``,
``idc``, ``ida_kernwin`` ...) at import time via ``sync.py`` and the ``api_*``
modules. Those modules only exist inside IDA Pro, so a plain ``pytest`` run that
imports the package fails with ``ModuleNotFoundError: No module named 'idaapi'``.

This conftest installs lightweight ``MagicMock``-backed fake modules into
``sys.modules`` BEFORE the package is imported, so the pure-logic units
(``trace.ProbeRing``, ``api_probes.parse_capture_spec`` / ``build_probe_record``,
``rpc.safety`` / ``rpc.title``, ``api_docs.search_docs`` ...) import and run
without a live IDA process. A conftest at this directory level is imported by
pytest before it collects the sibling test modules, so the stubs are in place
first.

The stubs are deliberately minimal. A couple of attributes that the package
reads at *import time* (notably ``idaapi.get_kernel_version()``) must return
real values rather than a ``MagicMock``, so they are pinned below.
"""

import importlib.abc
import importlib.machinery
import sys
import types
from unittest.mock import MagicMock


class _FakeIdaModule(types.ModuleType):
    """A module whose every attribute is a fresh MagicMock.

    Backs the import-time stubs. ``from fake import anything`` succeeds because
    ``__getattr__`` fabricates a MagicMock for any unknown name. Pinned concrete
    attributes (set with ``setattr``) take precedence over the fabricator.
    """

    def __getattr__(self, name: str):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        value = MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, value)
        return value


# Modules the package touches (the names that must always be backed by the stub,
# even before anything imports them). Anything else matching the IDA naming
# convention is fabricated on demand by the finder below.
_IDA_MODULES = [
    "idaapi", "ida_dbg", "idc", "ida_bytes", "ida_typeinf", "idautils",
    "ida_kernwin", "ida_netnode", "ida_idd", "ida_idp", "ida_ida",
]

# Real pip packages that LOOK like IDA names but must NOT be intercepted
# (ida-domain / idapro are genuine installed dependencies).
_REAL_PACKAGES = {"ida_domain", "idapro", "idadex", "ida_pro_mcp"}


def _is_ida_name(name: str) -> bool:
    head = name.split(".", 1)[0]
    if head in _REAL_PACKAGES:
        return False
    return head.startswith("ida_") or head in {"idc", "idautils", "idaapi"}


class _IdaStubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Meta-path finder that fabricates any IDA module as a _FakeIdaModule."""

    def find_spec(self, fullname, path=None, target=None):
        if not _is_ida_name(fullname):
            return None
        if fullname in sys.modules and not isinstance(sys.modules[fullname], _FakeIdaModule):
            return None
        return importlib.machinery.ModuleSpec(fullname, self)

    def create_module(self, spec):
        return _FakeIdaModule(spec.name)

    def exec_module(self, module):
        return None


def _install_ida_stubs() -> None:
    if not any(isinstance(f, _IdaStubFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _IdaStubFinder())

    for name in _IDA_MODULES:
        if name in sys.modules and not isinstance(sys.modules[name], _FakeIdaModule):
            # A real IDA is present (running under IDA): leave it alone.
            continue
        sys.modules.setdefault(name, _FakeIdaModule(name))

    # --- import-time values that must be concrete, not MagicMock ------------
    def _stub(name: str) -> _FakeIdaModule:
        mod = sys.modules.get(name)
        if not isinstance(mod, _FakeIdaModule):
            mod = _FakeIdaModule(name)
            sys.modules[name] = mod
        return mod

    idaapi = _stub("idaapi")
    # Sentinel marking this idaapi as the headless stub (NOT a real IDA runtime).
    # `pytest_collection_modifyitems` reads it to decide whether to skip the
    # IDA-runtime-only suite. When running inside real IDA the module is the
    # genuine one and this attribute is absent.
    idaapi._mh_headless_stub = True
    # sync.py: `ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))`
    idaapi.get_kernel_version = MagicMock(return_value="9.3")
    # sync._sync_wrapper does `idaapi.execute_sync(runned, MFF_WRITE)` then BLOCKS
    # on a queue waiting for `runned()` to run on the IDA main thread. Headless
    # there is no main loop, so run the callback inline (some api modules invoke
    # @idasync tools at import time, e.g. http.py).
    idaapi.execute_sync = lambda fn, flags=0: (fn(), 0)[1]
    idaapi.MFF_WRITE = 0x2
    idaapi.MFF_READ = 0x1
    idaapi.MFF_FAST = 0x0

    idc = _stub("idc")
    # _sync_wrapper toggles batch mode around the call; return a prior value.
    idc.batch = MagicMock(return_value=0)

    # IDB_Hooks must be subclassable AND expose hook()/unhook() (trace._install_idb_hook
    # does `class _TraceFlushHook(ida_idp.IDB_Hooks): ...` then `hook.hook()`).
    class _IDBHooks:
        def __init__(self, *a, **k):
            pass

        def hook(self):
            return False  # report "not hooked" so trace stays inert headless

        def unhook(self):
            return False

    _stub("ida_idp").IDB_Hooks = _IDBHooks

    ida_netnode = _stub("ida_netnode")
    ida_netnode.BADNODE = 0xFFFFFFFFFFFFFFFF

    # http.py reads the 'enabled_tools' netnode at import; a MagicMock blob makes
    # it print an "Invalid JSON" warning. Give it an empty netnode whose reads
    # return falsy values so that path stays quiet and inert.
    class _Netnode:
        def __init__(self, *a, **k):
            pass

        def __eq__(self, other):
            return False  # never equals BADNODE

        def __hash__(self):
            return id(self)

        def getblob(self, *a, **k):
            return None

        def altval(self, *a, **k):
            return 0

        def altset(self, *a, **k):
            return True

        def altfirst(self, *a, **k):
            return ida_netnode.BADNODE

        def altnext(self, *a, **k):
            return ida_netnode.BADNODE

        def setblob(self, *a, **k):
            return True

    ida_netnode.netnode = _Netnode

    ida_dbg = _stub("ida_dbg")
    # Default: no live debugger. Pure-logic tests never need a live session.
    ida_dbg.is_debugger_on = MagicMock(return_value=False)
    ida_dbg.DSTATE_SUSP = 1


_install_ida_stubs()


# ---------------------------------------------------------------------------
# requires_ida marker + headless auto-skip of the IDA-runtime-only suite.
#
# A large suite (everything under ``src/ida_pro_mcp/ida_mcp/tests/`` that drives
# the ``@test(binary=...)`` fixture, plus the supervisor import-isolation test)
# only behaves correctly against a real IDA / idalib runtime. Headless, the
# stub above returns ``MagicMock`` objects that don't behave like IDA, so those
# tests fail spuriously. When the stub is active (no real IDA present) we mark
# that suite ``requires_ida`` and skip it, while leaving the genuinely-headless
# pure-logic tests running.
# ---------------------------------------------------------------------------

import pytest  # noqa: E402  (after the stub install above, by design)


def _real_ida_present() -> bool:
    """True when running against a genuine IDA runtime (stub NOT in effect)."""
    idaapi_mod = sys.modules.get("idaapi")
    if idaapi_mod is None:
        return False
    if isinstance(idaapi_mod, _FakeIdaModule):
        return False
    if getattr(idaapi_mod, "_mh_headless_stub", False):
        return False
    return True


# nodeid substrings whose tests need a real IDA/idalib runtime. nodeids use
# forward slashes on every platform, so these match regardless of OS.
_REQUIRES_IDA_PATH_PREFIX = "src/ida_pro_mcp/ida_mcp/tests/"
_REQUIRES_IDA_NODEIDS = {
    "tests/test_idalib_supervisor.py::test_supervisor_import_does_not_import_ida_modules",
}


def _requires_ida_runtime(item) -> bool:
    nodeid = item.nodeid.replace("\\", "/")
    if _REQUIRES_IDA_PATH_PREFIX in nodeid:
        return True
    if nodeid in _REQUIRES_IDA_NODEIDS:
        return True
    return False


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_ida: test only runs against a real IDA/idalib runtime; "
        "auto-skipped headless (stub idaapi active).",
    )


def pytest_collection_modifyitems(config, items):
    if _real_ida_present():
        return
    skip_marker = pytest.mark.skip(reason="requires a real IDA/idalib runtime")
    for item in items:
        if _requires_ida_runtime(item):
            item.add_marker(pytest.mark.requires_ida)
            item.add_marker(skip_marker)
