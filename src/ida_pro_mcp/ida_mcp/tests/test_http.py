"""Tests for tool registration (@unsafe, @ext) and extension gating.

Tests exercise the real MCP_UNSAFE set, MCP_EXTENSIONS dict, and
MCP_SERVER.tools.methods registry — all populated by actual decorator
execution at import time.  No mocks.

Unsafe *removal* tests (simulating idalib --unsafe gating) live in
test_server.py; tests here focus on the decorator sets, extension
visibility, and ORIGINAL_TOOLS snapshot.
"""

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE, MCP_EXTENSIONS
from .. import http as http_mod


# ---------------------------------------------------------------------------
# @unsafe decorator: MCP_UNSAFE set populated by real decorators
# ---------------------------------------------------------------------------


@test()
def test_unsafe_set_includes_all_expected_categories():
    """MCP_UNSAFE should contain python-exec, composite, and debugger tools."""
    assert "py_eval" in MCP_UNSAFE
    assert "py_exec_file" in MCP_UNSAFE
    assert "diff_before_after" in MCP_UNSAFE
    dbg_tools = {n for n in MCP_UNSAFE if n.startswith("dbg_")}
    assert len(dbg_tools) >= 15, f"Expected ≥15 dbg_ unsafe tools, got {len(dbg_tools)}"


@test()
def test_unsafe_tools_are_disjoint_from_safe_core():
    """Core analysis tools must never be marked @unsafe."""
    safe_core = {"decompile", "disasm", "list_funcs", "rename", "imports"}
    overlap = MCP_UNSAFE & safe_core
    assert not overlap, f"Core tools incorrectly marked unsafe: {overlap}"


# ---------------------------------------------------------------------------
# @ext decorator: MCP_EXTENSIONS populated by real decorators
# ---------------------------------------------------------------------------


@test()
def test_dbg_extension_group_exists_and_populated():
    """@ext('dbg') decorators should create a 'dbg' group with ≥15 tools."""
    assert "dbg" in MCP_EXTENSIONS, "No 'dbg' extension group registered"
    assert len(MCP_EXTENSIONS["dbg"]) >= 15


@test()
def test_dbg_extension_tools_are_all_unsafe():
    """Every tool in the 'dbg' extension must also be @unsafe."""
    dbg_tools = MCP_EXTENSIONS.get("dbg", set())
    not_unsafe = dbg_tools - MCP_UNSAFE
    assert not not_unsafe, f"dbg tools missing @unsafe: {not_unsafe}"


@test()
def test_no_extension_tool_in_default_listing():
    """Extension tools should be hidden from tools/list when no ext is enabled."""
    old_exts = getattr(MCP_SERVER._enabled_extensions, "data", set())
    MCP_SERVER._enabled_extensions.data = set()
    try:
        listed = {t["name"] for t in MCP_SERVER._mcp_tools_list()["tools"]}
        for group, tools in MCP_EXTENSIONS.items():
            leaked = tools & listed
            assert not leaked, f"'{group}' tools visible without ?ext: {leaked}"
    finally:
        MCP_SERVER._enabled_extensions.data = old_exts


@test()
def test_extension_tools_appear_when_enabled():
    """Extension tools should appear in tools/list when their group is enabled."""
    old_exts = getattr(MCP_SERVER._enabled_extensions, "data", set())
    MCP_SERVER._enabled_extensions.data = {"dbg"}
    try:
        listed = {t["name"] for t in MCP_SERVER._mcp_tools_list()["tools"]}
        in_registry = MCP_EXTENSIONS["dbg"] & set(MCP_SERVER.tools.methods)
        missing = in_registry - listed
        assert not missing, f"dbg tools in registry but hidden: {missing}"
    finally:
        MCP_SERVER._enabled_extensions.data = old_exts


# ---------------------------------------------------------------------------
# ORIGINAL_TOOLS snapshot (populated at import from real registry)
# ---------------------------------------------------------------------------


@test()
def test_original_tools_contains_discovery_tools():
    """ORIGINAL_TOOLS snapshot must include discovery tools for config rendering."""
    for name in ("list_instances", "select_instance", "open_file"):
        assert name in http_mod.ORIGINAL_TOOLS, f"{name} missing from ORIGINAL_TOOLS"


@test()
def test_original_tools_covers_plugin_side_tools():
    """ORIGINAL_TOOLS should contain every plugin-registered tool.

    idalib-specific tools (idalib_*) are added dynamically by idalib_server
    and won't be in the snapshot — that's expected.
    """
    idalib_tools = {n for n in MCP_SERVER.tools.methods if n.startswith("idalib_")}
    plugin_tools = set(MCP_SERVER.tools.methods) - idalib_tools
    missing = plugin_tools - set(http_mod.ORIGINAL_TOOLS)
    assert not missing, f"Plugin tools missing from ORIGINAL_TOOLS: {missing}"
