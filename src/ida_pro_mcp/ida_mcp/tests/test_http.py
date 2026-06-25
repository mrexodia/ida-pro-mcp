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
    # Only the state-mutating dbg_ tools (EXECUTE tier: start/exit/continue/run/
    # step/add-delete-toggle bp/set-bp-condition/write) are unsafe; the READ-only
    # dbg_ tools (status/regs/bps/stacktrace/read/gpregs) are correctly safe.
    dbg_tools = {n for n in MCP_UNSAFE if n.startswith("dbg_")}
    assert len(dbg_tools) >= 10, f"Expected >=10 mutating dbg_ unsafe tools, got {len(dbg_tools)}"


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
    """Every STATE-MUTATING dbg-ext tool must be @unsafe.

    READ-only dbg/probe tools (dbg_status, dbg_read, probe_list, ...) are
    correctly @safety("READ") and intentionally NOT unsafe — listing or reading
    debugger state mutates nothing. Only the mutating tiers (EXECUTE /
    DESTRUCTIVE / PATCH, which set destructiveHint or openWorldHint) must be
    fenced behind @unsafe. So we assert exactly that: every mutating dbg tool is
    unsafe, and read-only dbg tools are allowed to be safe.
    """
    dbg_tools = MCP_EXTENSIONS.get("dbg", set())
    methods = MCP_SERVER.tools.methods

    mutating = set()
    read_only = set()
    for name in dbg_tools:
        func = methods.get(name)
        ann = getattr(func, "__mcp_annotations__", None) if func else None
        if ann and (ann.get("destructiveHint") or ann.get("openWorldHint")):
            mutating.add(name)
        else:
            read_only.add(name)

    # The mutating debugger surface (run/step/continue/bp-set/write/appcall/...)
    # is substantial; guard against the classifier silently collapsing.
    assert len(mutating) >= 10, (
        f"Expected >=10 mutating dbg tools, got {len(mutating)}: {sorted(mutating)}"
    )

    not_unsafe = mutating - MCP_UNSAFE
    assert not not_unsafe, f"mutating dbg tools missing @unsafe: {sorted(not_unsafe)}"

    # Sanity: read-only ext tools are explicitly permitted to be safe — at least
    # the known read tools must classify as read-only here.
    expected_read = {
        "dbg_status", "dbg_read", "dbg_bps", "dbg_stacktrace",
        "probe_list", "probe_drain", "probe_stats", "trace_summary",
        "diff_buffers", "snapshot_list", "read_struct_live",
        "appcall_inspect", "memory_scan",
    }
    present_read = expected_read & dbg_tools
    misclassified = present_read - read_only
    assert not misclassified, (
        f"known read-only dbg tools classified as mutating: {sorted(misclassified)}"
    )


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
def test_original_tools_covers_plugin_side_tools():
    """ORIGINAL_TOOLS should contain every plugin-registered tool.

    Supervisor-only management tools (idb_open, idb_list) are
    registered by idalib_supervisor and won't appear in the GUI plugin's
    snapshot — that's expected.
    """
    supervisor_only = {"idb_open", "idb_list"}
    plugin_tools = set(MCP_SERVER.tools.methods) - supervisor_only
    missing = plugin_tools - set(http_mod.ORIGINAL_TOOLS)
    assert not missing, f"Plugin tools missing from ORIGINAL_TOOLS: {missing}"
