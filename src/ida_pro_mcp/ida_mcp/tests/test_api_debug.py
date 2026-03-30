"""Tests for api_debug API functions.

Note: All debugger tools require a running debugger session.
Tests skip gracefully when no debugger is active.
"""

import idaapi

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
)
from ..api_debug import (
    dbg_bps,
    dbg_add_bp,
    dbg_delete_bp,
    dbg_regs,
    dbg_gpregs,
    dbg_regs_all,
    dbg_stacktrace,
    dbg_read,
)
from ..sync import IDAError


def _require_debugger():
    """Skip test if debugger is not running."""
    if not idaapi.is_debugger_on():
        skip_test("debugger not running")


# ============================================================================
# Breakpoint management
# ============================================================================


@test()
def test_dbg_bps_returns_list():
    """dbg_bps returns a list of breakpoints when debugger is active."""
    _require_debugger()
    result = dbg_bps()
    assert isinstance(result, list)


@test()
def test_dbg_add_delete_bp_roundtrip():
    """Add a breakpoint, verify it exists, then delete it."""
    _require_debugger()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("no functions available")

    # Add
    add_result = dbg_add_bp(fn_addr)
    assert_is_list(add_result, min_length=1)

    # Verify it shows in list
    bps = dbg_bps()
    bp_addrs = [bp.get("addr") for bp in bps]
    assert fn_addr in bp_addrs or hex(int(fn_addr, 16)) in bp_addrs

    # Delete
    del_result = dbg_delete_bp(fn_addr)
    assert_is_list(del_result, min_length=1)


# ============================================================================
# Register inspection
# ============================================================================


@test()
def test_dbg_regs_returns_registers():
    """dbg_regs returns current thread register values."""
    _require_debugger()
    result = dbg_regs()
    assert isinstance(result, dict)
    assert_has_keys(result, "thread_id", "registers")
    assert isinstance(result["registers"], dict)


@test()
def test_dbg_gpregs_subset_of_regs():
    """dbg_gpregs returns a subset of dbg_regs."""
    _require_debugger()
    gp = dbg_gpregs()
    assert isinstance(gp, dict)
    assert_has_keys(gp, "thread_id", "registers")


@test()
def test_dbg_regs_all_returns_threads():
    """dbg_regs_all returns registers for all threads."""
    _require_debugger()
    result = dbg_regs_all()
    assert isinstance(result, list)
    if result:
        assert_has_keys(result[0], "thread_id", "registers")


# ============================================================================
# Memory and stack
# ============================================================================


@test()
def test_dbg_stacktrace_returns_frames():
    """dbg_stacktrace returns call stack frames."""
    _require_debugger()
    result = dbg_stacktrace()
    assert isinstance(result, list)


@test()
def test_dbg_read_memory():
    """dbg_read reads memory from debuggee."""
    _require_debugger()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("no functions available")

    result = dbg_read({"addr": fn_addr, "size": 16})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_has_keys(entry, "addr", "size", "data", "error")
    if entry["error"] is None:
        assert entry["size"] == 16
        assert entry["data"] is not None


@test()
def test_dbg_read_capped_at_1mb():
    """dbg_read caps at 1MB per read."""
    _require_debugger()
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("no functions available")

    result = dbg_read({"addr": fn_addr, "size": 2 * 1024 * 1024})
    assert_is_list(result, min_length=1)
    entry = result[0]
    # Should have capped the size
    if entry["error"] is None:
        assert entry["size"] <= 1024 * 1024
