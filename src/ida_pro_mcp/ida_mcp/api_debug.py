"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, conditions, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

import os
from typing import Annotated, NotRequired, TypedDict

import ida_dbg
import ida_entry
import ida_idaapi
import ida_idd
import ida_kernwin
import ida_name
import idaapi
import idc

from .rpc import tool, safety, ext, title
from .sync import idasync, keep_batch, get_pre_call_batch, IDAError
from .utils import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
    BreakpointConditionOp,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


class DebugControlResult(TypedDict, total=False):
    ip: str
    started: bool
    continued: bool
    running: bool
    suspended: bool
    exited: bool
    state: str
    error: str


class BreakpointResult(TypedDict, total=False):
    addr: str
    ok: bool
    condition: str | None
    language: str | None
    error: str


class ThreadRegistersResult(TypedDict, total=False):
    tid: int
    regs: ThreadRegisters | None
    error: str


class StackFrameInfo(TypedDict):
    addr: str
    module: str
    symbol: str


class DebugMemoryReadResult(TypedDict):
    addr: str | None
    size: int
    data: str | None
    error: NotRequired[str | None]


class DebugMemoryWriteResult(TypedDict, total=False):
    addr: str | None
    size: int
    ok: bool
    error: str | None


# ============================================================================
# Constants and Helper Functions
# ============================================================================

GENERAL_PURPOSE_REGISTERS = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}


def _get_process_state_name() -> str:
    if not ida_dbg.is_debugger_on():
        return "not_running"

    state = ida_dbg.get_process_state()
    if state == ida_dbg.DSTATE_SUSP:
        return "suspended"
    if state == ida_dbg.DSTATE_RUN:
        return "running"
    if state == ida_dbg.DSTATE_NOTASK:
        return "not_running"
    return f"unknown({state})"


def _get_debug_state_result() -> DebugControlResult:
    state = _get_process_state_name()
    result: DebugControlResult = {"state": state}
    if state == "running":
        result["running"] = True
    elif state == "suspended":
        result["suspended"] = True
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            result["ip"] = hex(ip)
    return result


def dbg_ensure_active() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg or not ida_dbg.is_debugger_on():
        raise IDAError(
            "Debugger not running. Stop and ask the user to start a debugger "
            "session (call dbg_start, or have them launch from IDA) before "
            "retrying. If dbg_start has already been attempted and failed, "
            "the user must first configure the debugger and target."
        )
    return dbg


def dbg_ensure_suspended() -> "ida_idd.debugger_t":
    dbg = dbg_ensure_active()
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise IDAError(
            "Debugger is running; wait until it suspends before inspecting state"
        )
    return dbg


def _get_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> ThreadRegisters:
    """Helper to get registers for a specific thread."""
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        rv: ida_idd.regval_t
        reg_info = dbg.regs(reg_index)

        try:
            reg_value = rv.pyval(reg_info.dtype)
        except ValueError:
            reg_value = ida_idaapi.BADADDR

        if isinstance(reg_value, int):
            reg_value = hex(reg_value)
        if isinstance(reg_value, bytes):
            reg_value = reg_value.hex(" ")
        else:
            reg_value = str(reg_value)
        regs.append(
            RegisterValue(
                name=reg_info.name,
                value=reg_value,
            )
        )
    return ThreadRegisters(
        thread_id=tid,
        registers=regs,
    )


def _get_registers_general_for_thread(
    dbg: "ida_idd.debugger_t", tid: int
) -> ThreadRegisters:
    """Helper to get general-purpose registers for a specific thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    general_registers = [
        reg
        for reg in all_registers["registers"]
        if reg["name"] in GENERAL_PURPOSE_REGISTERS
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=general_registers,
    )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
    """Helper to get specific registers for a given thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    specific_registers = [
        reg for reg in all_registers["registers"] if reg["name"] in register_names
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=specific_registers,
    )


def _normalize_breakpoint_language(language: object) -> str | None:
    if language is None:
        return None
    text = str(language).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered == "idc":
        return "IDC"
    if lowered == "python":
        return "Python"
    return text


def _get_breakpoint_language(bpt: ida_dbg.bpt_t) -> str | None:
    language = getattr(bpt, "elang", None)
    if language is None:
        return None
    text = str(language).strip()
    return text or None


def _set_breakpoint_language(bpt: ida_dbg.bpt_t, language: str) -> None:
    setter = getattr(bpt, "set_cnd_elang", None)
    if callable(setter):
        if not setter(language):
            raise IDAError(f"Failed to set breakpoint condition language to {language}")
        return
    try:
        setattr(bpt, "elang", language)
    except Exception as exc:
        raise IDAError(
            f"Failed to set breakpoint condition language to {language}"
        ) from exc


def list_breakpoints() -> list[Breakpoint]:
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
                    condition=str(bpt.condition) if bpt.condition else None,
                    language=_get_breakpoint_language(bpt),
                )
            )
    return breakpoints


# ============================================================================
# Debugger Control Operations
# ============================================================================


def _get_debug_start_result() -> DebugControlResult | None:
    if not ida_dbg.is_debugger_on():
        return None
    result = _get_debug_state_result()
    result["started"] = True
    return result


# Batch-mode lifecycle for dbg_start.
#
# start_process schedules work that runs on the IDA main thread *after* our
# execute_sync returns. That work can show modal dialogs (e.g. "matching
# executable names"), so we need batch mode to remain on across the
# execute_sync boundary, and we need to be sure to turn it back off once the
# debugger has actually come up (or failed to). _DbgStartBatchHook does both.
_DBG_START_BATCH_FALLBACK_MS = 30_000  # absolute ceiling on stuck-in-batch state
_DBG_START_WAIT_TIMEOUT_SEC = 10.0
_DBG_START_WAIT_POLL_MS = 100
_DBG_START_IP_GRACE_POLL_COUNT = 5


class _DbgStartBatchHook(ida_dbg.DBG_Hooks):
    """Restore batch mode as soon as the debugger has finished STARTUP.

    "Startup" ends at dbg_process_start / dbg_process_attach — by then any
    startup dialogs (e.g. "matching executable names") are done, but the
    user is still inside an active debug session and should see normal
    dialogs from here on. dbg_process_exit / dbg_process_detach also
    restore so we don't get stuck if the process dies before fully coming
    up.
    """

    def __init__(self, restore_batch: int):
        super().__init__()
        self._restore_batch = restore_batch
        self._done = False

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        self._restore()

    def dbg_process_detach(self, pid, tid, ea):
        self._restore()

    def fallback_restore(self):
        """Called by the safety timer if no debugger event ever arrives."""
        self._restore()

    def _restore(self):
        if self._done:
            return
        self._done = True
        try:
            self.unhook()
        except Exception:
            pass
        idc.batch(self._restore_batch)


_dbg_start_batch_hook: _DbgStartBatchHook | None = None

_CONTINUE_WAIT_POLL_MS = 100


def _continue_and_wait(timeout_ms: int, *, target_ea: int | None = None) -> dict:
    """Resume the debuggee and poll wait_for_next_event until it suspends again.

    Pumps wait_for_next_event in poll-sized slices until the process suspends,
    exits, or the timeout elapses. When target_ea is given, run_to that address;
    otherwise continue_process. Returns {status, stopped_ea, elapsed_ms} where
    status is one of "suspended", "exited", "timeout", "not_running", or
    "failed_to_resume".
    """
    import time as _time

    if not ida_dbg.is_debugger_on():
        return {"status": "not_running", "stopped_ea": None, "elapsed_ms": 0}

    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        return {"status": "not_running", "stopped_ea": None, "elapsed_ms": 0}

    started_at = _time.monotonic()

    if target_ea is not None:
        resumed = idaapi.run_to(target_ea)
    else:
        resumed = idaapi.continue_process()

    if not resumed:
        elapsed = round((_time.monotonic() - started_at) * 1000, 2)
        return {"status": "failed_to_resume", "stopped_ea": None, "elapsed_ms": elapsed}

    deadline = started_at + max(0, timeout_ms) / 1000.0
    while True:
        remaining_ms = (deadline - _time.monotonic()) * 1000.0
        if remaining_ms <= 0:
            break
        poll_ms = int(min(_CONTINUE_WAIT_POLL_MS, remaining_ms))
        if poll_ms <= 0:
            poll_ms = 1
        ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
            poll_ms,
        )
        state = ida_dbg.get_process_state()
        if state == ida_dbg.DSTATE_SUSP:
            elapsed = round((_time.monotonic() - started_at) * 1000, 2)
            ip = ida_dbg.get_ip_val()
            return {
                "status": "suspended",
                "stopped_ea": hex(ip) if ip is not None else None,
                "elapsed_ms": elapsed,
            }
        if state == ida_dbg.DSTATE_NOTASK or not ida_dbg.is_debugger_on():
            elapsed = round((_time.monotonic() - started_at) * 1000, 2)
            return {"status": "exited", "stopped_ea": None, "elapsed_ms": elapsed}

    elapsed = round((_time.monotonic() - started_at) * 1000, 2)
    return {"status": "timeout", "stopped_ea": None, "elapsed_ms": elapsed}


def _arm_dbg_start_batch_hook(restore_batch: int) -> None:
    """Install the batch-restore hook before start_process is invoked."""
    global _dbg_start_batch_hook
    if _dbg_start_batch_hook is not None:
        _dbg_start_batch_hook.fallback_restore()
    hook = _DbgStartBatchHook(restore_batch)
    hook.hook()
    _dbg_start_batch_hook = hook

    def _fallback():
        if _dbg_start_batch_hook is hook and not hook._done:
            hook.fallback_restore()
        return -1  # don't repeat

    ida_kernwin.register_timer(_DBG_START_BATCH_FALLBACK_MS, _fallback)


@ext("dbg")
@safety("EXECUTE")
@title("Start Debugger Session")
@tool
@idasync
@keep_batch
def dbg_start() -> DebugControlResult:
    """Launch the configured target under IDA's debugger and report its state.

    WHAT: Starts a fresh debug session for the currently configured target. If
    no breakpoints exist yet, soft breakpoints are auto-planted at every entry
    point so the process suspends at startup instead of running away. Returns
    once the debugger has actually come up (state is trusted over start_process's
    unreliable return code), batch mode auto-handles any startup dialogs.
    WHEN-TO-USE: Only when the user has already selected a debugger
    (Debugger -> Select debugger) and configured the target (executable path /
    arguments / attach pid / remote host). For confirming a static hypothesis
    against the live process.
    RETURNS: A DebugControlResult with state ("running"/"suspended"), started=True,
    and ip (current instruction pointer) when suspended.
    PITFALL: If this fails, do NOT retry in a loop -- stop and ask the user to
    configure the debugger and dismiss any IDA dialogs (e.g. "matching executable
    names") first. In a clean-room RE workflow the maintainer usually F9-launches
    the client manually and you drive the existing session; avoid dbg_start unless
    explicitly asked to start it.
    """
    if len(list_breakpoints()) == 0:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            addr = ida_entry.get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)

    # Arm a DBG_Hooks instance to switch IDA back to its pre-call batch
    # state once the debugger has actually started. Combined with
    # @keep_batch on this function, batch mode stays on across the
    # execute_sync boundary so dialogs the debugger plugin shows during
    # initialization (e.g. "matching executable names") are auto-handled.
    # The hook restores on dbg_process_start / _attach / _exit / _detach,
    # with a register_timer fallback so we never get stuck in batch mode.
    # Capture the pre-call batch (what the caller had set before the
    # sync wrapper bumped it to 1) so headless / batch-mode workflows
    # aren't silently flipped to interactive after dbg_start.
    pre_call_batch = get_pre_call_batch()
    if pre_call_batch is None:
        pre_call_batch = 0
    _arm_dbg_start_batch_hook(restore_batch=pre_call_batch)

    # start_process is documented as asynchronous; when invoked from the
    # IDA main thread inside execute_sync the return code is unreliable
    # (often -1 even on success, because the dbg_process_start event has
    # not yet been dispatched). Trust the actual debugger state instead,
    # and only consult the return code as a tiebreaker for the error
    # message when nothing ever comes up.
    start_result = idaapi.start_process("", "", "")

    started = _get_debug_start_result()
    if started is not None:
        if started.get("running") and "ip" not in started:
            for _ in range(_DBG_START_IP_GRACE_POLL_COUNT):
                ida_dbg.wait_for_next_event(
                    ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
                    _DBG_START_WAIT_POLL_MS,
                )
                waited = _get_debug_start_result()
                if waited is None:
                    continue
                started = waited
                if started.get("suspended") or "ip" in started:
                    break
        return started

    for _ in range(int(_DBG_START_WAIT_TIMEOUT_SEC * 1000 / _DBG_START_WAIT_POLL_MS)):
        ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
            _DBG_START_WAIT_POLL_MS,
        )
        started = _get_debug_start_result()
        if started is not None:
            return started

    if start_result == 0:
        raise IDAError(
            "Debugger start was cancelled. Stop and ask the user to configure "
            "the debugger (Debugger -> Select debugger, set the target path / "
            "arguments) and dismiss any IDA dialogs before retrying."
        )
    raise IDAError(
        "Failed to start debugger. Stop and ask the user to verify that a "
        "debugger is selected (Debugger -> Select debugger), the target is "
        "configured (executable path / arguments / remote host), and any "
        "pending IDA dialogs (e.g. \"matching executable names\") have been "
        "dismissed before retrying."
    )


@ext("dbg")
@safety("READ")
@title("Get Debugger Status")
@tool
@idasync
def dbg_status() -> DebugControlResult:
    """Report whether a debug session is live and where it is stopped.

    WHAT: Queries the debugger lifecycle without changing it -- returns the
    process state ("not_running"/"running"/"suspended") plus the current
    instruction pointer (ip) when the process is suspended.
    WHEN-TO-USE: Before any other dbg_* call to confirm a session is active and
    suspended, or after a continue/step to poll whether the process has come to
    rest again.
    RETURNS: A DebugControlResult: {state, running?/suspended?, ip?}.
    PRO-TIP: Most inspection tools (dbg_regs*, dbg_stacktrace) require the
    process to be SUSPENDED; check state=="suspended" here first to avoid a
    "running; wait until it suspends" error.
    """
    return _get_debug_state_result()


@ext("dbg")
@safety("EXECUTE")
@title("Exit Debugger Session")
@tool
@idasync
def dbg_exit() -> DebugControlResult:
    """Terminate the live debuggee and tear down the debug session.

    WHAT: Kills the running/suspended process and ends the debugger session.
    WHEN-TO-USE: When you are finished with live confirmation and want to return
    IDA to static-analysis mode, or to recover from a wedged session.
    RETURNS: {exited: True, state: "not_running"} on success.
    PITFALL: This destroys all live state (registers, memory, stack) -- capture
    anything you still need first. Requires an active session; errors if none is
    running.
    """
    dbg_ensure_active()
    if idaapi.exit_process():
        return {"exited": True, "state": "not_running"}
    raise IDAError("Failed to exit debugger")


@ext("dbg")
@safety("EXECUTE")
@title("Continue Execution")
@tool
@idasync
def dbg_continue() -> DebugControlResult:
    """Resume the suspended debuggee and let it run freely.

    WHAT: Releases the process from its current breakpoint/step stop. The call
    returns immediately after resuming -- it does NOT block until the next stop.
    WHEN-TO-USE: After planting a breakpoint (dbg_add_bp) on an event of interest
    (a recv path, an opcode handler, an asset load), to run until that breakpoint
    fires.
    RETURNS: A DebugControlResult with continued=True and the post-resume state
    (typically "running").
    PRO-TIP: Because this returns while the process is still running, poll
    dbg_status until state=="suspended" before reading registers/memory. Requires
    a SUSPENDED session to start from.
    """
    dbg_ensure_suspended()
    if idaapi.continue_process():
        result = _get_debug_state_result()
        result["continued"] = True
        return result
    raise IDAError("Failed to continue debugger")


@ext("dbg")
@safety("EXECUTE")
@title("Run To Address")
@tool
@idasync
def dbg_run_to(
    addr: Annotated[
        str, "Target execution address to run to, hex (0x..) or decimal"
    ],
) -> DebugControlResult:
    """Resume execution until the instruction pointer reaches a one-shot address.

    WHAT: Sets a temporary run-to-cursor target at `addr` and resumes. Like
    dbg_continue, it returns right after resuming rather than blocking until the
    target is hit.
    WHEN-TO-USE: To reach a specific instruction once (e.g. land just past a
    decrypt loop, or at a dispatch site) without leaving a persistent breakpoint
    behind via dbg_add_bp.
    RETURNS: A DebugControlResult with continued=True and the post-resume state.
    PITFALL: The target is one-shot and only fires if execution actually reaches
    it -- if the path is never taken the process runs on. Poll dbg_status for
    "suspended" before inspecting. Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    ea = parse_address(addr)
    if idaapi.run_to(ea):
        result = _get_debug_state_result()
        result["continued"] = True
        return result
    raise IDAError(f"Failed to run to address {hex(ea)}")


@ext("dbg")
@safety("EXECUTE")
@title("Step Into")
@tool
@idasync
def dbg_step_into() -> DebugControlResult:
    """Execute a single instruction, descending into any call.

    WHAT: Single-steps one machine instruction; if it is a call, execution stops
    at the first instruction of the callee.
    WHEN-TO-USE: To trace into a subroutine you want to follow -- e.g. stepping
    from a dispatch site into the actual opcode handler, or into a decrypt helper.
    RETURNS: A DebugControlResult with continued=True and the post-step state.
    PRO-TIP: Use dbg_step_over instead when you want to skip over CRT/library
    calls (memcpy, malloc) that would otherwise drop you into uninteresting code.
    Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    if idaapi.step_into():
        result = _get_debug_state_result()
        result["continued"] = True
        return result
    raise IDAError("Failed to step into")


@ext("dbg")
@safety("EXECUTE")
@title("Step Over")
@tool
@idasync
def dbg_step_over() -> DebugControlResult:
    """Execute a single instruction, running any call to completion.

    WHAT: Single-steps one machine instruction; if it is a call, the entire
    callee runs and execution stops at the instruction after the call.
    WHEN-TO-USE: To advance through a function body without diving into helper/
    library calls -- the default stepping mode for following one routine's logic.
    RETURNS: A DebugControlResult with continued=True and the post-step state.
    PITFALL: If the stepped-over call never returns (or hits another breakpoint
    inside it), the process won't come back to the next line as expected -- poll
    dbg_status. Use dbg_step_into when you do need to enter the callee. Requires a
    SUSPENDED session.
    """
    dbg_ensure_suspended()
    if idaapi.step_over():
        result = _get_debug_state_result()
        result["continued"] = True
        return result
    raise IDAError("Failed to step over")


# ============================================================================
# Breakpoint Operations
# ============================================================================


@ext("dbg")
@safety("READ")
@title("List Breakpoints")
@tool
@idasync
def dbg_bps() -> list[Breakpoint]:
    """Enumerate every breakpoint currently defined in the database.

    WHAT: Reads the IDB breakpoint set without changing it -- one entry per
    breakpoint with its address, enabled flag, condition expression, and the
    condition language.
    WHEN-TO-USE: To audit what is planted before continuing, to confirm
    dbg_add_bp / dbg_toggle_bp / dbg_set_bp_condition took effect, or to find an
    address to delete.
    RETURNS: A list of Breakpoint dicts: {addr, enabled, condition, language}.
    Empty list means none are set.
    PRO-TIP: Breakpoints live in the IDB and persist across debug sessions even
    while the process is not running, so this works any time -- no live session
    required.
    """
    return list_breakpoints()


@ext("dbg")
@safety("EXECUTE")
@title("Add Breakpoints")
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[
        list[str] | str,
        "Address(es) to plant soft breakpoints at; hex (0x..) or decimal, a single string is accepted",
    ],
) -> list[BreakpointResult]:
    """Plant software breakpoints at one or more addresses.

    WHAT: Adds a soft (INT3-style) breakpoint at each address. Idempotent -- an
    address that already has a breakpoint is reported ok rather than failing.
    WHEN-TO-USE: To stop the debuggee when execution reaches a function or
    instruction of interest (a recv handler, an opcode dispatch case, a decrypt
    routine) so you can then dbg_continue and inspect state at the hit.
    RETURNS: One BreakpointResult per address, in input order: {addr, ok: True}
    or {addr, error}. Per-address failures never abort the batch.
    PRO-TIP: Breakpoints persist in the IDB and can be set before dbg_start; plant
    them first, then start/continue. Verify with dbg_bps.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
                results.append({"addr": addr, "ok": True})
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["addr"] == hex(ea):
                        results.append({"addr": addr, "ok": True})
                        break
                else:
                    results.append({"addr": addr, "error": "Failed to set breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@safety("EXECUTE")
@title("Delete Breakpoints")
@tool
@idasync
def dbg_delete_bp(
    addrs: Annotated[
        list[str] | str,
        "Address(es) whose breakpoints should be removed; hex (0x..) or decimal, a single string is accepted",
    ],
) -> list[BreakpointResult]:
    """Remove software breakpoints at one or more addresses.

    WHAT: Deletes the breakpoint at each given address from the IDB.
    WHEN-TO-USE: To clean up breakpoints you no longer need (e.g. one-shot
    investigation points) so the debuggee stops flagging them on later runs.
    RETURNS: One BreakpointResult per address, in input order: {addr, ok: True}
    or {addr, error: "Failed to delete breakpoint"} when no breakpoint existed
    there. Per-address failures never abort the batch.
    PRO-TIP: To temporarily silence a breakpoint without losing its condition,
    prefer dbg_toggle_bp(enabled=False) over deleting it.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.del_bpt(ea):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@safety("EXECUTE")
@title("Toggle Breakpoints")
@tool
@idasync
def dbg_toggle_bp(
    items: Annotated[
        list[BreakpointOp] | BreakpointOp,
        "One or more {addr, enabled} ops; enabled=True enables, False disables; a single dict is accepted",
    ],
) -> list[BreakpointResult]:
    """Enable or disable existing breakpoints in batch without deleting them.

    WHAT: For each {addr, enabled} op, flips an already-defined breakpoint on or
    off (enabled defaults to True). The breakpoint and its condition are
    preserved -- only its active state changes.
    WHEN-TO-USE: To temporarily mute a noisy breakpoint, or to re-arm one you
    silenced earlier, without losing its address/condition.
    RETURNS: One BreakpointResult per op, in input order: {addr, ok: True} or
    {addr, error}. Per-op failures never abort the batch.
    PITFALL: The breakpoint must already exist (use dbg_add_bp first); toggling a
    non-existent address reports an error rather than creating one.
    """

    items = normalize_dict_list(items)

    results = []
    for item in items:
        addr = item.get("addr", "")
        enable = item.get("enabled", True)

        try:
            ea = parse_address(addr)
            if idaapi.enable_bpt(ea, enable):
                results.append({"addr": addr, "ok": True})
            else:
                results.append(
                    {
                        "addr": addr,
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                    }
                )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@safety("EXECUTE")
@title("Set Breakpoint Conditions")
@tool
@idasync
def dbg_set_bp_condition(
    items: Annotated[
        list[BreakpointConditionOp] | BreakpointConditionOp,
        "One or more {addr, condition, language?, low_level?} ops; condition is an IDC/Python expression, null/empty clears it; a single dict is accepted",
    ],
) -> list[BreakpointResult]:
    """Attach, change, or clear conditional expressions on existing breakpoints.

    WHAT: For each op, sets a conditional expression on the breakpoint at `addr`
    so it only stops when the expression is true (passing an empty/null condition
    clears it). `language` selects IDC or Python; `low_level` evaluates the
    condition in the debugger rather than after a context switch. The result is
    validated -- a condition that fails to compile is reported as an error.
    WHEN-TO-USE: To stop only on the interesting case of a hot function -- e.g.
    break in a packet handler only when a register holds a specific opcode, or in
    a loop only on the Nth iteration -- instead of halting on every hit.
    RETURNS: One BreakpointResult per op: {addr, ok, condition, language} on
    success or {addr, error}. Per-op failures never abort the batch.
    PITFALL: The breakpoint must already exist (dbg_add_bp first). Switching the
    condition language clears any existing condition before re-applying it, so
    always supply the condition together with a new language.
    """

    items = normalize_dict_list(items)

    results = []
    for item in items:
        addr = item.get("addr", "")
        condition = item.get("condition")
        language = _normalize_breakpoint_language(item.get("language"))
        low_level = bool(item.get("low_level", False))

        try:
            ea = parse_address(addr)
            bpt = ida_dbg.bpt_t()
            if not ida_dbg.get_bpt(ea, bpt):
                results.append({"addr": addr, "error": "Breakpoint not found"})
                continue

            condition_text = "" if condition is None else str(condition)
            current_language = _get_breakpoint_language(bpt)
            current_condition = str(bpt.condition) if bpt.condition else None

            if language is not None and language != current_language:
                if current_condition and condition_text:
                    if not idc.set_bpt_cond(ea, "", 1 if low_level else 0):
                        results.append(
                            {
                                "addr": addr,
                                "error": "Failed to clear existing breakpoint condition before changing its language",
                            }
                        )
                        continue
                    if not ida_dbg.get_bpt(ea, bpt):
                        results.append(
                            {
                                "addr": addr,
                                "error": "Breakpoint condition was cleared, but breakpoint could not be reloaded to update its language",
                            }
                        )
                        continue

                _set_breakpoint_language(bpt, language)
                if not ida_dbg.update_bpt(bpt):
                    results.append(
                        {
                            "addr": addr,
                            "error": f"Failed to apply breakpoint condition language {language}",
                        }
                    )
                    continue

            if not idc.set_bpt_cond(ea, condition_text, 1 if low_level else 0):
                results.append({"addr": addr, "error": "Failed to set breakpoint condition"})
                continue

            updated = ida_dbg.bpt_t()
            if not ida_dbg.get_bpt(ea, updated):
                results.append(
                    {
                        "addr": addr,
                        "error": "Breakpoint condition was set, but breakpoint could not be reloaded for validation",
                    }
                )
                continue

            updated_condition = str(updated.condition) if updated.condition else None
            updated_language = _get_breakpoint_language(updated)
            is_compiled = getattr(updated, "is_compiled", None)
            if condition_text and callable(is_compiled) and not is_compiled():
                results.append(
                    {
                        "addr": addr,
                        "error": "Breakpoint condition was stored but did not compile successfully",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "ok": True,
                    "condition": updated_condition,
                    "language": updated_language,
                }
            )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


# ============================================================================
# Register Operations
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Read All Threads' Registers")
@tool
@idasync
def dbg_regs_all() -> list[ThreadRegisters]:
    """Snapshot the full register file of every thread in the suspended debuggee.

    WHAT: Reads all registers (GP, segment, flags, FPU/SIMD as exposed) for each
    debugger thread. Values are returned as hex strings (or formatted text for
    wide/non-integer registers).
    WHEN-TO-USE: For a complete machine-state snapshot across threads, or when you
    don't yet know which thread hit your breakpoint.
    RETURNS: A list of ThreadRegisters, one per thread: {thread_id, registers:
    [{name, value}, ...]}.
    PRO-TIP: This is verbose; if you only care about the current thread or a few
    registers, dbg_regs / dbg_gpregs / dbg_regs_named are far leaner. Requires a
    SUSPENDED session.
    """
    result: list[ThreadRegisters] = []
    dbg = dbg_ensure_suspended()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        result.append(_get_registers_for_thread(dbg, tid))
    return result


@ext("dbg")
@safety("READ")
@title("Read Registers By Thread ID")
@tool
@idasync
def dbg_regs_remote(
    tids: Annotated[
        list[int] | int, "Thread ID(s) to read full register sets for; a single int is accepted"
    ],
) -> list[ThreadRegistersResult]:
    """Read the full register file for one or more specific thread IDs.

    WHAT: For each requested tid, returns its complete register set. Unknown
    thread ids are reported per-entry rather than aborting the batch.
    WHEN-TO-USE: When you already know the thread id(s) of interest (e.g. from
    dbg_stacktrace or a prior dbg_regs_all) and want their state directly.
    RETURNS: One ThreadRegistersResult per tid: {tid, regs} on success or
    {tid, regs: null, error} when the thread isn't found.
    PRO-TIP: Get valid thread ids from dbg_regs_all first; passing a stale tid
    yields an error entry, not a crash. Requires a SUSPENDED session.
    """
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_suspended()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@safety("READ")
@title("Read Current Thread Registers")
@tool
@idasync
def dbg_regs() -> ThreadRegisters:
    """Read the full register file of the current (stopped) thread.

    WHAT: Returns every register for the thread that is currently selected in the
    debugger -- usually the one that hit the breakpoint or step.
    WHEN-TO-USE: The default "where am I / what's in the registers" call right
    after a breakpoint hit or a step.
    RETURNS: A single ThreadRegisters: {thread_id, registers: [{name, value}, ...]}
    with hex-string values.
    PRO-TIP: Use dbg_gpregs to drop the segment/FPU noise, or dbg_regs_named to
    pull just the registers you care about. Requires a SUSPENDED session.
    """
    dbg = dbg_ensure_suspended()
    tid = ida_dbg.get_current_thread()
    return _get_registers_for_thread(dbg, tid)


@ext("dbg")
@safety("READ")
@title("Read GP Registers By Thread ID")
@tool
@idasync
def dbg_gpregs_remote(
    tids: Annotated[
        list[int] | int,
        "Thread ID(s) to read general-purpose registers for; a single int is accepted",
    ],
) -> list[ThreadRegistersResult]:
    """Read just the general-purpose registers for one or more thread IDs.

    WHAT: Like dbg_regs_remote but filtered to the GP set (E/RAX..E/RSP, E/RIP,
    R8..R15), dropping segment/flags/FPU/SIMD registers.
    WHEN-TO-USE: When you know the thread id(s) and only need integer/pointer
    state -- the common case for following control flow and arguments.
    RETURNS: One ThreadRegistersResult per tid: {tid, regs} or {tid, regs: null,
    error} for unknown threads.
    PRO-TIP: Source valid thread ids from dbg_regs_all/dbg_stacktrace. Requires a
    SUSPENDED session.
    """
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_suspended()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_general_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@safety("READ")
@title("Read Current Thread GP Registers")
@tool
@idasync
def dbg_gpregs() -> ThreadRegisters:
    """Read the general-purpose registers of the current (stopped) thread.

    WHAT: Returns only the GP registers (E/RAX..E/RSP, E/RIP, R8..R15) for the
    currently selected thread.
    WHEN-TO-USE: The lean default for inspecting control flow and arguments right
    after a breakpoint hit, without the segment/FPU clutter of dbg_regs.
    RETURNS: A single ThreadRegisters: {thread_id, registers: [{name, value}, ...]}.
    PRO-TIP: For just one or two specific registers, dbg_regs_named is even
    tighter. Requires a SUSPENDED session.
    """
    dbg = dbg_ensure_suspended()
    tid = ida_dbg.get_current_thread()
    return _get_registers_general_for_thread(dbg, tid)


@ext("dbg")
@safety("READ")
@title("Read Named Registers By Thread ID")
@tool
@idasync
def dbg_regs_named_remote(
    thread_id: Annotated[int, "Thread ID to read registers from"],
    register_names: Annotated[
        str,
        "Comma-separated register names to read (e.g. 'RAX, RBX, RCX'); matched case-sensitively against the platform register names",
    ],
) -> ThreadRegisters:
    """Read a named subset of registers from a specific thread ID.

    WHAT: Returns only the registers whose names appear in `register_names`, for
    the given thread.
    WHEN-TO-USE: When you know both the thread id and exactly which registers you
    want (e.g. the argument registers of a particular handler).
    RETURNS: A ThreadRegisters with just the requested {name, value} entries.
    PITFALL: Names must match the platform's register names exactly; misspelled or
    unsupported names are silently omitted (no error), so an empty result usually
    means a name mismatch. Errors if the thread id is not found. Requires a
    SUSPENDED session.
    """
    dbg = dbg_ensure_suspended()
    if thread_id not in [
        ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
    ]:
        raise IDAError(f"Thread with ID {thread_id} not found")
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, thread_id, names)


@ext("dbg")
@safety("READ")
@title("Read Named Registers")
@tool
@idasync
def dbg_regs_named(
    register_names: Annotated[
        str,
        "Comma-separated register names to read (e.g. 'RAX, RBX, RCX'); matched case-sensitively against the platform register names",
    ],
) -> ThreadRegisters:
    """Read a named subset of registers from the current (stopped) thread.

    WHAT: Returns only the registers named in `register_names`, for the currently
    selected thread.
    WHEN-TO-USE: The tightest register read -- when you want just a couple of
    values (e.g. RIP and the register holding an opcode) after a breakpoint hit.
    RETURNS: A ThreadRegisters with just the requested {name, value} entries.
    PITFALL: Names must match the platform register names exactly; unknown names
    are silently dropped, so an empty result means a name mismatch. Requires a
    SUSPENDED session.
    """
    dbg = dbg_ensure_suspended()
    tid = ida_dbg.get_current_thread()
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, tid, names)


# ============================================================================
# Call Stack Operations
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Get Call Stack")
@tool
@idasync
def dbg_stacktrace() -> list[StackFrameInfo]:
    """Collect the current thread's call stack with module + symbol context.

    WHAT: Walks the current thread's frames innermost-first, resolving each return
    address to its owning module and nearest symbol name.
    WHEN-TO-USE: At a breakpoint hit to understand how execution got here -- which
    caller invoked the handler, whether you are inside a library call, where to
    plant the next breakpoint up the chain.
    RETURNS: A list of StackFrameInfo: {addr, module, symbol}. Unresolved fields
    come back as "<unknown>"/"<unnamed>" rather than failing; returns an empty
    list if the stack can't be collected.
    PRO-TIP: Use the returned addresses as dbg_add_bp / dbg_run_to targets to step
    back out to a caller of interest. Requires a SUSPENDED session.
    """
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "addr": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)

            callstack.append(frame_info)

    except Exception:
        pass
    return callstack


# ============================================================================
# Debugger Memory Operations
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Read Debuggee Memory")
@tool
@idasync
def dbg_read(
    regions: Annotated[
        list[MemoryRead] | MemoryRead,
        "One or more {addr, size} read requests against LIVE process memory; a single dict is accepted",
    ],
) -> list[DebugMemoryReadResult]:
    """Read live debuggee memory from one or more regions, returned as hex.

    WHAT: For each {addr, size} region, reads `size` bytes from the RUNNING
    process's address space (post-relocation, post-decryption, live heap/stack) --
    not the static IDB image. Reads go through the debugger, which can reach pages
    the static view marks PAGE_NOACCESS.
    WHEN-TO-USE: To inspect a buffer at a live pointer -- a received packet before/
    after decryption, a struct at a register-held address, a string the program
    just built -- exactly the ground-truth confirmation step of live RE.
    RETURNS: One DebugMemoryReadResult per region, in order: {addr, size, data
    (hex string), error: null} on success or {addr, size: 0, data: null, error}
    on failure. Per-region failures never abort the batch.
    PITFALL: `data` is a hex STRING. Addresses are only meaningful while the
    session is live; resolve dynamic pointers from a fresh register read each
    stop. Requires an ACTIVE session (running or suspended).
    """

    regions = normalize_dict_list(regions)
    dbg_ensure_active()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            size = region["size"]

            data = idaapi.dbg_read_memory(addr, size)
            if data:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data),
                        "data": data.hex(),
                        "error": None,
                    }
                )
            else:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": 0,
                        "data": None,
                        "error": "Failed to read memory",
                    }
                )

        except Exception as e:
            results.append(
                {"addr": region.get("addr"), "size": 0, "data": None, "error": str(e)}
            )

    return results


@ext("dbg")
@safety("EXECUTE")
@title("Write Debuggee Memory")
@tool
@idasync
def dbg_write(
    regions: Annotated[
        list[MemoryPatch] | MemoryPatch,
        "One or more {addr, data} writes against LIVE process memory; data is a hex string of the bytes to write; a single dict is accepted",
    ],
) -> list[DebugMemoryWriteResult]:
    """Write bytes into the live debuggee's memory at one or more regions.

    WHAT: For each {addr, data} region, decodes the hex `data` and writes it into
    the RUNNING process's address space, mutating live state.
    WHEN-TO-USE: To patch the live process for an experiment -- e.g. flip a branch
    condition, neutralize a check, or feed a crafted value to confirm a hypothesis
    about how the code reacts. Does NOT modify the on-disk binary or the IDB.
    RETURNS: One DebugMemoryWriteResult per region, in order: {addr, size, ok,
    error: null} on success or {addr, size: 0, error} on failure. Per-region
    failures never abort the batch.
    PITFALL: This is destructive to live execution and easily crashes the target
    if you write the wrong width/location; snapshot the original bytes with
    dbg_read first so you can restore them. Requires an ACTIVE session.
    """

    regions = normalize_dict_list(regions)
    dbg_ensure_active()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            data = bytes.fromhex(region["data"])

            success = idaapi.dbg_write_memory(addr, data)
            results.append(
                {
                    "addr": region["addr"],
                    "size": len(data) if success else 0,
                    "ok": success,
                    "error": None if success else "Write failed",
                }
            )

        except Exception as e:
            results.append({"addr": region.get("addr"), "size": 0, "error": str(e)})

    return results
