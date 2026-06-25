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
import ida_lines
import ida_name
import idaapi
import idc

from . import dbg_common
from .rpc import tool, safety, ext, title
from .sync import idasync, keep_batch, get_pre_call_batch, IDAError, tool_timeout
from .utils import (
    RegisterValue,
    ThreadRegisters,
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
    stepped: bool
    running: bool
    suspended: bool
    exited: bool
    state: str
    return_address: str
    error: str


class BreakpointResult(TypedDict, total=False):
    addr: str
    ok: bool
    condition: str | None
    language: str | None
    type: str | None
    hw: bool | None
    size: int | None
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
    original_bytes: str | None
    note: str | None


class RegisterWriteResult(TypedDict, total=False):
    name: str
    value: str
    ok: bool
    old: str | None
    error: str


class MemoryRegionInfo(TypedDict, total=False):
    start: str
    end: str
    size: int
    perm: str | None
    module: str | None
    kind: str


class MemoryMapResult(TypedDict, total=False):
    regions: list[MemoryRegionInfo]
    module_bases: list[dict]
    count: int
    error: str


class PointerClassResult(TypedDict, total=False):
    addr: str
    region: list[int] | None
    module: str | None
    perm: str | None
    offset_in_region: int | None
    kind: str
    preview: str | None
    error: str


class PointerInfo(TypedDict, total=False):
    reg: str
    value: str
    kind: str
    module: str | None
    perm: str | None
    offset_in_region: int | None
    preview: str | None


class DisasmLineLite(TypedDict, total=False):
    addr: str
    instruction: str
    current: bool


class StackArgInfo(TypedDict, total=False):
    index: int
    location: str
    value: str | None


class FlagsInfo(TypedDict, total=False):
    raw: str
    set: list[str]


class StopContextResult(TypedDict, total=False):
    state: str
    tid: int
    ip: str
    function: str | None
    abi: str
    disasm: list[DisasmLineLite]
    registers: list[RegisterValue]
    flags: FlagsInfo
    stack_args: list[StackArgInfo]
    stacktrace: list["StackFrameInfo"]
    pointers: list[PointerInfo]
    error: str


class ThreadInfo(TypedDict, total=False):
    tid: int
    current: bool
    ip: str | None
    name: str | None


class ThreadListResult(TypedDict, total=False):
    threads: list[ThreadInfo]
    current: int | None
    error: str


class ThreadSelectResult(TypedDict, total=False):
    tid: int
    ok: bool
    ip: str | None
    error: str


class HwSlotInfo(TypedDict, total=False):
    total: int
    used: int
    free: int
    occupants: list[str]


class ExceptionConfigResult(TypedDict, total=False):
    code: int
    name: str | None
    catch: bool
    stop: bool
    ok: bool
    error: str


# ============================================================================
# Constants and Helper Functions
# ============================================================================

# Default bounded wait (ms) for blocking control tools before they report
# "timeout" / "running" if the next debug event never arrives.
_DEFAULT_BLOCK_WAIT_MS = 10_000

# x86 EFLAGS bit positions -> short mnemonic. Used to decode the flags register
# into a human-readable set in stop_context.
_EFLAGS_BITS: list[tuple[int, str]] = [
    (0, "CF"),
    (2, "PF"),
    (4, "AF"),
    (6, "ZF"),
    (7, "SF"),
    (8, "TF"),
    (9, "IF"),
    (10, "DF"),
    (11, "OF"),
]

# Processor-family GP register name sets, matched case-insensitively against the
# debugger's register names. x86/x64 keeps the historical allowlist; ARM/AArch64
# are added so register reads aren't silently empty on those targets. Anything
# not covered here falls back to "all registers" rather than an empty filter.
_GP_REGS_X86 = {
    "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
}
_GP_REGS_ARM = (
    {f"R{i}" for i in range(16)}
    | {"SP", "LR", "PC"}
)
_GP_REGS_AARCH64 = (
    {f"X{i}" for i in range(31)}
    | {f"W{i}" for i in range(31)}
    | {"SP", "LR", "PC", "XSP", "XPC"}
)


def _processor_gp_registers() -> set[str]:
    """Processor-aware GP register name set (upper-cased).

    Picks x86/x64, ARM, or AArch64 based on the IDB processor name so register
    reads work beyond Intel. Falls back to the union of all known families when
    the processor is unrecognised (the filter then keeps any register that looks
    general-purpose on SOME family rather than dropping everything).
    """
    proc = ""
    try:
        import ida_ida

        proc = str(getattr(ida_ida, "inf_get_procname", lambda: "")() or "").lower()
    except Exception:
        proc = ""
    if not proc:
        try:
            info = idaapi.get_inf_structure()
            proc = str(getattr(info, "procname", "") or "").lower()
        except Exception:
            proc = ""

    if "arm" in proc:
        # IDA reports both arm and aarch64 under "arm"/"armb"; AArch64 exposes
        # 64-bit. Offer both register families so X*/R* both resolve.
        return _GP_REGS_ARM | _GP_REGS_AARCH64
    if "aarch64" in proc:
        return _GP_REGS_AARCH64
    if proc in ("metapc", "8086", "80386p", "80386r", "80486p", "p2", "p3", "p4") or "pc" in proc:
        return _GP_REGS_X86
    # Unknown processor: union so we don't return an empty register view.
    return _GP_REGS_X86 | _GP_REGS_ARM | _GP_REGS_AARCH64


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
    gp_names = _processor_gp_registers()
    general_registers = [
        reg
        for reg in all_registers["registers"]
        if reg["name"].upper() in gp_names
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


class BreakpointInfo(TypedDict, total=False):
    addr: str
    enabled: bool
    condition: str | None
    language: str | None
    type: str
    size: int
    hw: bool


# Map ida_dbg BPT_* type codes -> human label. BPT_SOFT is the default INT3-style
# software breakpoint; the rest are hardware (debug-register backed) and consume a
# DR slot.
_BPT_TYPE_NAMES = {
    "BPT_SOFT": "soft",
    "BPT_EXEC": "exec",
    "BPT_WRITE": "write",
    "BPT_RDWR": "rdwr",
    "BPT_READ": "read",
    "BPT_DEFAULT": "default",
}

# Hardware breakpoint types (debug-register backed). Each occupies one of the 4
# DR slots. Resolved lazily so a missing constant on an older SDK is tolerated.
_HW_BPT_TYPE_NAMES = ("BPT_EXEC", "BPT_WRITE", "BPT_RDWR", "BPT_READ")

# Total hardware debug-register slots on x86/x64 (DR0..DR3).
_HW_BPT_SLOTS = 4


def _resolve_bpt_type(name: str) -> int | None:
    """Resolve a BPT_* type name to its int code, tolerating SDK variance."""
    return getattr(ida_dbg, name, None)


def _bpt_type_label(type_code: int) -> str:
    """Human label for a bpt_t.type code (e.g. 'soft'/'write'/'exec')."""
    for cname, label in _BPT_TYPE_NAMES.items():
        code = _resolve_bpt_type(cname)
        if code is not None and code == type_code:
            return label
    return f"type({type_code})"


def _bpt_is_hardware(type_code: int) -> bool:
    """True if `type_code` is a hardware (DR-slot) breakpoint type."""
    soft = _resolve_bpt_type("BPT_SOFT")
    if soft is not None and type_code == soft:
        return False
    for cname in _HW_BPT_TYPE_NAMES:
        code = _resolve_bpt_type(cname)
        if code is not None and code == type_code:
            return True
    return False


def _breakpoint_info(bpt: "ida_dbg.bpt_t") -> BreakpointInfo:
    type_code = int(getattr(bpt, "type", _resolve_bpt_type("BPT_SOFT") or 0))
    return BreakpointInfo(
        addr=hex(bpt.ea),
        enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
        condition=str(bpt.condition) if bpt.condition else None,
        language=_get_breakpoint_language(bpt),
        type=_bpt_type_label(type_code),
        size=int(getattr(bpt, "size", 0) or 0),
        hw=_bpt_is_hardware(type_code),
    )


def list_breakpoints() -> list[BreakpointInfo]:
    breakpoints: list[BreakpointInfo] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(_breakpoint_info(bpt))
    return breakpoints


def _hw_slot_accounting() -> HwSlotInfo:
    """Count used/free hardware debug-register slots across all breakpoints."""
    occupants: list[str] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.getn_bpt(i, bpt):
            continue
        type_code = int(getattr(bpt, "type", 0))
        if _bpt_is_hardware(type_code):
            occupants.append(hex(bpt.ea))
    used = len(occupants)
    return HwSlotInfo(
        total=_HW_BPT_SLOTS,
        used=used,
        free=max(0, _HW_BPT_SLOTS - used),
        occupants=occupants,
    )


# ----------------------------------------------------------------------------
# Live reader helpers (thin wrappers over ida_dbg) used by stop_context and the
# step/return tools. They feed the PURE dbg_common helpers small inputs.
# ----------------------------------------------------------------------------


def _ptr_size_live() -> int:
    """Pointer width of the target (8 on 64-bit, else 4)."""
    try:
        import ida_ida

        if hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit():
            return 8
    except Exception:
        pass
    try:
        info = idaapi.get_inf_structure()
        if getattr(info, "is_64bit", lambda: False)():
            return 8
    except Exception:
        pass
    return 4


def _is_windows_target() -> bool:
    """Best-effort: is the analysed target a Windows (PE) image?

    Used only to pick win64 vs sysv for 64-bit arg resolution; defaults to True
    on Windows-hosted IDA when the filetype is unclear.
    """
    try:
        ftype = idaapi.get_file_type_name() or ""
        low = ftype.lower()
        if "portable executable" in low or "pe" == low.strip() or "ms-dos" in low:
            return True
        if "elf" in low:
            return False
        if "mach-o" in low or "macho" in low:
            return False
    except Exception:
        pass
    # Fall back to the host OS of the IDA process.
    return os.name == "nt"


def _read_reg_live(name: str) -> int | None:
    """Read one register value as an int from the current thread, or None."""
    try:
        rv = ida_dbg.get_reg_val(name.upper())
    except Exception:
        return None
    if isinstance(rv, int):
        return rv
    try:
        return int(rv)
    except Exception:
        return None


def _read_sp_live() -> int | None:
    """Read the stack pointer (RSP/ESP) of the current thread."""
    name = "RSP" if _ptr_size_live() == 8 else "ESP"
    return _read_reg_live(name)


def _read_stack_word_live(sp_disp: int) -> int | None:
    """Read a pointer-sized word at SP + sp_disp from live memory."""
    sp = _read_sp_live()
    if sp is None:
        return None
    psize = _ptr_size_live()
    raw = idaapi.dbg_read_memory(sp + int(sp_disp), psize)
    if not raw or len(raw) < psize:
        return None
    return int.from_bytes(bytes(raw), "little")


def _decode_eflags(value: int) -> FlagsInfo:
    """Decode an x86 EFLAGS/RFLAGS value into the set of mnemonics that are 1."""
    out: list[str] = []
    for bit, name in _EFLAGS_BITS:
        if value & (1 << bit):
            out.append(name)
    return FlagsInfo(raw=hex(value), set=out)


def _disasm_window(ip: int, before: int = 4, after: int = 6) -> list[DisasmLineLite]:
    """Disassemble a small window of instructions around `ip`.

    Walks `before` instructions back (best-effort) and `after` forward, marking
    the line at ip with current=True. Tolerant of decode failures.
    """
    lines: list[DisasmLineLite] = []
    # Walk backwards to find a sane window start.
    start = ip
    for _ in range(max(0, before)):
        prev = idc.prev_head(start)
        if prev == idaapi.BADADDR or prev >= start:
            break
        start = prev

    ea = start
    count = before + after + 1
    for _ in range(max(1, count)):
        if ea == idaapi.BADADDR:
            break
        line = ida_lines.generate_disasm_line(ea, 0)
        text = ida_lines.tag_remove(line) if line else ""
        lines.append(DisasmLineLite(
            addr=hex(ea),
            instruction=" ".join(text.split()),
            current=(ea == ip),
        ))
        nxt = idc.next_head(ea, idaapi.BADADDR)
        if nxt == idaapi.BADADDR or nxt <= ea:
            break
        ea = nxt
    return lines


def _byte_preview_live(addr: int, size: int = 16) -> str | None:
    """Read a short byte preview from live memory at `addr` (hex string)."""
    try:
        raw = idaapi.dbg_read_memory(addr, size)
    except Exception:
        return None
    if not raw:
        return None
    return bytes(raw).hex()


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


def _wait_for_settle(timeout_ms: int) -> dict:
    """Pump wait_for_next_event until the process suspends/exits or times out.

    Unlike _continue_and_wait this does NOT resume the process -- it assumes the
    caller already issued a step/continue and just waits for the resulting event
    to settle. Returns {status, stopped_ea, elapsed_ms} mirroring _continue_and_wait
    (status in "suspended"|"exited"|"timeout"|"not_running").
    """
    import time as _time

    if not ida_dbg.is_debugger_on():
        return {"status": "not_running", "stopped_ea": None, "elapsed_ms": 0}

    started_at = _time.monotonic()
    deadline = started_at + max(0, timeout_ms) / 1000.0
    while True:
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

    elapsed = round((_time.monotonic() - started_at) * 1000, 2)
    return {"status": "timeout", "stopped_ea": None, "elapsed_ms": elapsed}


def _block_result_from_wait(wait: dict) -> DebugControlResult:
    """Translate a _continue_and_wait / _wait_for_settle dict into a settled
    DebugControlResult (state + ip when suspended, exited flag, etc.)."""
    status = wait.get("status")
    result: DebugControlResult = {}
    if status == "suspended":
        result["state"] = "suspended"
        result["suspended"] = True
        stopped = wait.get("stopped_ea")
        if stopped is None:
            ip = ida_dbg.get_ip_val()
            stopped = hex(ip) if ip is not None else None
        if stopped is not None:
            result["ip"] = stopped
    elif status == "exited":
        result["state"] = "not_running"
        result["exited"] = True
    elif status in ("timeout", "running"):
        result["state"] = "running"
        result["running"] = True
    else:
        result.update(_get_debug_state_result())
    return result


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
def dbg_start(
    plant_entry_bps: Annotated[
        bool,
        "When True AND no breakpoints exist yet, plant soft breakpoints at every "
        "entry point so the process suspends at startup instead of running away. "
        "Default False: dbg_start mutates no breakpoints in the IDB and the target "
        "runs freely until it hits a pre-existing breakpoint or exits.",
    ] = False,
) -> DebugControlResult:
    """Launch the configured target under IDA's debugger and report its state.

    WHAT: Starts a fresh debug session for the currently configured target. By
    default NO entry breakpoints are planted -- the IDB's breakpoint set is left
    untouched and the target runs until it hits a pre-existing breakpoint or
    exits. Set plant_entry_bps=True to opt into auto-planting soft breakpoints at
    every entry point (only done when no breakpoints exist yet) so the process
    suspends at startup. Returns once the debugger has actually come up (state is
    trusted over start_process's unreliable return code), batch mode auto-handles
    any startup dialogs.
    WHEN-TO-USE: Only when the user has already selected a debugger
    (Debugger -> Select debugger) and configured the target (executable path /
    arguments / attach pid / remote host). For confirming a static hypothesis
    against the live process. Pass plant_entry_bps=True when you specifically want
    to halt at program entry without setting your own breakpoint first.
    RETURNS: A DebugControlResult with state ("running"/"suspended"), started=True,
    and ip (current instruction pointer) when suspended.
    PRO-TIP: Set your own breakpoint with dbg_bp_add before calling dbg_start to
    control exactly where execution halts, instead of relying on plant_entry_bps.
    PITFALL: If this fails, do NOT retry in a loop -- stop and ask the user to
    configure the debugger and dismiss any IDA dialogs (e.g. "matching executable
    names") first. In a clean-room RE workflow the maintainer usually F9-launches
    the client manually and you drive the existing session; avoid dbg_start unless
    explicitly asked to start it. plant_entry_bps mutates the IDB's breakpoint set
    (an undocumented side effect if left on by accident), which is why it defaults
    to False.
    """
    if plant_entry_bps and len(list_breakpoints()) == 0:
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

    WHAT: KILLS the running/suspended process and ends the debugger session.
    WHEN-TO-USE: When you are finished with live confirmation and want to return
    IDA to static-analysis mode, or to recover from a wedged session.
    RETURNS: {exited: True, state: "not_running"} on success.
    PITFALL: This TERMINATES the target and destroys all live state (registers,
    memory, stack) -- capture anything you still need first. To leave the process
    RUNNING and only stop debugging it, use dbg_detach instead. Requires an active
    session; errors if none is running.
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
@tool_timeout(120.0)
def dbg_continue(
    wait_ms: Annotated[
        int,
        "Bounded milliseconds to BLOCK waiting for the next debug event before "
        "returning. Default 10000. Pass 0 to resume and return immediately "
        "without blocking (legacy fire-and-forget behaviour).",
    ] = _DEFAULT_BLOCK_WAIT_MS,
) -> DebugControlResult:
    """Resume the suspended debuggee and BLOCK until it next comes to rest.

    WHAT: Releases the process from its current breakpoint/step stop and, by
    default, blocks (bounded by wait_ms) pumping the debug-event loop until the
    process suspends again, exits, or the wait elapses -- then reports the REAL
    post-stop ip/state. Pass wait_ms=0 to resume and return immediately (the old
    fire-and-forget behaviour) when you want to poll dbg_status yourself.
    WHEN-TO-USE: After planting a breakpoint (dbg_add_bp) on an event of interest
    (a recv path, an opcode handler, an asset load), to run until that breakpoint
    fires and land directly on the settled state.
    RETURNS: A DebugControlResult with continued=True and the SETTLED state:
    state=="suspended" + ip when it stopped, exited=True when the process ended,
    or state=="running" if the bounded wait elapsed first (poll dbg_status then).
    PRO-TIP: If wait_ms elapses with state=="running", the breakpoint simply has
    not been hit yet -- call dbg_continue again or raise wait_ms. Requires a
    SUSPENDED session to start from.
    """
    dbg_ensure_suspended()
    if wait_ms and wait_ms > 0:
        wait = _continue_and_wait(int(wait_ms))
        if wait.get("status") == "failed_to_resume":
            raise IDAError("Failed to continue debugger")
        result = _block_result_from_wait(wait)
        result["continued"] = True
        return result
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
@tool_timeout(120.0)
def dbg_run_to(
    addr: Annotated[
        str, "Target execution address to run to, hex (0x..) or decimal"
    ],
    wait_ms: Annotated[
        int,
        "Bounded milliseconds to BLOCK waiting until the target is reached (or "
        "the process otherwise stops). Default 10000. Pass 0 to resume and return "
        "immediately without blocking.",
    ] = _DEFAULT_BLOCK_WAIT_MS,
) -> DebugControlResult:
    """Resume execution until the instruction pointer reaches a one-shot address.

    WHAT: Sets a temporary run-to-cursor target at `addr`, resumes, and by default
    BLOCKS (bounded by wait_ms) until execution actually reaches it (or the process
    otherwise stops/exits), returning the REAL settled ip/state. Pass wait_ms=0 to
    resume and return immediately without blocking.
    WHEN-TO-USE: To reach a specific instruction once (e.g. land just past a
    decrypt loop, or at a dispatch site) without leaving a persistent breakpoint
    behind via dbg_add_bp.
    RETURNS: A DebugControlResult with continued=True and the SETTLED state:
    state=="suspended" + ip at the target, exited=True if the process ended, or
    state=="running" if the bounded wait elapsed before the target was hit.
    PITFALL: The target is one-shot and only fires if execution actually reaches
    it -- if the path is never taken the process runs until wait_ms elapses and
    state comes back "running". Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    ea = parse_address(addr)
    if wait_ms and wait_ms > 0:
        wait = _continue_and_wait(int(wait_ms), target_ea=ea)
        if wait.get("status") == "failed_to_resume":
            raise IDAError(f"Failed to run to address {hex(ea)}")
        result = _block_result_from_wait(wait)
        result["continued"] = True
        return result
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
@tool_timeout(60.0)
def dbg_step_into(
    wait_ms: Annotated[
        int,
        "Bounded milliseconds to wait for the step to settle before returning. "
        "Default 5000. Pass 0 to issue the step and return the (stale) state "
        "immediately without waiting.",
    ] = 5000,
) -> DebugControlResult:
    """Execute a single instruction, descending into any call, then settle.

    WHAT: Single-steps one machine instruction; if it is a call, execution stops
    at the first instruction of the callee. The step is asynchronous, so this
    waits (bounded by wait_ms) for the step to complete and returns the SETTLED
    ip/state rather than a stale pre-step ip.
    WHEN-TO-USE: To trace into a subroutine you want to follow -- e.g. stepping
    from a dispatch site into the actual opcode handler, or into a decrypt helper.
    RETURNS: A DebugControlResult with stepped=True and the settled state
    (state=="suspended" + the new ip, or exited=True if the step ended the
    process).
    PRO-TIP: Use dbg_step_over instead when you want to skip over CRT/library
    calls (memcpy, malloc) that would otherwise drop you into uninteresting code.
    Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    if not idaapi.step_into():
        raise IDAError("Failed to step into")
    if wait_ms and wait_ms > 0:
        wait = _wait_for_settle(int(wait_ms))
        result = _block_result_from_wait(wait)
    else:
        result = _get_debug_state_result()
    result["stepped"] = True
    return result


@ext("dbg")
@safety("EXECUTE")
@title("Step Over")
@tool
@idasync
@tool_timeout(60.0)
def dbg_step_over(
    wait_ms: Annotated[
        int,
        "Bounded milliseconds to wait for the step to settle before returning. "
        "Default 5000. Pass 0 to issue the step and return immediately.",
    ] = 5000,
) -> DebugControlResult:
    """Execute a single instruction, running any call to completion, then settle.

    WHAT: Single-steps one machine instruction; if it is a call, the entire
    callee runs and execution stops at the instruction after the call. Waits
    (bounded by wait_ms) for the step to settle and returns the SETTLED ip/state
    instead of a stale pre-step ip.
    WHEN-TO-USE: To advance through a function body without diving into helper/
    library calls -- the default stepping mode for following one routine's logic.
    RETURNS: A DebugControlResult with stepped=True and the settled state.
    PITFALL: If the stepped-over call never returns within wait_ms (or hits
    another breakpoint inside it), state comes back "running" -- poll dbg_status.
    Use dbg_step_into when you do need to enter the callee. Requires a SUSPENDED
    session.
    """
    dbg_ensure_suspended()
    if not idaapi.step_over():
        raise IDAError("Failed to step over")
    if wait_ms and wait_ms > 0:
        wait = _wait_for_settle(int(wait_ms))
        result = _block_result_from_wait(wait)
    else:
        result = _get_debug_state_result()
    result["stepped"] = True
    return result


@ext("dbg")
@safety("EXECUTE")
@title("Step Out (Run To Return)")
@tool
@idasync
@tool_timeout(120.0)
def dbg_step_out(
    wait_ms: Annotated[
        int,
        "Bounded milliseconds to BLOCK waiting to land on the return address. "
        "Default 10000. Pass 0 to resume and return immediately.",
    ] = _DEFAULT_BLOCK_WAIT_MS,
) -> DebugControlResult:
    """Run the current function to completion and stop at its return address.

    WHAT: Reads the return address off the top of the stack at the current
    suspended stop (the pointer-sized word at SP, where a function epilogue has
    not yet rebalanced the frame) and run_to()s it, blocking (bounded by wait_ms)
    until execution returns to the caller. This is the "finish current frame"
    primitive.
    WHEN-TO-USE: When you have stepped into a callee (or hit a breakpoint inside
    one) and want to get back out to the caller in one move, e.g. to inspect the
    return value (RAX/EAX) at the call site.
    RETURNS: A DebugControlResult with stepped=True and the settled state at the
    return address.
    PITFALL: This assumes SP currently points at the return address -- it is most
    reliable at a function's PROLOGUE/ENTRY before locals are pushed. Deeper in a
    frame the top-of-stack is not the return address; in that case prefer
    dbg_run_to with an explicit address from dbg_stacktrace. Requires a SUSPENDED
    session.
    """
    dbg_ensure_suspended()
    psize = _ptr_size_live()
    sp = _read_sp_live()
    if sp is None:
        raise IDAError("Could not read the stack pointer to find the return address")
    raw = idaapi.dbg_read_memory(sp, psize)
    if not raw or len(raw) < psize:
        raise IDAError("Could not read the return address off the stack")
    ret_ea = int.from_bytes(bytes(raw), "little")
    wait = _continue_and_wait(int(wait_ms) if wait_ms else 1, target_ea=ret_ea)
    if wait.get("status") == "failed_to_resume":
        raise IDAError(f"Failed to run to return address {hex(ret_ea)}")
    result = _block_result_from_wait(wait)
    result["stepped"] = True
    result["return_address"] = hex(ret_ea)
    return result


# ============================================================================
# Breakpoint Operations
# ============================================================================


class BreakpointListResult(TypedDict, total=False):
    breakpoints: list[BreakpointInfo]
    hw_slots: HwSlotInfo


@ext("dbg")
@safety("READ")
@title("List Breakpoints")
@tool
@idasync
def dbg_bps() -> BreakpointListResult:
    """Enumerate every breakpoint currently defined, with type + HW-slot usage.

    WHAT: Reads the IDB breakpoint set without changing it -- one entry per
    breakpoint with its address, enabled flag, condition expression, condition
    language, the breakpoint TYPE (soft/exec/write/rdwr/read), its byte size, and
    whether it is a HARDWARE breakpoint (debug-register backed). Also reports
    hardware DR-slot accounting (total/used/free + which addresses occupy slots).
    WHEN-TO-USE: To audit what is planted before continuing, to confirm
    dbg_add_bp / dbg_toggle_bp / dbg_set_bp_condition took effect, to find an
    address to delete, or to see how many of the 4 hardware watch slots are free.
    RETURNS: {breakpoints: [{addr, enabled, condition, language, type, size, hw}],
    hw_slots: {total, used, free, occupants}}. Empty breakpoints means none set.
    PRO-TIP: Breakpoints live in the IDB and persist across debug sessions even
    while the process is not running, so this works any time -- no live session
    required. Only 4 hardware (write/rdwr/exec) breakpoints can be active at once;
    check hw_slots.free before adding another.
    """
    return {"breakpoints": list_breakpoints(), "hw_slots": _hw_slot_accounting()}


# Caller-facing breakpoint type tokens -> ida_dbg BPT_* constant name.
_BP_TYPE_TOKENS = {
    "soft": "BPT_SOFT",
    "exec": "BPT_EXEC",
    "hw_exec": "BPT_EXEC",
    "write": "BPT_WRITE",
    "w": "BPT_WRITE",
    "rdwr": "BPT_RDWR",
    "rw": "BPT_RDWR",
    "readwrite": "BPT_RDWR",
    "read": "BPT_READ",
    "r": "BPT_READ",
}


def _resolve_bp_request(bp_type: str, size: int) -> tuple[int, int, bool]:
    """Map a caller bp_type token + size to (type_code, size, is_hardware).

    Raises IDAError on an unknown token or a size that is invalid for the type.
    """
    token = str(bp_type or "soft").strip().lower()
    cname = _BP_TYPE_TOKENS.get(token)
    if cname is None:
        raise IDAError(
            f"unknown breakpoint type {bp_type!r}; expected one of "
            f"{sorted(set(_BP_TYPE_TOKENS))}"
        )
    code = _resolve_bpt_type(cname)
    if code is None:
        raise IDAError(f"breakpoint type {token!r} unsupported by this IDA build")
    soft = _resolve_bpt_type("BPT_SOFT")
    if code == soft:
        return code, 0, False
    # Hardware data/exec breakpoint: size must be 1/2/4 (8 on 64-bit) and the
    # debugger allocates a DR slot. Default size 1 when caller passes 0.
    sz = int(size) if size else 1
    valid = {1, 2, 4} | ({8} if _ptr_size_live() == 8 else set())
    if sz not in valid:
        raise IDAError(
            f"hardware breakpoint size must be one of {sorted(valid)}, got {sz}"
        )
    return code, sz, True


@ext("dbg")
@safety("EXECUTE")
@title("Add Breakpoints")
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[
        list[str] | str,
        "Address(es) to plant breakpoints at; hex (0x..) or decimal, a single string is accepted",
    ],
    bp_type: Annotated[
        str,
        "Breakpoint type: 'soft' (default, INT3 software bp), or a HARDWARE type "
        "'exec' (DR exec bp), 'write' (data write watchpoint), 'rdwr' (read+write "
        "watchpoint), 'read'. Hardware types consume one of the 4 CPU debug-register "
        "slots.",
    ] = "soft",
    size: Annotated[
        int,
        "For HARDWARE data/exec breakpoints, the watched window size in bytes "
        "(1/2/4, or 8 on 64-bit). Ignored for soft breakpoints. Defaults to 1.",
    ] = 0,
) -> list[BreakpointResult]:
    """Plant software or hardware breakpoints/watchpoints at one or more addresses.

    WHAT: Adds a breakpoint at each address. bp_type='soft' (default) is an
    INT3-style software breakpoint; 'exec'/'write'/'rdwr'/'read' are HARDWARE
    breakpoints backed by the CPU debug registers (DR0..DR3) with a watched `size`
    window -- 'write'/'rdwr'/'read' are data watchpoints that fire on memory
    access. Idempotent for soft bps -- an address that already has one is reported
    ok rather than failing.
    WHEN-TO-USE: Soft bps to stop when execution reaches an instruction of
    interest; hardware WRITE/RDWR watchpoints to stop when a specific variable/
    field is read or written (the classic "who writes this global" question).
    RETURNS: One BreakpointResult per address, in input order: {addr, ok: True,
    type, hw, size} or {addr, error}. Per-address failures never abort the batch.
    PRO-TIP: Breakpoints persist in the IDB and can be set before dbg_start.
    Verify with dbg_bps, which also reports hardware-slot usage.
    PITFALL: Only 4 hardware slots exist. If they are all in use this FAILS LOUDLY
    with an "all 4 hardware breakpoint slots in use" error rather than silently
    planting a non-firing watchpoint -- delete an existing hardware bp first.
    """
    addrs = normalize_list_input(addrs)
    results = []

    try:
        type_code, eff_size, is_hw = _resolve_bp_request(bp_type, size)
    except IDAError as exc:
        return [{"addr": a, "error": str(exc)} for a in addrs]

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Fail loudly when the hardware DR slots are exhausted, instead of
            # planting a watchpoint that never fires.
            if is_hw:
                slots = _hw_slot_accounting()
                already = any(o == hex(ea) for o in slots["occupants"])
                if not already and slots["free"] <= 0:
                    results.append({
                        "addr": addr,
                        "error": (
                            f"all {slots['total']} hardware breakpoint slots in use "
                            f"({', '.join(slots['occupants'])}); delete one first"
                        ),
                    })
                    continue

            if idaapi.add_bpt(ea, eff_size, type_code):
                results.append({
                    "addr": addr, "ok": True,
                    "type": _bpt_type_label(type_code), "hw": is_hw, "size": eff_size,
                })
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["addr"] == hex(ea):
                        results.append({
                            "addr": addr, "ok": True,
                            "type": bpt.get("type"), "hw": bpt.get("hw"),
                            "size": bpt.get("size"),
                        })
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
    return _collect_stacktrace()


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
    RETURNS: One DebugMemoryWriteResult per region, in order. On success:
    {addr, size, ok: True, error: null, original_bytes (hex of the bytes that were
    overwritten), note}. On failure: {addr, size: 0, ok: False, error,
    original_bytes, note: null} (all branches share the same keys). The
    original_bytes are captured BEFORE the write so the caller can restore the
    target by writing them back to the same addr. Per-region failures never abort
    the batch.
    PRO-TIP: To revert a successful write, call dbg_write again with the returned
    original_bytes as the new data at the same addr.
    PITFALL: This is destructive to live execution and easily crashes the target
    if you write the wrong width/location; original_bytes is captured for you, but
    only at the exact addr/size written -- it does not snapshot wider context.
    Requires an ACTIVE session.
    """

    regions = normalize_dict_list(regions)
    dbg_ensure_active()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            data = bytes.fromhex(region["data"])

            # Capture the original bytes BEFORE writing so the caller can
            # restore live state by writing original_bytes back to addr.
            original = idaapi.dbg_read_memory(addr, len(data))
            original_hex = original.hex() if original else None

            success = idaapi.dbg_write_memory(addr, data)
            if success:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data),
                        "ok": True,
                        "error": None,
                        "original_bytes": original_hex,
                        "note": "original_bytes captured before write; write them "
                        "back to addr to revert this live-memory change",
                    }
                )
            else:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": 0,
                        "ok": False,
                        "error": "Write failed",
                        "original_bytes": original_hex,
                        "note": None,
                    }
                )

        except Exception as e:
            results.append(
                {
                    "addr": region.get("addr"),
                    "size": 0,
                    "ok": False,
                    "error": str(e),
                    "original_bytes": None,
                    "note": None,
                }
            )

    return results


# ============================================================================
# Register Writes
# ============================================================================


@ext("dbg")
@safety("EXECUTE")
@title("Set Register Value")
@tool
@idasync
def dbg_set_reg(
    name: Annotated[str, "Register name to write (e.g. 'RAX', 'EIP', 'RDI'); matched case-insensitively"],
    value: Annotated[str, "New value, hex (0x..) or decimal"],
) -> RegisterWriteResult:
    """Overwrite a single register in the current (stopped) thread.

    WHAT: Reads the register's old value (for the round-trip), then writes `value`
    into it via ida_dbg.set_reg_val. Mutates LIVE machine state only -- the IDB and
    on-disk binary are untouched.
    WHEN-TO-USE: To steer a live experiment -- force a branch by flipping a flag-
    holding register, redirect control by setting RIP/EIP, or inject a crafted
    pointer/value into an argument register before continuing.
    RETURNS: {name, value, ok: True, old} on success (old is the prior value as
    hex so you can restore it) or {name, error} on failure.
    PITFALL: This easily destabilises the target (especially writing RIP/RSP) --
    capture `old` and write it back to revert. Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    rn = name.strip()
    try:
        val = parse_address(value)
    except Exception:
        try:
            val = int(str(value), 0)
        except Exception as exc:
            return {"name": rn, "error": f"bad value {value!r}: {exc}"}

    old = _read_reg_live(rn)
    try:
        if ida_dbg.set_reg_val(rn.upper(), val):
            return {
                "name": rn,
                "value": hex(val),
                "ok": True,
                "old": hex(old) if isinstance(old, int) else None,
            }
        return {"name": rn, "error": f"set_reg_val rejected register {rn!r}"}
    except Exception as exc:
        return {"name": rn, "error": str(exc)}


# ============================================================================
# Fused "Where Am I" Context
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Stop Context (Where Am I)")
@tool
@idasync
def stop_context(
    arg_count: Annotated[
        int, "How many integer/pointer arguments to resolve at the current frame (default 4)"
    ] = 4,
    disasm_before: Annotated[int, "Instructions to show before ip (default 3)"] = 3,
    disasm_after: Annotated[int, "Instructions to show after ip (default 6)"] = 6,
    preview_bytes: Annotated[int, "Bytes of memory preview to read where each register points (default 16)"] = 16,
) -> StopContextResult:
    """One fused "where am I" snapshot at the current suspended stop.

    WHAT: The highest-leverage debug read. In one call returns: the instruction
    pointer + owning function, a small disassembly window around ip (current line
    flagged), the full register file, decoded EFLAGS (which flag bits are set),
    the top N integer/pointer arguments resolved via the DETECTED ABI (win64 /
    sysv / cdecl from pointer width + OS), the call stack, and per-register pointer
    CLASSIFICATION (which module/region each register points into, its perms, and a
    short byte preview of what it points at).
    WHEN-TO-USE: The first call after any breakpoint hit or step -- it replaces a
    flurry of dbg_regs / dbg_stacktrace / dbg_read / disasm calls with a single
    ground-truth picture of the machine state.
    RETURNS: A StopContextResult: {state, tid, ip, function, abi, disasm[],
    registers[], flags{raw,set}, stack_args[], stacktrace[], pointers[]}.
    PRO-TIP: pointers[] tells you at a glance which register holds a heap/stack/
    image pointer vs garbage; follow the previews to spot strings/structs without
    a second read. Requires a SUSPENDED session.
    """
    dbg = dbg_ensure_suspended()
    out: StopContextResult = {"state": "suspended"}

    tid = ida_dbg.get_current_thread()
    out["tid"] = tid

    ip = ida_dbg.get_ip_val()
    if ip is not None:
        out["ip"] = hex(ip)
        func = idaapi.get_func(ip)
        if func:
            out["function"] = ida_funcs_get_name(func.start_ea)
        else:
            out["function"] = None
        out["disasm"] = _disasm_window(ip, disasm_before, disasm_after)

    # ABI detection from pointer width + OS.
    psize = _ptr_size_live()
    conv = dbg_common.detect_abi(psize, _is_windows_target())
    out["abi"] = conv

    # Full register file for the current thread.
    thread_regs = _get_registers_for_thread(dbg, tid)
    out["registers"] = thread_regs["registers"]

    # Decoded flags (x86/x64 EFLAGS); best-effort.
    flags_val = _read_reg_live("EFL")
    if flags_val is None:
        flags_val = _read_reg_live("EFLAGS")
    if flags_val is None:
        flags_val = _read_reg_live("RFLAGS")
    if isinstance(flags_val, int):
        out["flags"] = _decode_eflags(flags_val)

    # Stack args via the detected ABI and the SEAM resolver.
    stack_args: list[StackArgInfo] = []
    for i in range(max(0, int(arg_count))):
        loc = dbg_common.int_arg_location(i, conv)
        if loc.get("error"):
            stack_args.append({"index": i, "location": loc["error"], "value": None})
            continue
        if loc.get("kind") == "reg":
            location = f"reg:{loc['reg']}"
        else:
            location = f"[sp+{hex(loc['disp'])}]"
        val = dbg_common.resolve_int_arg(
            i, conv,
            read_reg=_read_reg_live,
            read_stack_at_sp_disp=_read_stack_word_live,
        )
        stack_args.append({
            "index": i,
            "location": location,
            "value": hex(val) if isinstance(val, int) else None,
        })
    out["stack_args"] = stack_args

    # Stacktrace (reuse the existing collector logic).
    out["stacktrace"] = _collect_stacktrace()

    # Per-register pointer classification over the live region map.
    regions = dbg_common.enumerate_memory_regions()
    pointers: list[PointerInfo] = []
    gp_names = _processor_gp_registers()
    for reg in thread_regs["registers"]:
        rname = reg["name"]
        if rname.upper() not in gp_names:
            continue
        try:
            rval = int(reg["value"], 0)
        except (TypeError, ValueError):
            continue
        cls = dbg_common.classify_pointer(rval, regions)
        if cls.get("kind") == "unmapped":
            continue
        info: PointerInfo = {
            "reg": rname,
            "value": reg["value"],
            "kind": cls.get("kind"),
            "module": cls.get("module"),
            "perm": cls.get("perm"),
            "offset_in_region": cls.get("offset_in_region"),
        }
        if preview_bytes and preview_bytes > 0:
            info["preview"] = _byte_preview_live(rval, int(preview_bytes))
        pointers.append(info)
    out["pointers"] = pointers

    return out


def ida_funcs_get_name(ea: int) -> str | None:
    """Resolve a function name at `ea` (thin wrapper, tolerant of failure)."""
    try:
        import ida_funcs

        return ida_funcs.get_func_name(ea) or None
    except Exception:
        return None


def _collect_stacktrace() -> list["StackFrameInfo"]:
    """Shared stacktrace collector (mirrors dbg_stacktrace's body)."""
    callstack: list[StackFrameInfo] = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info: StackFrameInfo = {"addr": hex(frame.callea)}
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
# Memory Map / Pointer Classification
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Memory Map")
@tool
@idasync
def memory_map() -> MemoryMapResult:
    """Enumerate the live debuggee's mapped memory regions with perms + modules.

    WHAT: Walks the live process's memory info into one record per region:
    {start, end, size, perm ("rwx" with "-" for absent bits), module (owning
    module basename when named), kind ("image"/"stack"/"heap"/"mapped")}. Also
    derives the module base list (lowest mapped start per module).
    WHEN-TO-USE: To orient yourself in the target's address space -- find where a
    module loaded (ASLR base), confirm a pointer lands in an executable image vs
    the heap/stack, or pick a region to scan. Pairs with classify_pointer.
    RETURNS: {regions: [{start,end,size,perm,module,kind}], module_bases:
    [{module, base}], count}. Empty regions means no live session / no info.
    PRO-TIP: Module bases are the anchor for translating static IDB addresses to
    live addresses after relocation. Requires a live session for meaningful data.
    """
    regions = dbg_common.enumerate_memory_regions()
    out_regions: list[MemoryRegionInfo] = []
    module_bases: dict[str, int] = {}
    for r in regions:
        start = int(r["start"])
        end = int(r["end"])
        module = r.get("module")
        out_regions.append({
            "start": hex(start),
            "end": hex(end),
            "size": end - start,
            "perm": r.get("perm"),
            "module": module,
            "kind": r.get("kind"),
        })
        if module:
            if module not in module_bases or start < module_bases[module]:
                module_bases[module] = start
    bases = [{"module": m, "base": hex(b)} for m, b in sorted(module_bases.items(), key=lambda kv: kv[1])]
    return {"regions": out_regions, "module_bases": bases, "count": len(out_regions)}


@ext("dbg")
@safety("READ")
@title("Classify Pointer")
@tool
@idasync
def classify_pointer(
    addr: Annotated[str, "Address/pointer value to classify, hex (0x..) or decimal"],
    preview_bytes: Annotated[int, "Bytes of memory preview to read at addr (default 16; 0 to skip)"] = 16,
) -> PointerClassResult:
    """Classify a raw pointer against the live process's memory map.

    WHAT: Looks `addr` up in the enumerated live regions and reports where it
    lands: the containing region [start,end), the owning module, the region's
    permissions, the offset within the region, and a coarse kind
    ("image"/"stack"/"heap"/"mapped"/"unmapped"), plus an optional short byte
    preview of what it points at.
    WHEN-TO-USE: To turn a raw register/argument value into a human-meaningful
    location -- "is RAX a heap pointer, a code pointer, or garbage?" -- without a
    full memory_map scan.
    RETURNS: {addr, region, module, perm, offset_in_region, kind, preview}. For an
    unmapped address region/module/perm/offset are null and kind=="unmapped".
    PRO-TIP: Combine with dbg_read to dump the structure once you confirm the
    pointer is mapped+readable. Requires a live session for accurate mapping.
    """
    try:
        a = parse_address(addr)
    except Exception as exc:
        return {"addr": str(addr), "kind": "unmapped", "error": str(exc)}
    regions = dbg_common.enumerate_memory_regions()
    cls = dbg_common.classify_pointer(a, regions)
    result: PointerClassResult = {
        "addr": hex(a),
        "region": cls.get("region"),
        "module": cls.get("module"),
        "perm": cls.get("perm"),
        "offset_in_region": cls.get("offset_in_region"),
        "kind": cls.get("kind"),
    }
    if preview_bytes and preview_bytes > 0 and cls.get("kind") != "unmapped":
        result["preview"] = _byte_preview_live(a, int(preview_bytes))
    return result


# ============================================================================
# Attach / Detach
# ============================================================================


@ext("dbg")
@safety("EXECUTE")
@title("Attach To Process")
@tool
@idasync
@tool_timeout(60.0)
def dbg_attach(
    pid: Annotated[int, "OS process id to attach the configured debugger to"],
    wait_ms: Annotated[
        int, "Bounded milliseconds to wait for the attach to settle (default 10000)"
    ] = _DEFAULT_BLOCK_WAIT_MS,
) -> DebugControlResult:
    """Attach IDA's debugger to an already-running process by pid.

    WHAT: Attaches the currently selected debugger backend to the live process
    `pid` and waits (bounded) for the session to come up suspended. Does NOT
    launch a new process.
    WHEN-TO-USE: When the target is already running (started outside IDA) and you
    want to inspect it live without relaunching -- the dynamic-analysis entry point
    for an existing process.
    RETURNS: A DebugControlResult with started=True and the settled state
    (typically suspended + ip) on success.
    PITFALL: Requires a debugger backend already selected (Debugger -> Select
    debugger) and sufficient privileges to attach. If attach is rejected, stop and
    ask the user to select a debugger / elevate rather than retrying in a loop.
    """
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError(
            "No debugger backend selected. Ask the user to choose one "
            "(Debugger -> Select debugger) before attaching."
        )
    rc = ida_dbg.attach_process(int(pid), -1)
    # attach_process returns 1 on success, 0 cancelled, -1 error on most builds.
    if rc == -1:
        raise IDAError(f"Failed to attach to pid {pid}")
    wait = _wait_for_settle(int(wait_ms) if wait_ms else 1)
    result = _block_result_from_wait(wait)
    result["started"] = True
    return result


@ext("dbg")
@safety("EXECUTE")
@title("Detach From Process")
@tool
@idasync
def dbg_detach() -> DebugControlResult:
    """Stop debugging WITHOUT killing the target (leave it running).

    WHAT: Detaches the debugger from the live process and ends the debug session,
    but LEAVES THE TARGET PROCESS RUNNING. This is the non-destructive counterpart
    to dbg_exit (which terminates the target).
    WHEN-TO-USE: When you attached to (or want to release) a live process you must
    not kill -- e.g. a long-running service or a game client the user is still
    using -- and just want IDA to let go.
    RETURNS: {exited: True, state: "not_running"} once detached (from IDA's
    perspective the session ended; the OS process keeps running).
    PITFALL: Unlike dbg_exit this does NOT stop the target -- if you actually want
    it dead, call dbg_exit. Requires an active session.
    """
    dbg_ensure_active()
    if ida_dbg.detach_process():
        return {"exited": True, "state": "not_running"}
    raise IDAError("Failed to detach from process")


# ============================================================================
# Threads
# ============================================================================


@ext("dbg")
@safety("READ")
@title("List Threads")
@tool
@idasync
def dbg_threads() -> ThreadListResult:
    """List every thread in the suspended debuggee with its current ip.

    WHAT: Enumerates all debugger threads, marking the currently selected one and
    reporting each thread's instruction pointer (best-effort) and name when known.
    WHEN-TO-USE: At a stop in a multi-threaded target to see which threads exist
    and pick one to switch to (dbg_select_thread) before reading its registers/
    stack.
    RETURNS: {threads: [{tid, current, ip, name}], current}.
    PRO-TIP: Use the tid values with dbg_select_thread, dbg_regs_remote, or
    dbg_stacktrace to inspect a specific thread. Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    current = ida_dbg.get_current_thread()
    threads: list[ThreadInfo] = []
    for i in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(i)
        info: ThreadInfo = {"tid": tid, "current": tid == current}
        try:
            ip = ida_dbg.get_ip_val() if tid == current else None
            # For non-current threads, read PC/RIP/EIP from its reg set.
            if ip is None:
                regs = _get_registers_specific_for_thread(dbg_ensure_active(), tid, ["RIP", "EIP", "PC"])
                for r in regs["registers"]:
                    try:
                        ip = int(r["value"], 0)
                        break
                    except (TypeError, ValueError):
                        continue
            info["ip"] = hex(ip) if isinstance(ip, int) else None
        except Exception:
            info["ip"] = None
        try:
            name = ida_dbg.get_thread_name(tid)
            info["name"] = name or None
        except Exception:
            info["name"] = None
        threads.append(info)
    return {"threads": threads, "current": current}


@ext("dbg")
@safety("EXECUTE")
@title("Select Thread")
@tool
@idasync
def dbg_select_thread(
    tid: Annotated[int, "Thread id to make the current debugger thread"],
) -> ThreadSelectResult:
    """Switch the debugger's current thread to `tid`.

    WHAT: Makes `tid` the active thread so subsequent register/stack reads
    (dbg_regs, dbg_gpregs, dbg_stacktrace, stop_context) target it. Does not
    resume the process.
    WHEN-TO-USE: After dbg_threads, to focus on the thread that hit your event of
    interest (or a worker thread) before inspecting its state.
    RETURNS: {tid, ok: True, ip} on success or {tid, error} if the thread id is
    unknown.
    PITFALL: The thread must exist in the current session (source tids from
    dbg_threads). Requires a SUSPENDED session.
    """
    dbg_ensure_suspended()
    available = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    if tid not in available:
        return {"tid": tid, "error": f"thread {tid} not found"}
    try:
        if ida_dbg.select_thread(int(tid)):
            ip = ida_dbg.get_ip_val()
            return {"tid": tid, "ok": True, "ip": hex(ip) if ip is not None else None}
        return {"tid": tid, "error": "select_thread failed"}
    except Exception as exc:
        return {"tid": tid, "error": str(exc)}


# ============================================================================
# Exception Configuration
# ============================================================================


@ext("dbg")
@safety("EXECUTE")
@title("Configure Exception Handling")
@tool
@idasync
def exception_config(
    code: Annotated[int, "Exception code to configure (e.g. 0xC0000005 for an access violation)"],
    catch: Annotated[
        bool,
        "True: have the debugger STOP on this exception (first-chance catch). "
        "False: pass it through to the target's own handler without stopping.",
    ] = True,
    stop: Annotated[
        bool,
        "Whether to halt the debuggee when the exception fires (implies catch). "
        "Defaults to the value of `catch`.",
    ] = True,
) -> ExceptionConfigResult:
    """Set first-chance catch/pass policy for a debugger exception code.

    WHAT: Adjusts how IDA's debugger reacts to exception `code` -- whether it is
    CAUGHT (the debugger is notified / can stop) or silently PASSED to the
    target's handler. Updates the debugger's exception table for the running
    backend.
    WHEN-TO-USE: To stop precisely when a specific fault occurs (e.g. break on the
    access violation that an anti-debug or a crashing decode triggers), or to
    suppress noisy first-chance exceptions a target throws as control flow so they
    don't keep halting you.
    RETURNS: {code, name, catch, stop, ok} reflecting the applied policy, or
    {code, error} if the code is unknown to the debugger's exception table.
    PITFALL: Only codes present in the debugger's exception list can be tuned;
    an unrecognised code returns an error. Requires a debugger backend selected
    (usually a live session).
    """
    dbg_ensure_active()
    try:
        info = ida_dbg.get_exception_info(int(code))
    except Exception:
        info = None
    if not info:
        return {"code": int(code), "error": f"exception code {hex(int(code))} not in the debugger's exception table"}

    name = getattr(info, "name", None)
    flags = int(getattr(info, "flags", 0))
    # ida_idd exception flag bits: EXC_BREAK (stop), EXC_HANDLE (pass to app).
    exc_break = getattr(ida_idd, "EXC_BREAK", 0x001)
    exc_handle = getattr(ida_idd, "EXC_HANDLE", 0x002)

    want_stop = bool(stop) and bool(catch)
    if catch:
        # Catch: do NOT auto-hand to the app; optionally stop.
        flags &= ~exc_handle
        if want_stop:
            flags |= exc_break
        else:
            flags &= ~exc_break
    else:
        # Pass through: hand to the app, don't stop.
        flags |= exc_handle
        flags &= ~exc_break

    try:
        info.flags = flags
        ok = bool(ida_dbg.set_exception_info([info], 1)) if hasattr(ida_dbg, "set_exception_info") else False
    except Exception as exc:
        return {"code": int(code), "name": name, "error": str(exc)}

    return {
        "code": int(code),
        "name": name,
        "catch": bool(catch),
        "stop": want_stop,
        "ok": ok,
    }


# ============================================================================
# Counting / Nth-Hit Breakpoints
# ============================================================================


@ext("dbg")
@safety("EXECUTE")
@title("Set Nth-Hit / Counting Breakpoint")
@tool
@idasync
def dbg_set_bp_hit_count(
    addr: Annotated[str, "Breakpoint address (hex or decimal); must already exist (dbg_add_bp first)"],
    nth: Annotated[
        int,
        "Stop only on the Nth hit (1-based). The breakpoint maintains a hidden "
        "hit counter and stops exactly when it reaches `nth`, then keeps counting "
        "(so the (2N)th, (3N)th... also stop when reset_each is True).",
    ],
    reset_each: Annotated[
        bool,
        "When True the counter wraps every `nth` hits (stop on N, 2N, 3N...). "
        "When False it stops once at the Nth hit and never again.",
    ] = False,
    language: Annotated[
        str, "Condition language for the counter expression: 'idc' (default) or 'python'"
    ] = "idc",
) -> BreakpointResult:
    """Make an existing breakpoint stop only on its Nth hit (or every Nth hit).

    WHAT: Installs a self-counting CONDITION on the breakpoint at `addr` so it
    only halts the debuggee on the Nth time it is reached (1-based). The counter
    lives in a per-breakpoint global the condition increments on each hit; the
    condition returns true exactly at the Nth hit (and, with reset_each, at every
    multiple of N). Implemented purely as a breakpoint condition -- no extra
    breakpoints.
    WHEN-TO-USE: To skip the boring early iterations of a hot loop / handler and
    land on the specific invocation you care about (e.g. "stop the 500th time this
    allocator is called") without manually continuing hundreds of times.
    RETURNS: {addr, ok, condition, language} on success or {addr, error}. The
    breakpoint must already exist.
    PITFALL: The counter is keyed to this breakpoint's address; deleting and
    re-adding the breakpoint resets it. Requires the breakpoint to exist
    (dbg_add_bp first). The hidden counter persists in the IDA process across
    runs until you clear/replace the condition.
    """
    try:
        ea = parse_address(addr)
    except Exception as exc:
        return {"addr": addr, "error": str(exc)}

    bpt = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(ea, bpt):
        return {"addr": addr, "error": "Breakpoint not found (add it with dbg_add_bp first)"}

    try:
        n = int(nth)
    except (TypeError, ValueError):
        return {"addr": addr, "error": f"nth must be an int, got {nth!r}"}
    if n < 1:
        return {"addr": addr, "error": "nth must be >= 1"}

    lang = _normalize_breakpoint_language(language) or "IDC"
    counter_name = f"_ida_mcp_hit_{ea:x}"

    # Build a self-counting condition. We seed a counter in the chosen language's
    # global namespace, bump it each hit, and stop at the Nth (or every Nth).
    if lang == "Python":
        # Python condition: maintain a dict in __main__.
        if reset_each:
            cond = (
                f"(lambda g: (g.__setitem__('{counter_name}', g.get('{counter_name}', 0) + 1), "
                f"g['{counter_name}'] % {n} == 0)[1])(__import__('__main__').__dict__)"
            )
        else:
            cond = (
                f"(lambda g: (g.__setitem__('{counter_name}', g.get('{counter_name}', 0) + 1), "
                f"g['{counter_name}'] == {n})[1])(__import__('__main__').__dict__)"
            )
        low_level = 0
    else:
        lang = "IDC"
        # IDC condition using a global variable. extern declares/refs a global.
        if reset_each:
            cond = (
                f"extern {counter_name}; {counter_name} = {counter_name} + 1, "
                f"({counter_name} % {n}) == 0"
            )
        else:
            cond = (
                f"extern {counter_name}; {counter_name} = {counter_name} + 1, "
                f"{counter_name} == {n}"
            )
        low_level = 0

    try:
        current_language = _get_breakpoint_language(bpt)
        if current_language != lang:
            _set_breakpoint_language(bpt, lang)
            if not ida_dbg.update_bpt(bpt):
                return {"addr": addr, "error": f"Failed to set condition language {lang}"}
        if not idc.set_bpt_cond(ea, cond, low_level):
            return {"addr": addr, "error": "Failed to set hit-count condition"}
    except Exception as exc:
        return {"addr": addr, "error": str(exc)}

    return {"addr": addr, "ok": True, "condition": cond, "language": lang}
