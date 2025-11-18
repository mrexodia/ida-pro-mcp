"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

import os
from typing import Annotated

import ida_dbg
import ida_entry
import ida_idd
import ida_idaapi
import ida_name
import idaapi

from .rpc import tool, unsafe
from .sync import idaread, IDAError
from .utils import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


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


def dbg_ensure_running() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running")
    if ida_dbg.get_ip_val() is None:
        raise IDAError("Debugger not running")
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


def list_breakpoints():
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bpt.flags & ida_dbg.BPT_ENABLED,
                    condition=str(bpt.condition) if bpt.condition else None,
                )
            )
    return breakpoints


# ============================================================================
# Debugger Control Operations
# ============================================================================


@tool
@idaread
@unsafe
def dbg_start():
    """Start debugger"""
    if len(list_breakpoints()) == 0:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            addr = ida_entry.get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)

    if idaapi.start_process("", "", "") == 1:
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to start debugger")


@tool
@idaread
@unsafe
def dbg_exit():
    """Exit debugger"""
    dbg_ensure_running()
    if idaapi.exit_process():
        return
    raise IDAError("Failed to exit debugger")


@tool
@idaread
@unsafe
def dbg_continue() -> str:
    """Continue debugger"""
    dbg_ensure_running()
    if idaapi.continue_process():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to continue debugger")


@tool
@idaread
@unsafe
def dbg_run_to(
    addr: Annotated[str, "Address"],
):
    """Run to address"""
    dbg_ensure_running()
    ea = parse_address(addr)
    if idaapi.run_to(ea):
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError(f"Failed to run to address {hex(ea)}")


@tool
@idaread
@unsafe
def dbg_step_into():
    """Step into"""
    dbg_ensure_running()
    if idaapi.step_into():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step into")


@tool
@idaread
@unsafe
def dbg_step_over():
    """Step over"""
    dbg_ensure_running()
    if idaapi.step_over():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step over")


# ============================================================================
# Breakpoint Operations
# ============================================================================


@tool
@idaread
@unsafe
def dbg_list_bps():
    """List breakpoints"""
    return list_breakpoints()


@tool
@idaread
@unsafe
def dbg_add_bp(
    addrs: Annotated[list[str] | str, "Address(es) to add breakpoints at"],
) -> list[dict]:
    """Add breakpoints"""
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


@tool
@idaread
@unsafe
def dbg_delete_bp(
    addrs: Annotated[list[str] | str, "Address(es) to delete breakpoints from"],
) -> list[dict]:
    """Delete breakpoints"""
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


@tool
@idaread
@unsafe
def dbg_enable_bp(items: list[BreakpointOp] | BreakpointOp) -> list[dict]:
    """Enable/disable breakpoints"""

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


# ============================================================================
# Register Operations
# ============================================================================


@tool
@idaread
@unsafe
def dbg_regs() -> list[ThreadRegisters]:
    """Get all registers"""
    result: list[ThreadRegisters] = []
    dbg = dbg_ensure_running()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        result.append(_get_registers_for_thread(dbg, tid))
    return result


@tool
@idaread
@unsafe
def dbg_regs_thread(
    tids: Annotated[list[int] | int, "Thread ID(s) to get registers for"],
) -> list[dict]:
    """Get thread registers"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
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


@tool
@idaread
@unsafe
def dbg_regs_cur() -> ThreadRegisters:
    """Get current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_for_thread(dbg, tid)


@tool
@idaread
@unsafe
def dbg_gpregs_thread(
    tids: Annotated[list[int] | int, "Thread ID(s) to get GP registers for"],
) -> list[dict]:
    """Get GP registers for threads"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
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


@tool
@idaread
@unsafe
def dbg_current_gpregs() -> ThreadRegisters:
    """Get current thread GP registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_general_for_thread(dbg, tid)


@tool
@idaread
@unsafe
def dbg_regs_for_thread(
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific thread registers"""
    dbg = dbg_ensure_running()
    if thread_id not in [
        ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
    ]:
        raise IDAError(f"Thread with ID {thread_id} not found")
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, thread_id, names)


@tool
@idaread
@unsafe
def dbg_current_regs(
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, tid, names)


# ============================================================================
# Call Stack Operations
# ============================================================================


@tool
@idaread
@unsafe
def dbg_callstack() -> list[dict[str, str]]:
    """Get call stack"""
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


@tool
@idaread
@unsafe
def dbg_read_mem(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
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


@tool
@idaread
@unsafe
def dbg_write_mem(regions: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Write debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
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
