"""Processor module information for IDA Pro MCP.

Provides tools for querying processor details, registers, and instruction set.
"""

from typing import Annotated

import ida_idp
import ida_ida
import ida_ua
import idaapi
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, normalize_list_input


# ============================================================================
# Processor Tools
# ============================================================================


@tool
@idasync
def processor_info() -> dict:
    """Get detailed processor module information."""
    info = ida_idp.ph

    result = {
        "proc_name": idaapi.get_inf_structure().procname
        if hasattr(idaapi, "get_inf_structure")
        else "",
        "bitness": 64
        if ida_ida.inf_is_64bit()
        else (32 if ida_ida.inf_is_32bit_exactly() else 16),
        "is_be": ida_ida.inf_is_be(),
        "filetype": ida_ida.inf_get_filetype(),
        "ostype": ida_ida.inf_get_ostype(),
        "apptype": ida_ida.inf_get_apptype(),
        "cc_id": ida_ida.inf_get_cc_id(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
        "main": hex(ida_ida.inf_get_main()),
        "start_ea": hex(ida_ida.inf_get_start_ea()),
    }

    # Get compiler info
    cc_names = {
        1: "Visual C++",
        2: "Borland",
        3: "Watcom",
        6: "GNU C++",
        7: "Visual C++",
    }
    result["compiler"] = cc_names.get(
        ida_ida.inf_get_cc_id(), f"unknown({ida_ida.inf_get_cc_id()})"
    )

    # File type names
    ft_names = {
        0: "unknown",
        1: "EXE (old)",
        2: "COM (old)",
        3: "BIN",
        4: "DRV",
        5: "WinDRV",
        6: "SYS",
        11: "ELF",
        12: "W32RUN",
        13: "AOUT",
        14: "PE",
        15: "PEP",
        16: "NE",
        17: "LE",
        18: "LX",
        19: "MACHO",
    }
    result["filetype_name"] = ft_names.get(
        ida_ida.inf_get_filetype(), f"type_{ida_ida.inf_get_filetype()}"
    )

    return result


@tool
@idasync
def list_registers() -> list[dict]:
    """List all registers for the current processor."""
    regs = []
    idx = 0
    while True:
        try:
            name = ida_idp.get_reg_name(idx, 0)
            if not name:
                break
            regs.append(
                {
                    "index": idx,
                    "name": name,
                }
            )
            idx += 1
        except Exception:
            break

    return regs


@tool
@idasync
def decode_insn(
    addrs: Annotated[str, "Addresses, comma-separated"],
) -> list[dict]:
    """Decode instruction(s) at address(es), returning detailed operand info."""
    items = normalize_list_input(addrs)
    results = []

    op_type_names = {
        0: "void",
        1: "reg",
        2: "mem",
        3: "phrase",
        4: "displ",
        5: "imm",
        6: "far",
        7: "near",
    }

    for item in items:
        try:
            ea = parse_address(item)
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)

            if length == 0:
                results.append({"addr": hex(ea), "error": "Cannot decode"})
                continue

            ops = []
            for i in range(ida_ida.UA_MAXOP):
                op = insn.ops[i]
                if op.type == ida_ua.o_void:
                    break
                op_info = {
                    "n": i,
                    "type": op.type,
                    "type_name": op_type_names.get(op.type, f"custom({op.type})"),
                }
                if op.type == ida_ua.o_reg:
                    op_info["reg"] = (
                        ida_idp.get_reg_name(op.reg, op.dtype) or f"r{op.reg}"
                    )
                elif op.type == ida_ua.o_imm:
                    op_info["value"] = hex(op.value)
                elif op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
                    op_info["addr"] = hex(op.addr)
                elif op.type == ida_ua.o_displ:
                    op_info["reg"] = ida_idp.get_reg_name(op.reg, 0) or f"r{op.reg}"
                    op_info["offset"] = hex(op.addr)
                elif op.type == ida_ua.o_phrase:
                    op_info["reg"] = ida_idp.get_reg_name(op.reg, 0) or f"r{op.reg}"

                op_info["dtype"] = op.dtype
                ops.append(op_info)

            results.append(
                {
                    "addr": hex(ea),
                    "mnem": idc.print_insn_mnem(ea) or "",
                    "disasm": idc.GetDisasm(ea) or "",
                    "size": length,
                    "itype": insn.itype,
                    "operands": ops,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def insn_feature(
    addrs: Annotated[str, "Addresses, comma-separated"],
) -> list[dict]:
    """Get instruction feature flags (is_call, is_ret, is_jump, etc.)."""
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                results.append({"addr": hex(ea), "error": "Cannot decode"})
                continue

            feature = insn.get_canon_feature()
            results.append(
                {
                    "addr": hex(ea),
                    "mnem": idc.print_insn_mnem(ea) or "",
                    "is_call": bool(feature & ida_idp.CF_CALL),
                    "is_jump": bool(feature & ida_idp.CF_JUMP),
                    "is_stop": bool(feature & ida_idp.CF_STOP),
                    "uses_op1": bool(feature & ida_idp.CF_USE1),
                    "uses_op2": bool(feature & ida_idp.CF_USE2),
                    "changes_op1": bool(feature & ida_idp.CF_CHG1),
                    "changes_op2": bool(feature & ida_idp.CF_CHG2),
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results
