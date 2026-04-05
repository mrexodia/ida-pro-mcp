"""Operand representation operations for IDA Pro MCP.

Provides tools for changing how operands are displayed:
hex, decimal, octal, binary, char, enum, struct offset, offset references.
"""

from typing import Annotated, TypedDict

import ida_bytes
import ida_offset
import ida_typeinf
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# TypedDict Definitions
# ============================================================================


class OpReprOp(TypedDict, total=False):
    addr: Annotated[str, "Instruction address"]
    n: Annotated[int, "Operand index (0-based)"]
    repr: Annotated[
        str, "Representation: hex|dec|oct|bin|char|enum|stkvar|offset|default"
    ]
    enum_name: Annotated[str, "Enum name (when repr=enum)"]
    offset_base: Annotated[str, "Base address for offset (when repr=offset)"]


# ============================================================================
# Operand Representation Tools
# ============================================================================


@tool
@idasync
def set_op_repr(items: list[OpReprOp] | OpReprOp) -> list[dict]:
    """Change operand representation (display format) at instruction(s).

    Supported representations:
    - hex: Display as hexadecimal
    - dec: Display as decimal (signed)
    - oct: Display as octal
    - bin: Display as binary
    - char: Display as character
    - enum: Display as enum member (requires enum_name)
    - stkvar: Display as stack variable
    - offset: Display as offset/pointer (optionally with offset_base)
    - default: Reset to default representation
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            n = item.get("n", 0)
            repr_type = item.get("repr", "hex")

            ok = False
            if repr_type == "hex":
                ok = idc.op_hex(ea, n)
            elif repr_type == "dec":
                ok = idc.op_dec(ea, n)
            elif repr_type == "oct":
                ok = idc.op_oct(ea, n)
            elif repr_type == "bin":
                ok = idc.op_bin(ea, n)
            elif repr_type == "char":
                ok = idc.op_chr(ea, n)
            elif repr_type == "stkvar":
                ok = idc.op_stkvar(ea, n)
            elif repr_type == "enum":
                enum_name = item.get("enum_name", "")
                if not enum_name:
                    results.append({"addr": hex(ea), "error": "enum_name required"})
                    continue
                eid = idc.get_enum(enum_name)
                if eid == idaapi.BADADDR:
                    results.append(
                        {"addr": hex(ea), "error": f"Enum not found: {enum_name}"}
                    )
                    continue
                ok = idc.op_enum(ea, n, eid, 0)
            elif repr_type == "offset":
                base_str = item.get("offset_base", "")
                if base_str:
                    base = parse_address(base_str)
                    refinfo = ida_offset.refinfo_t()
                    refinfo.init(ida_offset.REF_OFF64, base)
                    ok = ida_offset.op_offset_ex(ea, n, refinfo)
                else:
                    ok = idc.op_plain_offset(ea, n, 0)
            elif repr_type == "default":
                idc.clr_op_type(ea, n)
                ok = True
            else:
                results.append({"addr": hex(ea), "error": f"Unknown repr: {repr_type}"})
                continue

            results.append({"addr": hex(ea), "n": n, "repr": repr_type, "ok": ok})
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def get_op_type(
    addrs: Annotated[str, "Addresses, comma-separated"],
    n: Annotated[int, "Operand index (0-based)"] = 0,
) -> list[dict]:
    """Get operand type and value at address(es)."""
    items = normalize_list_input(addrs)
    results = []

    type_names = {
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
            op_t = idc.get_operand_type(ea, n)
            op_val = idc.get_operand_value(ea, n)

            result = {
                "addr": hex(ea),
                "n": n,
                "type": op_t,
                "type_name": type_names.get(op_t, f"custom({op_t})"),
                "value": hex(op_val) if op_val is not None else None,
            }
            results.append(result)
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def set_manual_operand(
    addr: Annotated[str, "Instruction address"],
    n: Annotated[int, "Operand index (0-based)"],
    text: Annotated[str, "Manual operand text, or empty to clear"],
) -> dict:
    """Set or clear a manual operand override at an address."""
    ea = parse_address(addr)
    if text:
        ok = idc.set_forced_operand(ea, n, text)
    else:
        ok = idc.set_forced_operand(ea, n, "")
    return {"addr": hex(ea), "n": n, "ok": ok}
