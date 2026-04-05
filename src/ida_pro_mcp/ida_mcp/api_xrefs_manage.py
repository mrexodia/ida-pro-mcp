"""Manual cross-reference management for IDA Pro MCP.

Provides tools for adding and deleting cross-references manually.
"""

from typing import Annotated, TypedDict

import ida_xref
import idaapi

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# TypedDict Definitions
# ============================================================================


class XrefAdd(TypedDict, total=False):
    frm: Annotated[str, "Source address"]
    to: Annotated[str, "Target address"]
    type: Annotated[
        str,
        "Xref type: call_far|call_near|jump_far|jump_near|flow|data_read|data_write|data_offset|data_unknown",
    ]


class XrefDel(TypedDict, total=False):
    frm: Annotated[str, "Source address"]
    to: Annotated[str, "Target address"]
    is_code: Annotated[bool, "True for code xrefs, False for data xrefs (default True)"]


# ============================================================================
# Xref type mapping
# ============================================================================

_CODE_XREF_TYPES = {
    "call_far": ida_xref.fl_CF,
    "call_near": ida_xref.fl_CN,
    "jump_far": ida_xref.fl_JF,
    "jump_near": ida_xref.fl_JN,
    "flow": ida_xref.fl_F,
}

_DATA_XREF_TYPES = {
    "data_read": ida_xref.dr_R,
    "data_write": ida_xref.dr_W,
    "data_offset": ida_xref.dr_O,
    "data_unknown": ida_xref.dr_I,
}


# ============================================================================
# Xref Management Tools
# ============================================================================


@unsafe
@tool
@idasync
def add_xref(items: list[XrefAdd] | XrefAdd) -> list[dict]:
    """Add manual cross-reference(s).

    Code xref types: call_far, call_near, jump_far, jump_near, flow.
    Data xref types: data_read, data_write, data_offset, data_unknown.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            frm_ea = parse_address(item.get("frm", "0"))
            to_ea = parse_address(item.get("to", "0"))
            xtype = item.get("type", "call_near")

            if xtype in _CODE_XREF_TYPES:
                ok = ida_xref.add_cref(frm_ea, to_ea, _CODE_XREF_TYPES[xtype])
            elif xtype in _DATA_XREF_TYPES:
                ok = ida_xref.add_dref(frm_ea, to_ea, _DATA_XREF_TYPES[xtype])
            else:
                results.append(
                    {
                        "frm": hex(frm_ea),
                        "to": hex(to_ea),
                        "error": f"Unknown xref type: {xtype}",
                    }
                )
                continue

            results.append(
                {"frm": hex(frm_ea), "to": hex(to_ea), "type": xtype, "ok": ok}
            )
        except Exception as e:
            results.append(
                {"frm": item.get("frm", ""), "to": item.get("to", ""), "error": str(e)}
            )
    return results


@unsafe
@tool
@idasync
def del_xref(items: list[XrefDel] | XrefDel) -> list[dict]:
    """Delete cross-reference(s)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            frm_ea = parse_address(item.get("frm", "0"))
            to_ea = parse_address(item.get("to", "0"))
            is_code = item.get("is_code", True)

            if is_code:
                ida_xref.del_cref(frm_ea, to_ea, False)
            else:
                ida_xref.del_dref(frm_ea, to_ea)

            results.append({"frm": hex(frm_ea), "to": hex(to_ea), "ok": True})
        except Exception as e:
            results.append(
                {"frm": item.get("frm", ""), "to": item.get("to", ""), "error": str(e)}
            )
    return results
