"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_typeinf
import ida_frame
import idaapi

from .rpc import jsonrpc
from .sync import idaread, idawrite, IDAError, ida_major
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackFrameVariable,
    get_stack_frame_variables_internal,
    JsonSchema,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


@jsonrpc
@idaread
def stack_frame(
    addrs: Annotated[
        list[str] | str,
        "Address(es)",
        JsonSchema({
            "oneOf": [
                {
                    "type": "array",
                    "items": {"type": "string", "description": "Function address"},
                    "description": "Array of function addresses"
                },
                {
                    "type": "string",
                    "description": "Single address or comma-separated addresses"
                }
            ]
        })
    ]
) -> list[dict]:
    """Get stack vars"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            results.append({"addr": addr, "vars": vars})
        except Exception as e:
            results.append({"addr": addr, "vars": None, "error": str(e)})

    return results


@jsonrpc
@idawrite
def declare_stack(
    items: Annotated[
        list[dict] | dict,
        "[{addr, offset, name, ty}, ...] or {addr, offset, name, ty}",
        JsonSchema({
            "oneOf": [
                {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "addr": {"type": "string", "description": "Function address"},
                            "offset": {"type": "string", "description": "Stack offset"},
                            "name": {"type": "string", "description": "Variable name"},
                            "ty": {"type": "string", "description": "Type name"}
                        },
                        "required": ["addr", "offset", "name", "ty"]
                    },
                    "description": "Array of stack variable declarations"
                },
                {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address"},
                        "offset": {"type": "string", "description": "Stack offset"},
                        "name": {"type": "string", "description": "Variable name"},
                        "ty": {"type": "string", "description": "Type name"}
                    },
                    "required": ["addr", "offset", "name", "ty"],
                    "description": "Single stack variable declaration"
                }
            ]
        })
    ],
):
    """Create stack vars"""
    items = normalize_dict_list(items)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        offset = item.get("offset", "")
        var_name = item.get("name", "")
        type_name = item.get("ty", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            ea = parse_address(offset)

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            tif = get_type_by_name(type_name)
            if not ida_frame.define_stkvar(func, var_name, ea, tif):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to define"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@jsonrpc
@idawrite
def delete_stack(
    items: Annotated[
        list[dict] | dict | str,
        "[{addr, name}, ...] or {addr, name} or 'addr:name'",
        JsonSchema({
            "oneOf": [
                {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "addr": {"type": "string", "description": "Function address"},
                            "name": {"type": "string", "description": "Variable name"}
                        },
                        "required": ["addr", "name"]
                    },
                    "description": "Array of stack variable deletions"
                },
                {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string", "description": "Function address"},
                        "name": {"type": "string", "description": "Variable name"}
                    },
                    "required": ["addr", "name"],
                    "description": "Single stack variable deletion"
                },
                {
                    "type": "string",
                    "description": "addr:varname format or comma-separated list"
                }
            ]
        })
    ],
):
    """Delete stack vars"""

    def parse_addr_name(s: str) -> dict:
        # Support "addr:varname" format
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "name": parts[1].strip()}
        # Just varname without address (invalid)
        return {"addr": "", "name": s.strip()}

    items = normalize_dict_list(items, parse_addr_name)
    results = []
    for item in items:
        fn_addr = item.get("addr", "")
        var_name = item.get("name", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": f"{var_name} not found"}
                )
                continue

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not ida_frame.delete_frame_members(func, offset, offset + size):
                results.append(
                    {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results
