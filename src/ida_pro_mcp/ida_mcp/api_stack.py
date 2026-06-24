"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated, NotRequired, TypedDict

import ida_frame
import ida_typeinf
import idaapi

from .compat import tinfo_get_udm
from .rpc import tool, safety, title
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackVarDecl,
    StackVarDelete,
    StackFrameVariable,
    get_stack_frame_variables_internal,
)


class StackFrameResult(TypedDict):
    addr: str
    vars: list[StackFrameVariable] | None
    error: NotRequired[str]


class StackMutationResult(TypedDict):
    addr: str
    name: str
    error: NotRequired[str]


# ============================================================================
# Stack Frame Operations
# ============================================================================


@safety("READ")
@title("Read Stack Frame Variables")
@tool
@idasync
def stack_frame(
    addrs: Annotated[
        list[str] | str,
        "One function address, or a list of them (hex/decimal/symbol). Any address inside a function resolves to its frame.",
    ]
) -> list[StackFrameResult]:
    """WHAT: Read the stack-frame layout (local variables and saved arguments) of one or more functions.

    WHEN-TO-USE: To inspect a function's locals before renaming/retyping them, to confirm an offset before calling `declare_stack`/`delete_stack`, or to understand how a routine lays out its stack while reverse-engineering it. Accepts a batch of addresses in a single call to amortize round-trips.

    RETURNS: A list parallel to the input, one StackFrameResult per address with `addr` (the address you passed) and `vars` (a list of {name, offset, size, type}); on a per-address failure `vars` is None and `error` carries the reason.

    PITFALL: Each result is reported independently — a bad address yields an `error` entry rather than failing the whole batch, so always check each element. Requires IDA 9+; on older versions frames come back empty. Offsets are frame offsets (the same ones `declare_stack`/`delete_stack` expect), not file addresses."""
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


@safety("DESTRUCTIVE")
@title("Declare Stack Variables")
@tool
@idasync
def declare_stack(
    items: Annotated[
        list[StackVarDecl] | StackVarDecl,
        "One declaration or a list of them. Each is {addr: function address, offset: stack offset, name: variable name, ty: type name}.",
    ],
) -> list[StackMutationResult]:
    """WHAT: Define (create/rename/retype) named, typed stack variables in function frames from a batch of typed declarations.

    WHEN-TO-USE: After recovering a local's purpose and type, to give it a meaningful name and C type at its frame offset so the decompiler renders it cleanly. Use `stack_frame` first to find the exact offset, then declare it here.

    RETURNS: A list parallel to the input, one StackMutationResult per item with `addr` and `name`; a failed item additionally carries `error` (e.g. no function at `addr`, unresolved type, or define failure).

    PITFALL: This MUTATES the IDB — defining a variable at an occupied offset overwrites the existing member there, so confirm the offset with `stack_frame` first. `ty` must resolve via the type system (a known builtin or an existing local type); an unknown type name fails that item without aborting the rest of the batch."""
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

            results.append({"addr": fn_addr, "name": var_name})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@safety("DESTRUCTIVE")
@title("Delete Stack Variables")
@tool
@idasync
def delete_stack(
    items: Annotated[
        list[StackVarDelete] | StackVarDelete,
        "One deletion or a list of them. Each is {addr: function address, name: stack variable name to remove}.",
    ],
) -> list[StackMutationResult]:
    """WHAT: Delete user-defined stack variables from function frames by name, freeing the frame bytes they occupied.

    WHEN-TO-USE: To undo a bad/obsolete stack declaration or clean up a frame before re-laying it out. Look up the exact variable name with `stack_frame` first.

    RETURNS: A list parallel to the input, one StackMutationResult per item with `addr` and `name`; a failed item additionally carries `error` (no function found, name not present in the frame, the member is a special/argument member, or the delete failed).

    PITFALL: This MUTATES the IDB and is irreversible via this tool. It deliberately refuses to delete special frame members (saved registers / return address) and function arguments (`is_funcarg_off`) — those return an `error` instead of being removed. Match by name, not offset; an unknown name fails only that item, leaving the rest of the batch intact."""

    items = normalize_dict_list(items)
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

            idx, udm = tinfo_get_udm(frame_tif, var_name)
            if not udm:
                results.append(
                    {
                        "addr": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} not found",
                    }
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

            results.append({"addr": fn_addr, "name": var_name})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results
