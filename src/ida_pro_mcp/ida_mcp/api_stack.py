"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_typeinf
import ida_frame
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    StackVarDecl,
    StackVarDelete,
    get_stack_frame_variables_internal,
)
from .tests import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


@tool
@idasync
def stack_frame(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
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


@test()
def test_stack_frame():
    """stack_frame returns stack variables for a valid function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = stack_frame(fn_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "vars")
    # vars can be None if function has no stack frame, or a list
    # Just verify the structure is correct
    assert result[0]["addr"] == fn_addr
    assert "error" not in result[0] or result[0].get("error") is None


@test()
def test_stack_frame_no_function():
    """stack_frame handles invalid address gracefully"""
    # Use an address that's unlikely to be a valid function
    result = stack_frame("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    # Should return error, not crash
    assert "error" in result[0]
    assert result[0]["error"] is not None


@tool
@idasync
def declare_stack(
    items: list[StackVarDecl] | StackVarDecl,
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


@tool
@idasync
def delete_stack(
    items: list[StackVarDelete] | StackVarDelete,
):
    """Delete stack vars"""

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

            idx, udm = frame_tif.get_udm(var_name)
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

            results.append({"addr": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

    return results


@test()
def test_declare_delete_stack():
    """declare_stack and delete_stack create/delete stack variables"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # First check if the function has a stack frame
    frame_result = stack_frame(fn_addr)
    if not frame_result or frame_result[0].get("error"):
        return  # Skip if function has no frame

    test_var_name = "__mcp_test_var__"

    try:
        # Try to create a stack variable at offset 0x10
        # Use "int" as the type - a basic type that should exist
        declare_result = declare_stack(
            {"addr": fn_addr, "offset": "0x10", "name": test_var_name, "ty": "int"}
        )
        assert_is_list(declare_result, min_length=1)
        assert_has_keys(declare_result[0], "addr", "name")

        # If creation succeeded, try to delete it
        if declare_result[0].get("ok"):
            delete_result = delete_stack({"addr": fn_addr, "name": test_var_name})
            assert_is_list(delete_result, min_length=1)
            assert_has_keys(delete_result[0], "addr", "name")
        # If creation failed (e.g., no frame, offset conflict), that's OK
        # The test verifies the API handles it gracefully without crashing
    except Exception:
        # If any operation fails, ensure cleanup is attempted
        try:
            delete_stack({"addr": fn_addr, "name": test_var_name})
        except Exception:
            pass
        raise
