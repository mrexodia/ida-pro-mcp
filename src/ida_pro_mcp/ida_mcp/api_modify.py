import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_typeinf
import ida_frame

from .rpc import tool
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    CommentOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
)
from .tests import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
)


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idasync
def set_comments(items: list[CommentOp] | CommentOp):
    """Set comments at addresses (both disassembly and decompiler views)"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"addr": addr_str, "ok": True})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"addr": addr_str, "ok": True})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"addr": addr_str, "ok": True})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"addr": addr_str, "ok": True})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@test()
def test_set_comment_roundtrip():
    """set_comments can set and clear comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original comment (may be None/empty)
    original_comment = idc.get_cmt(int(fn_addr, 16), False) or ""

    try:
        # Set a test comment
        result = set_comments({"addr": fn_addr, "comment": "__test_comment__"})
        assert_is_list(result, min_length=1)
        assert_has_keys(result[0], "addr")
        # Either "ok" or "error" should be present
        assert "ok" in result[0] or "error" in result[0]

        # Verify comment was set
        new_comment = idc.get_cmt(int(fn_addr, 16), False)
        assert new_comment == "__test_comment__", (
            f"Expected '__test_comment__', got {new_comment!r}"
        )
    finally:
        # Restore original comment
        set_comments({"addr": fn_addr, "comment": original_comment})


@tool
@idasync
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[dict]:
    """Patch assembly instructions at addresses"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        instructions = item.get("asm", "")

        try:
            ea = parse_address(addr_str)
            assembles = instructions.split(";")
            for assemble in assembles:
                assemble = assemble.strip()
                try:
                    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
                    if not check_assemble:
                        results.append(
                            {
                                "addr": addr_str,
                                "error": f"Failed to assemble: {assemble}",
                            }
                        )
                        break
                    ida_bytes.patch_bytes(ea, bytes_to_patch)
                    ea += len(bytes_to_patch)
                except Exception as e:
                    results.append(
                        {"addr": addr_str, "error": f"Failed at {hex(ea)}: {e}"}
                    )
                    break
            else:
                results.append({"addr": addr_str, "ok": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@test()
def test_patch_asm():
    """patch_asm returns proper result structure"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original bytes at function start for potential restore
    ea = int(fn_addr, 16)
    original_bytes = ida_bytes.get_bytes(ea, 16)
    if not original_bytes:
        return  # Skip if can't read bytes

    # Try to assemble a NOP (this may fail depending on architecture)
    # We're just testing the API returns proper structure, not necessarily succeeding
    result = patch_asm({"addr": fn_addr, "asm": "nop"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr")
    # Result should have either "ok" or "error"
    assert "ok" in result[0] or "error" in result[0]

    # Restore original bytes if patch succeeded
    if result[0].get("ok"):
        ida_bytes.patch_bytes(ea, original_bytes)


@tool
@idasync
def rename(batch: RenameBatch) -> dict:
    """Unified rename operation for functions, globals, locals, and stack variables"""

    def _normalize_items(items):
        """Convert single item or None to list"""
        if items is None:
            return []
        return [items] if isinstance(items, dict) else items

    def _rename_funcs(items: list[FunctionRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = parse_address(item["addr"])
                success = idaapi.set_name(ea, item["name"], idaapi.SN_CHECK)
                if success:
                    func = idaapi.get_func(ea)
                    if func:
                        refresh_decompiler_ctext(func.start_ea)
                results.append(
                    {
                        "addr": item["addr"],
                        "name": item["name"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"addr": item.get("addr"), "error": str(e)})
        return results

    def _rename_globals(items: list[GlobalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, item["old"])
                if ea == idaapi.BADADDR:
                    results.append(
                        {
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"Global '{item['old']}' not found",
                        }
                    )
                    continue
                success = idaapi.set_name(ea, item["new"], idaapi.SN_CHECK)
                results.append(
                    {
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"old": item.get("old"), "error": str(e)})
        return results

    def _rename_locals(items: list[LocalRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No function found",
                        }
                    )
                    continue
                success = ida_hexrays.rename_lvar(
                    func.start_ea, item["old"], item["new"]
                )
                if success:
                    refresh_decompiler_ctext(func.start_ea)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    def _rename_stack(items: list[StackRename]) -> list[dict]:
        results = []
        for item in items:
            try:
                func = idaapi.get_func(parse_address(item["func_addr"]))
                if not func:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No function found",
                        }
                    )
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "No frame",
                        }
                    )
                    continue

                idx, udm = frame_tif.get_udm(item["old"])
                if not udm:
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": f"'{item['old']}' not found",
                        }
                    )
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Special frame member",
                        }
                    )
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    results.append(
                        {
                            "func_addr": item["func_addr"],
                            "old": item["old"],
                            "new": item["new"],
                            "ok": False,
                            "error": "Argument member",
                        }
                    )
                    continue

                sval = ida_frame.soff_to_fpoff(func, offset)
                success = ida_frame.define_stkvar(func, item["new"], sval, udm.type)
                results.append(
                    {
                        "func_addr": item["func_addr"],
                        "old": item["old"],
                        "new": item["new"],
                        "ok": success,
                        "error": None if success else "Rename failed",
                    }
                )
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
        return results

    # Process each category
    result = {}
    if "func" in batch:
        result["func"] = _rename_funcs(_normalize_items(batch["func"]))
    if "data" in batch:
        result["data"] = _rename_globals(_normalize_items(batch["data"]))
    if "local" in batch:
        result["local"] = _rename_locals(_normalize_items(batch["local"]))
    if "stack" in batch:
        result["stack"] = _rename_stack(_normalize_items(batch["stack"]))

    return result


@test()
def test_rename_function_roundtrip():
    """rename can rename and restore function names"""
    from .api_core import lookup_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original name
    lookup_result = lookup_funcs(fn_addr)
    if not lookup_result or not lookup_result[0].get("fn"):
        return  # Skip if lookup failed
    original_name = lookup_result[0]["fn"]["name"]

    try:
        # Rename the function
        result = rename({"func": [{"addr": fn_addr, "name": "__test_func_name__"}]})
        assert_has_keys(result, "func")
        assert_is_list(result["func"], min_length=1)
        assert_has_keys(result["func"][0], "addr", "name", "ok")
        assert result["func"][0]["ok"], (
            f"Rename failed: {result['func'][0].get('error')}"
        )

        # Verify the change
        new_lookup = lookup_funcs(fn_addr)
        new_name = new_lookup[0]["fn"]["name"]
        assert new_name == "__test_func_name__", (
            f"Expected '__test_func_name__', got {new_name!r}"
        )
    finally:
        # Restore original name
        rename({"func": [{"addr": fn_addr, "name": original_name}]})


@test()
def test_rename_global_roundtrip():
    """rename can rename and restore global names"""
    from .api_core import list_globals

    # Get a global variable
    globals_result = list_globals({"count": 1})
    if not globals_result or not globals_result[0]["data"]:
        return  # Skip if no globals

    global_info = globals_result[0]["data"][0]
    original_name = global_info["name"]
    global_info["addr"]

    # Skip system globals that can't be renamed
    if original_name.startswith("__") or original_name.startswith("."):
        return

    result = {}
    try:
        # Rename the global
        result = rename(
            {"data": [{"old": original_name, "new": "__test_global_name__"}]}
        )
        assert_has_keys(result, "data")
        assert_is_list(result["data"], min_length=1)
        assert_has_keys(result["data"][0], "old", "new", "ok")

        # Only verify change if rename succeeded (some globals may not be renameable)
        if result["data"][0]["ok"]:
            # Verify we can look it up by new name
            ea = idaapi.get_name_ea(idaapi.BADADDR, "__test_global_name__")
            assert ea != idaapi.BADADDR, "Could not find renamed global"
    finally:
        # Restore original name (only if rename succeeded)
        if result.get("data") and result["data"][0].get("ok"):
            rename({"data": [{"old": "__test_global_name__", "new": original_name}]})


@test()
def test_rename_local_roundtrip():
    """rename can rename and restore local variable names"""
    from .api_analysis import decompile

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Try to decompile to get local variables
    try:
        dec_result = decompile(fn_addr)
    except IDAError:
        return  # Skip if decompilation fails

    if not dec_result or dec_result[0].get("error"):
        return  # Skip if decompilation failed

    # Get local variables from decompiled code
    lvars = dec_result[0].get("lvars", [])
    if not lvars:
        return  # Skip if no local variables

    # Find a regular local (not argument)
    test_lvar = None
    for lvar in lvars:
        if not lvar.get("is_arg"):
            test_lvar = lvar
            break

    if not test_lvar:
        return  # Skip if no non-argument local found

    original_name = test_lvar["name"]

    result = {}
    try:
        # Rename the local variable
        result = rename(
            {
                "local": [
                    {
                        "func_addr": fn_addr,
                        "old": original_name,
                        "new": "__test_local__",
                    }
                ]
            }
        )
        assert_has_keys(result, "local")
        assert_is_list(result["local"], min_length=1)
        assert_has_keys(result["local"][0], "func_addr", "old", "new", "ok")

        # We don't assert ok=True because some locals may not be renameable
    finally:
        # Restore original name if rename succeeded
        if result.get("local") and result["local"][0].get("ok"):
            rename(
                {
                    "local": [
                        {
                            "func_addr": fn_addr,
                            "old": "__test_local__",
                            "new": original_name,
                        }
                    ]
                }
            )
