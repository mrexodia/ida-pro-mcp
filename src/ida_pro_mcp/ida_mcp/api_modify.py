from typing import Annotated

import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_nalt
import ida_typeinf
import ida_frame

from .rpc import jsonrpc
from .sync import idawrite, idaread, IDAError
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    decompile_checked,
    refresh_decompiler_ctext,
)


# ============================================================================
# Modification Operations
# ============================================================================


@jsonrpc
@idawrite
def set_cmt(
    items: Annotated[list[dict] | dict, "[{addr, comment}, ...] or {addr, comment}"],
):
    """Set comments"""

    def parse_addr_comment(s: str) -> dict:
        # Support "addr: comment" format
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "comment": parts[1].strip()}
        # Just address without comment (will clear comment)
        return {"addr": s.strip(), "comment": ""}

    items = normalize_dict_list(items, parse_addr_comment)

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


@jsonrpc
@idawrite
def patch_asm(
    items: Annotated[list[dict] | dict, "[{addr, asm}, ...] or {addr, asm}"],
) -> list[dict]:
    """Patch assembly"""

    def parse_addr_asm(s: str) -> dict:
        # Support "addr: instruction" format
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "asm": parts[1].strip()}
        # Just instruction without address (invalid, but let it fail gracefully)
        return {"addr": "", "asm": s.strip()}

    items = normalize_dict_list(items, parse_addr_asm)

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
                            {"addr": addr_str, "error": f"Failed to assemble: {assemble}"}
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


@jsonrpc
@idawrite
def rename_all(
    renamings: Annotated[
        list | dict,
        "Array defaults to function renames, or {ty: 'function'|'global'|'local'|'stack', qs: [...]} for batch",
    ],
) -> list[dict]:
    """Rename anything (batch-first API)

    Examples:
    - ["0x401000:main", "0x402000:init"] - Function renames (default)
    - {"ty": "function", "qs": ["0x401000:main", "0x402000:init"]}
    - {"ty": "global", "qs": ["old_var:new_var", "data:config"]}
    - {"ty": "local", "qs": ["0x401000:old:new", "0x402000:v1:v2"]}
    - {"ty": "stack", "qs": ["0x401000:var_8:buffer"]}
    """
    # Handle new batch format: {ty, qs}
    if isinstance(renamings, dict) and "qs" in renamings and "ty" in renamings:
        ty = renamings["ty"]
        query_list = renamings["qs"]

        results = []
        for q in query_list:
            item = _parse_rename_query(q, ty)
            result = _rename_single(item)
            results.append(result)
        return results

    # Handle array of strings (default to function renames)
    if isinstance(renamings, list) and all(isinstance(q, str) for q in renamings):
        results = []
        for q in renamings:
            item = _parse_rename_query(q, "function")
            result = _rename_single(item)
            results.append(result)
        return results

    # Legacy format: list of {ty, addr, src, dst} dicts
    renamings = normalize_dict_list(renamings)
    results = []
    for item in renamings:
        result = _rename_single(item)
        results.append(result)

    return results


def _parse_rename_query(query: str, ty: str) -> dict:
    """Parse rename query string into dict format"""
    parts = query.split(":", 2)

    if ty == "function":
        # Format: "addr:name"
        if len(parts) != 2:
            raise ValueError(f"Expected 'addr:name' for function, got: {query}")
        return {"ty": "function", "addr": parts[0].strip(), "dst": parts[1].strip()}

    elif ty == "global":
        # Format: "old_name:new_name"
        if len(parts) != 2:
            raise ValueError(f"Expected 'old:new' for global, got: {query}")
        return {"ty": "global", "src": parts[0].strip(), "dst": parts[1].strip()}

    elif ty == "local":
        # Format: "func_addr:old_name:new_name"
        if len(parts) != 3:
            raise ValueError(f"Expected 'func:old:new' for local, got: {query}")
        return {
            "ty": "local",
            "addr": parts[0].strip(),
            "src": parts[1].strip(),
            "dst": parts[2].strip(),
        }

    elif ty == "stack":
        # Format: "func_addr:old_name:new_name"
        if len(parts) != 3:
            raise ValueError(f"Expected 'func:old:new' for stack, got: {query}")
        return {
            "ty": "stack",
            "addr": parts[0].strip(),
            "src": parts[1].strip(),
            "dst": parts[2].strip(),
        }

    else:
        raise ValueError(f"Unknown rename type: {ty}")


def _rename_single(item: dict) -> dict:
    """Internal helper to rename a single item"""
    try:
        item_type = item["ty"]
        success = False

        if item_type == "function":
            ea = parse_address(item["addr"])
            success = idaapi.set_name(ea, item["dst"], idaapi.SN_CHECK)
            if success:
                func = idaapi.get_func(ea)
                if func:
                    refresh_decompiler_ctext(func.start_ea)

        elif item_type == "global":
            ea = idaapi.get_name_ea(idaapi.BADADDR, item["src"])
            if ea != idaapi.BADADDR:
                success = idaapi.set_name(ea, item["dst"], idaapi.SN_CHECK)

        elif item_type == "local":
            func = idaapi.get_func(parse_address(item["addr"]))
            if func:
                success = ida_hexrays.rename_lvar(
                    func.start_ea, item["src"], item["dst"]
                )
                if success:
                    refresh_decompiler_ctext(func.start_ea)

        elif item_type == "stack":
            func = idaapi.get_func(parse_address(item["addr"]))
            if not func:
                return {"item": item, "error": "No function found"}

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                return {"item": item, "error": "No frame"}

            idx, udm = frame_tif.get_udm(item["src"])
            if not udm:
                return {"item": item, "error": f"{item['src']} not found"}

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                return {"item": item, "error": "Special frame member"}

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            if ida_frame.is_funcarg_off(func, offset):
                return {"item": item, "error": "Argument member"}

            sval = ida_frame.soff_to_fpoff(func, offset)
            success = ida_frame.define_stkvar(func, item["dst"], sval, udm.type)

        return {
            "item": item,
            "ok": success,
            "error": None if success else "Rename failed",
        }

    except Exception as e:
        return {"item": item, "error": str(e)}
