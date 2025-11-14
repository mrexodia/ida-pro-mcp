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
        list[dict] | dict,
        "[{ty, addr, src, dst}, ...] or {ty, addr, src, dst}. ty: function|global|local|stack",
    ],
) -> list[dict]:
    """Rename anything (function/global/local/stack)"""
    renamings = normalize_dict_list(renamings)
    results = []

    for item in renamings:
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
                    results.append({"item": item, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"item": item, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(item["src"])
                if not udm:
                    results.append({"item": item, "error": f"{item['src']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    results.append({"item": item, "error": "Special frame member"})
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    results.append({"item": item, "error": "Argument member"})
                    continue

                sval = ida_frame.soff_to_fpoff(func, offset)
                success = ida_frame.define_stkvar(func, item["dst"], sval, udm.type)

            results.append(
                {
                    "item": item,
                    "ok": success,
                    "error": None if success else "Rename failed",
                }
            )

        except Exception as e:
            results.append({"item": item, "error": str(e)})

    return results
