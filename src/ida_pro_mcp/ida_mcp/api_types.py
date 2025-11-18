from typing import Annotated

import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import ida_ida
import idaapi

from .rpc import tool
from .sync import idaread, idawrite, ida_major
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    StructureMember,
    StructureDefinition,
    StructRead,
    TypeApplication,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idawrite
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare types"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idaread
def structs() -> list[StructureDefinition]:
    """List all structures"""
    rv = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            members = []
            if tif.get_udt_details(udt):
                members = [
                    StructureMember(
                        name=x.name,
                        offset=hex(x.offset // 8),
                        size=hex(x.size // 8),
                        type=str(x.type),
                    )
                    for _, x in enumerate(udt)
                ]

            rv += [
                StructureDefinition(
                    name=tif.get_type_name(), size=hex(tif.get_size()), members=members
                )
            ]

    return rv


@tool
@idaread
def struct_info(
    names: Annotated[list[str] | str, "Structure names to query"],
) -> list[dict]:
    """Get struct info"""
    names = normalize_list_input(names)
    results = []

    for name in names:
        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                results.append({"name": name, "error": f"Struct '{name}' not found"})
                continue

            result = {
                "name": name,
                "type": str(tif._print()),
                "size": tif.get_size(),
                "is_udt": tif.is_udt(),
            }

            if not tif.is_udt():
                result["error"] = "Not a user-defined type"
                results.append({"name": name, "info": result})
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                result["error"] = "Failed to get struct details"
                results.append({"name": name, "info": result})
                continue

            result["cardinality"] = udt_data.size()
            result["is_union"] = udt_data.is_union
            result["udt_type"] = "Union" if udt_data.is_union else "Struct"

            members = []
            for i, member in enumerate(udt_data):
                offset = member.begin() // 8
                size = member.size // 8 if member.size > 0 else member.type.get_size()
                member_type = member.type._print()
                member_name = member.name

                member_info = {
                    "index": i,
                    "offset": f"0x{offset:08X}",
                    "size": size,
                    "type": member_type,
                    "name": member_name,
                    "is_nested_udt": member.type.is_udt(),
                }

                if member.type.is_udt():
                    member_info["nested_size"] = member.type.get_size()

                members.append(member_info)

            result["members"] = members
            result["total_size"] = tif.get_size()

            results.append({"name": name, "info": result})
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    return results


@tool
@idaread
def read_struct(queries: list[StructRead] | StructRead) -> list[dict]:
    """Read struct fields"""

    def parse_addr_struct(s: str) -> dict:
        # Support "addr:struct" or just "addr" (auto-detect struct)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "struct": parts[1].strip()}
        return {"addr": s.strip(), "struct": ""}

    queries = normalize_dict_list(queries, parse_addr_struct)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            addr = parse_address(addr_str)

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_addr = addr + offset
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                try:
                    if member.type.is_ptr():
                        is_64bit = (
                            ida_ida.inf_is_64bit()
                            if ida_major >= 9
                            else idaapi.get_inf_structure().is_64bit()
                        )
                        if is_64bit:
                            value = idaapi.get_qword(member_addr)
                            value_str = f"0x{value:016X}"
                        else:
                            value = idaapi.get_dword(member_addr)
                            value_str = f"0x{value:08X}"
                    elif member_size == 1:
                        value = idaapi.get_byte(member_addr)
                        value_str = f"0x{value:02X} ({value})"
                    elif member_size == 2:
                        value = idaapi.get_word(member_addr)
                        value_str = f"0x{value:04X} ({value})"
                    elif member_size == 4:
                        value = idaapi.get_dword(member_addr)
                        value_str = f"0x{value:08X} ({value})"
                    elif member_size == 8:
                        value = idaapi.get_qword(member_addr)
                        value_str = f"0x{value:016X} ({value})"
                    else:
                        bytes_data = []
                        for i in range(min(member_size, 16)):
                            try:
                                byte_val = idaapi.get_byte(member_addr + i)
                                bytes_data.append(f"{byte_val:02X}")
                            except Exception:
                                break
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "value": value_str,
                }

                members.append(member_info)

            results.append(
                {"addr": addr_str, "struct": struct_name, "members": members}
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "struct": struct_name,
                    "members": None,
                    "error": str(e),
                }
            )

    return results


@tool
@idaread
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[dict]:
    """Search structs"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idawrite
def apply_types(applications: list[TypeApplication] | TypeApplication) -> list[dict]:
    """Apply types (function/global/local/stack)"""

    def parse_addr_type(s: str) -> dict:
        # Support "addr:typename" format (auto-detects kind)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "ty": parts[1].strip()}
        # Just typename without address (invalid)
        return {"ty": s.strip()}

    applications = normalize_dict_list(applications, parse_addr_type)
    results = []

    for app in applications:
        try:
            # Auto-detect kind if not provided
            kind = app.get("kind")
            if not kind:
                if "signature" in app:
                    kind = "function"
                elif "variable" in app:
                    kind = "local"
                elif "addr" in app:
                    # Check if address points to a function
                    try:
                        addr = parse_address(app["addr"])
                        func = idaapi.get_func(addr)
                        if func and "name" in app and "ty" in app:
                            kind = "stack"
                        else:
                            kind = "global"
                    except Exception:
                        kind = "global"
                else:
                    kind = "global"

            if kind == "function":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(app["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": app, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, app.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(app["addr"])

                tif = get_type_by_name(app["ty"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(app["ty"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(app["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stack":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": app, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(app["name"])
                if not udm:
                    results.append({"edit": app, "error": f"{app['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(app["ty"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": app, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": app, "error": str(e)})

    return results


@tool
@idaread
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer types"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results
