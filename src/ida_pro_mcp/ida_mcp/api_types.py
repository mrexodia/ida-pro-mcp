from typing import Annotated, Any, TypedDict

import idc
import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    paginate,
    pattern_filter,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    StructRead,
    TypeEdit,
    TypeInspectQuery,
    TypeQuery,
    TypeApplyBatch,
    EnumUpsert,
)
from . import compat


class DeclareTypeResult(TypedDict, total=False):
    decl: str
    error: str


class EnumMemberUpsertResult(TypedDict, total=False):
    name: str
    value: int
    created: bool
    skipped: bool
    error: str


class EnumUpsertSummaryResult(TypedDict):
    created: int
    skipped: int
    conflicts: int


class EnumUpsertResult(TypedDict, total=False):
    name: str
    enum_id: str
    created: bool
    bitfield: bool
    members: list[EnumMemberUpsertResult]
    summary: EnumUpsertSummaryResult
    error: str


class StructMemberValueResult(TypedDict):
    offset: str
    type: str
    name: str
    size: int
    value: str


class ReadStructResult(TypedDict, total=False):
    addr: str | None
    struct: str | None
    members: list[StructMemberValueResult] | None
    error: str


class SearchStructResult(TypedDict):
    name: str
    size: int
    cardinality: int
    is_union: bool
    ordinal: int


class TypeCatalogMemberResult(TypedDict):
    name: str
    offset: str
    size: int
    type: str


class TypeCatalogRow(TypedDict, total=False):
    ordinal: int
    name: str
    size: int
    kind: str
    declaration: str
    member_count: int
    members: list[TypeCatalogMemberResult]
    members_truncated: bool
    related_count: int
    related_types: list[str]
    related_truncated: bool


class TypeQueryResult(TypedDict):
    kind: str
    data: list[TypeCatalogRow]
    next_offset: int | None
    total: int


class TypeInspectResult(TypedDict, total=False):
    name: str
    exists: bool
    declaration: str
    size: int
    is_func: bool
    is_ptr: bool
    is_enum: bool
    is_udt: bool
    members: list[TypeCatalogMemberResult] | None
    member_count: int
    error: str


class SetTypeResult(TypedDict, total=False):
    edit: dict[str, Any]
    kind: str
    ok: bool
    error: str


class TypeApplyBatchResult(TypedDict):
    ok: bool
    applied: int
    failed: int
    stopped: bool
    results: list[SetTypeResult]


class InferTypeResult(TypedDict, total=False):
    addr: str
    inferred_type: str | None
    method: str | None
    confidence: str
    error: str


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[DeclareTypeResult]:
    """Declare C type definitions in local type library."""
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
                results.append({"decl": decl})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


@tool
@idasync
def enum_upsert(
    queries: Annotated[
        list[EnumUpsert] | EnumUpsert,
        "Create enums if missing and upsert enum members without destructive replacement",
    ],
) -> list[EnumUpsertResult]:
    """Create or extend local enums in an idempotent way."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        enum_name = str(query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        bitfield = bool(query.get("bitfield", False))

        if not enum_name:
            results.append({"name": enum_name, "error": "Enum name is required"})
            continue
        if not members or members == [{}]:
            results.append({"name": enum_name, "error": "At least one enum member is required"})
            continue

        try:
            enum_id = idc.get_enum(enum_name)
            created = enum_id == idc.BADADDR
            if created:
                enum_id = idc.add_enum(idc.BADADDR, enum_name, 0)
                if enum_id == idc.BADADDR:
                    results.append({"name": enum_name, "error": f"Failed to create enum: {enum_name}"})
                    continue

            if bool(idc.is_bf(enum_id)) != bitfield and not created:
                results.append(
                    {
                        "name": enum_name,
                        "enum_id": hex(enum_id),
                        "error": f"Enum bitfield mismatch for {enum_name}",
                    }
                )
                continue
            idc.set_enum_bf(enum_id, bitfield)

            member_results = []
            created_count = 0
            skipped_count = 0
            conflict_count = 0
            for member in members:
                member_name = str(member.get("name", "") or "").strip()
                raw_value = member.get("value")
                if not member_name:
                    member_results.append({"name": member_name, "error": "Member name is required"})
                    conflict_count += 1
                    continue
                try:
                    value = _parse_enum_value(raw_value)
                except Exception as exc:
                    member_results.append({"name": member_name, "error": str(exc)})
                    conflict_count += 1
                    continue

                existing_member_id = idc.get_enum_member_by_name(member_name)
                if existing_member_id != idc.BADADDR:
                    existing_enum = idc.get_enum_member_enum(existing_member_id)
                    existing_value = idc.get_enum_member_value(existing_member_id)
                    if existing_enum == enum_id and existing_value == value:
                        member_results.append(
                            {"name": member_name, "value": value, "skipped": True}
                        )
                        skipped_count += 1
                        continue
                    member_results.append(
                        {
                            "name": member_name,
                            "value": value,
                            "error": (
                                f"Member name conflict: {member_name} already exists with value "
                                f"{existing_value} in enum {idc.get_enum_name(existing_enum) or hex(existing_enum)}"
                            ),
                        }
                    )
                    conflict_count += 1
                    continue

                existing_const = idc.get_enum_member(enum_id, value, 0, -1)
                if existing_const != -1:
                    existing_name = idc.get_enum_member_name(existing_const) or ""
                    if existing_name == member_name:
                        member_results.append(
                            {"name": member_name, "value": value, "skipped": True}
                        )
                        skipped_count += 1
                        continue
                    member_results.append(
                        {
                            "name": member_name,
                            "value": value,
                            "error": f"Enum value conflict: {value} already belongs to {existing_name}",
                        }
                    )
                    conflict_count += 1
                    continue

                rc = idc.add_enum_member(enum_id, member_name, value, -1)
                if rc != 0:
                    member_results.append(
                        {"name": member_name, "value": value, "error": f"Failed to add enum member: rc={rc}"}
                    )
                    conflict_count += 1
                    continue
                member_results.append({"name": member_name, "value": value, "created": True})
                created_count += 1

            result_dict: dict = {
                "name": enum_name,
                "enum_id": hex(enum_id),
                "created": created,
                "bitfield": bitfield,
                "members": member_results,
                "summary": {
                    "created": created_count,
                    "skipped": skipped_count,
                    "conflicts": conflict_count,
                },
            }
            if conflict_count > 0:
                result_dict["error"] = f"{conflict_count} member conflict(s)"
            results.append(result_dict)
        except Exception as exc:
            results.append({"name": enum_name, "error": str(exc)})

    return results


def _parse_enum_value(value: int | str | None) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Enum member value is required")
        return int(text, 0)
    raise ValueError(f"Invalid enum member value: {value!r}")


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(
    queries: list[StructRead] | StructRead,
) -> list[ReadStructResult]:
    """Read struct fields from memory at address; auto-detect type when possible."""

    queries = normalize_dict_list(queries)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            # Parse address - this is required
            if not addr_str:
                results.append(
                    {
                        "addr": None,
                        "struct": struct_name,
                        "members": None,
                        "error": "Address is required for reading struct fields",
                    }
                )
                continue

            # Try to parse as address, then try name resolution
            try:
                addr = parse_address(addr_str)
            except Exception:
                addr = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
                if addr == idaapi.BADADDR:
                    results.append(
                        {
                            "addr": addr_str,
                            "struct": struct_name,
                            "members": None,
                            "error": f"Failed to resolve address: {addr_str}",
                        }
                    )
                    continue

            # Auto-detect struct type from address if not provided
            if not struct_name:
                tif_auto = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif_auto, addr) and tif_auto.is_udt():
                    struct_name = tif_auto.get_type_name()

            if not struct_name:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": None,
                        "members": None,
                        "error": "No struct specified and could not auto-detect from address",
                    }
                )
                continue

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
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                # Read memory value at member address
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        is_64bit = compat.inf_is_64bit()
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
                                bytes_data.append(
                                    f"{idaapi.get_byte(member_addr + i):02X}"
                                )
                            except Exception:
                                break
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
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
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[SearchStructResult]:
    """Search local structs/unions by name pattern."""
    results = []
    limit = compat.get_ordinal_limit()

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


def _type_kind(tif: ida_typeinf.tinfo_t) -> str:
    try:
        if tif.is_enum():
            return "enum"
    except Exception:
        pass
    try:
        if tif.is_typedef():
            return "typedef"
    except Exception:
        pass
    try:
        if tif.is_func():
            return "func"
    except Exception:
        pass
    try:
        if tif.is_ptr():
            return "ptr"
    except Exception:
        pass

    try:
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt) and udt.is_union:
                return "union"
            return "struct"
    except Exception:
        pass

    return "other"


def _type_matches_kind(kind: str, tif: ida_typeinf.tinfo_t) -> bool:
    if kind == "any":
        return True
    if kind == "udt":
        try:
            return bool(tif.is_udt())
        except Exception:
            return False
    return _type_kind(tif) == kind


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def type_query(
    queries: Annotated[
        list[TypeQuery] | TypeQuery | str,
        "Type catalog query with filtering, pagination, and optional relationships",
    ],
) -> list[TypeQueryResult]:
    """Query local types with structured filters/projection-friendly output."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "filter": s,
            "kind": "any",
            "offset": 0,
            "count": 100,
            "sort_by": "name",
            "descending": False,
            "include_decl": True,
            "include_members": False,
            "max_members": 64,
            "include_relationships": False,
        },
    )

    # Build one local catalog and page/filter it per query.
    catalog: list[dict] = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal):
            continue
        name = tif.get_type_name()
        if not name:
            continue
        catalog.append(
            {
                "ordinal": ordinal,
                "name": name,
                "size": tif.get_size(),
                "kind": _type_kind(tif),
                "_tif": tif,
            }
        )

    results: list[dict] = []
    for query in queries:
        filter_pattern = str(query.get("filter", "") or "")
        kind = str(query.get("kind", "any") or "any").lower()
        if kind not in {"any", "struct", "union", "enum", "typedef", "func", "ptr", "udt"}:
            kind = "any"

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        sort_by = str(query.get("sort_by", "name") or "name")
        descending = bool(query.get("descending", False))
        include_decl = bool(query.get("include_decl", True))
        include_members = bool(query.get("include_members", False))
        max_members = int(query.get("max_members", 64) or 64)
        include_relationships = bool(query.get("include_relationships", False))

        if max_members < 0:
            max_members = 0
        if max_members > 4096:
            max_members = 4096

        filtered: list[dict] = []
        for row in catalog:
            tif = row.get("_tif")
            if not isinstance(tif, ida_typeinf.tinfo_t):
                continue
            if not _type_matches_kind(kind, tif):
                continue
            filtered.append(row)

        if filter_pattern:
            filtered = pattern_filter(filtered, filter_pattern, "name")

        if sort_by == "size":
            filtered.sort(key=lambda r: int(r.get("size", 0) or 0), reverse=descending)
        elif sort_by == "ordinal":
            filtered.sort(key=lambda r: int(r.get("ordinal", 0) or 0), reverse=descending)
        else:
            filtered.sort(key=lambda r: str(r.get("name", "")).lower(), reverse=descending)

        output_rows: list[dict] = []
        for row in filtered:
            tif = row["_tif"]
            out = {
                "ordinal": row["ordinal"],
                "name": row["name"],
                "size": row["size"],
                "kind": row["kind"],
            }

            if include_decl:
                out["declaration"] = str(tif)

            if include_members:
                members = []
                member_count = 0
                members_truncated = False
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        member_count = len(udt)
                        for idx, member in enumerate(udt):
                            if idx >= max_members:
                                members_truncated = True
                                break
                            members.append(
                                {
                                    "name": member.name,
                                    "offset": hex(member.begin() // 8),
                                    "size": member.type.get_size(),
                                    "type": member.type._print(),
                                }
                            )
                out["member_count"] = member_count
                out["members"] = members
                out["members_truncated"] = members_truncated

            if include_relationships:
                related: set[str] = set()
                if tif.is_udt():
                    udt = ida_typeinf.udt_type_data_t()
                    if tif.get_udt_details(udt):
                        for member in udt:
                            rel_name = member.type.get_type_name() or str(member.type)
                            if rel_name:
                                related.add(rel_name)
                if tif.is_ptr():
                    pointed = ida_typeinf.tinfo_t()
                    try:
                        if tif.get_pointed_object(pointed):
                            rel_name = pointed.get_type_name() or str(pointed)
                            if rel_name:
                                related.add(rel_name)
                    except Exception:
                        pass

                related_list = sorted(related)
                out["related_count"] = len(related_list)
                out["related_types"] = related_list[:256]
                out["related_truncated"] = len(related_list) > 256

            output_rows.append(out)

        page = paginate(output_rows, offset, count)
        results.append(
            {
                "kind": kind,
                "data": page["data"],
                "next_offset": page["next_offset"],
                "total": len(output_rows),
            }
        )

    return results


@tool
@idasync
def type_inspect(
    queries: Annotated[
        list[TypeInspectQuery] | TypeInspectQuery | str,
        "Inspect named types and optionally include member layout",
    ],
) -> list[TypeInspectResult]:
    """Inspect named types (size/kind/declaration/members)."""
    queries = normalize_dict_list(
        queries,
        lambda s: {"name": s, "include_members": False, "max_members": 128},
    )
    results = []

    for query in queries:
        name = (query.get("name") or "").strip()
        include_members = bool(query.get("include_members", False))
        max_members = int(query.get("max_members", 128) or 128)
        if max_members < 0:
            max_members = 0
        if max_members > 4096:
            max_members = 4096

        if not name:
            results.append(
                {
                    "name": name,
                    "exists": False,
                    "error": "Type name is required",
                }
            )
            continue

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                results.append(
                    {"name": name, "exists": False, "error": f"Type not found: {name}"}
                )
                continue

            info = {
                "name": name,
                "exists": True,
                "declaration": str(tif),
                "size": tif.get_size(),
                "is_func": tif.is_func(),
                "is_ptr": tif.is_ptr(),
                "is_enum": tif.is_enum(),
                "is_udt": tif.is_udt(),
                "members": None,
                "member_count": 0,
            }

            if include_members and tif.is_udt():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    info["member_count"] = len(udt)
                    members = []
                    for idx, member in enumerate(udt):
                        if idx >= max_members:
                            break
                        members.append(
                            {
                                "name": member.name,
                                "offset": hex(member.begin() // 8),
                                "size": member.type.get_size(),
                                "type": member.type._print(),
                            }
                        )
                    info["members"] = members

            results.append(info)
        except Exception as e:
            results.append(
                {
                    "name": name,
                    "exists": False,
                    "error": str(e),
                }
            )

    return results


def _parse_addr_type_shorthand(s: str) -> dict:
    # Support "addr:typename" shorthand.
    if ":" in s:
        addr, ty = s.split(":", 1)
        return {"addr": addr.strip(), "ty": ty.strip()}
    return {"ty": s.strip()}


def _resolve_type_text(edit: dict) -> str:
    return str(
        edit.get("ty")
        or edit.get("type")
        or edit.get("decl")
        or edit.get("declaration")
        or ""
    ).strip()


def _parse_type_tinfo(type_text: str) -> ida_typeinf.tinfo_t:
    text = type_text.strip()
    if not text:
        raise ValueError("Type text is required")

    # Fast path for common type aliases and named types.
    try:
        return get_type_by_name(text)
    except Exception:
        pass

    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    parse_decl = getattr(ida_typeinf, "parse_decl", None)
    if callable(parse_decl):
        candidates = [text]
        if not text.endswith(";"):
            candidates.append(text + ";")
        for candidate in candidates:
            tif = ida_typeinf.tinfo_t()
            try:
                # parse_decl returns '' on success in IDA 9.0, check is not None
                if parse_decl(tif, None, candidate, flags) is not None and not tif.empty():
                    return tif
            except Exception:
                continue

    # Legacy constructor fallback.
    try:
        tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
        empty = getattr(tif, "empty", None)
        if callable(empty):
            if not empty():
                return tif
        else:
            return tif
    except Exception:
        pass

    raise ValueError(f"Unable to parse type: {text}")


def _parse_function_tinfo(signature_text: str) -> ida_typeinf.tinfo_t:
    text = signature_text.strip()
    if not text:
        raise ValueError("Function signature is required")

    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    parse_decl = getattr(ida_typeinf, "parse_decl", None)
    if callable(parse_decl):
        candidates = [text]
        if not text.endswith(";"):
            candidates.append(text + ";")
        for candidate in candidates:
            tif = ida_typeinf.tinfo_t()
            try:
                # parse_decl returns '' on success in IDA 9.0, check is not None
                if parse_decl(tif, None, candidate, flags) is not None and tif.is_func():
                    return tif
            except Exception:
                continue

    try:
        tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
        if tif.is_func():
            return tif
    except Exception:
        pass

    raise ValueError(f"Not a function type: {text}")


def _infer_type_edit_kind(edit: dict) -> str:
    kind = str(edit.get("kind") or "").strip().lower()
    if kind:
        return kind
    if edit.get("signature"):
        return "function"
    if edit.get("variable"):
        return "local"

    if "addr" in edit and "name" in edit and _resolve_type_text(edit):
        # Heuristic: addr + frame name usually indicates stack variable updates.
        try:
            fn = idaapi.get_func(parse_address(edit["addr"]))
            if fn:
                frame_tif = ida_typeinf.tinfo_t()
                if ida_frame.get_func_frame(frame_tif, fn):
                    _, udm = frame_tif.get_udm(str(edit["name"]))
                    if udm:
                        return "stack"
        except Exception:
            pass

    return "global"


def _apply_type_edit(edit: dict[str, Any]) -> SetTypeResult:
    try:
        kind = _infer_type_edit_kind(edit)
        type_text = _resolve_type_text(edit)

        if kind == "function":
            addr_text = str(edit.get("addr", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "Function not found"}

            signature = str(edit.get("signature") or type_text).strip()
            tif = _parse_function_tinfo(signature)
            ok = ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply function type"
            return result

        if kind == "global":
            ea = idaapi.BADADDR
            name = str(edit.get("name", "")).strip()
            if name:
                ea = idaapi.get_name_ea(idaapi.BADADDR, name)
            if ea == idaapi.BADADDR:
                addr_text = str(edit.get("addr", "")).strip()
                if not addr_text:
                    return {
                        "edit": edit,
                        "kind": kind,
                        "error": "Global requires name or address",
                    }
                ea = parse_address(addr_text)

            tif = _parse_type_tinfo(type_text)
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply global type"
            return result

        if kind == "local":
            addr_text = str(edit.get("addr", "")).strip()
            var_name = str(edit.get("variable", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            if not var_name:
                return {"edit": edit, "kind": kind, "error": "Local variable name is required"}

            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "Function not found"}

            new_tif = _parse_type_tinfo(type_text)
            modifier = my_modifier_t(var_name, new_tif)
            ok = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to apply local variable type"
            return result

        if kind == "stack":
            addr_text = str(edit.get("addr", "")).strip()
            stack_name = str(edit.get("name", "")).strip()
            if not addr_text:
                return {"edit": edit, "kind": kind, "error": "Function address is required"}
            if not stack_name:
                return {"edit": edit, "kind": kind, "error": "Stack variable name is required"}

            func = idaapi.get_func(parse_address(addr_text))
            if not func:
                return {"edit": edit, "kind": kind, "error": "No function found"}

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                return {"edit": edit, "kind": kind, "error": "No frame available"}

            idx, udm = frame_tif.get_udm(stack_name)
            if not udm:
                return {
                    "edit": edit,
                    "kind": kind,
                    "error": f"Stack variable not found: {stack_name}",
                }

            tid = frame_tif.get_udm_tid(idx)
            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8

            tif = _parse_type_tinfo(type_text)
            ok = ida_frame.set_frame_member_type(func, offset, tif)
            result = {"edit": edit, "kind": kind, "ok": ok}
            if not ok:
                result["error"] = "Failed to set stack member type"
            return result

        return {"edit": edit, "kind": kind, "error": f"Unknown kind: {kind}"}
    except Exception as e:
        return {"edit": edit, "error": str(e)}


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[SetTypeResult]:
    """Apply types (function/global/local/stack)"""
    normalized_edits = normalize_dict_list(edits, _parse_addr_type_shorthand)
    return [_apply_type_edit(edit) for edit in normalized_edits]


@tool
@idasync
def type_apply_batch(
    batch: Annotated[
        TypeApplyBatch | list[TypeEdit] | TypeEdit,
        "Batch type edits with optional stop_on_error behavior",
    ],
) -> TypeApplyBatchResult:
    """Apply multiple type edits and return aggregate status."""
    if isinstance(batch, dict) and "edits" in batch:
        normalized_edits = normalize_dict_list(
            batch.get("edits", []), _parse_addr_type_shorthand
        )
        stop_on_error = bool(batch.get("stop_on_error", False))
    else:
        normalized_edits = normalize_dict_list(batch, _parse_addr_type_shorthand)
        stop_on_error = False

    results: list[dict] = []
    for edit in normalized_edits:
        result = _apply_type_edit(edit)
        results.append(result)
        if stop_on_error and result.get("error"):
            break

    failed = sum(1 for r in results if r.get("error"))
    applied = sum(1 for r in results if r.get("ok"))
    return {
        "ok": failed == 0,
        "applied": applied,
        "failed": failed,
        "stopped": stop_on_error and failed > 0,
        "results": results,
    }


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[InferTypeResult]:
    """Infer and apply likely types at target addresses."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if compat.guess_tinfo(tif, ea):
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
