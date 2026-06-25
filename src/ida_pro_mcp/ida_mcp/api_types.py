from typing import Annotated, Any, TypedDict

import ida_bytes
import ida_frame
import ida_hexrays
import ida_nalt
import ida_typeinf
import idaapi
import idc

from . import compat
from .compat import tinfo_get_udm
from .rpc import tool, safety, title
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
    hexrays_local_var_exists,
    read_bytes_bss_safe,
    read_int_bss_safe,
    bump_decompile_dirty,
    StructRead,
    TypeEdit,
    TypeInspectQuery,
    TypeQuery,
    TypeApplyBatch,
    EnumUpsert,
)


def _tinfo_definite_flag() -> int:
    """TINFO_DEFINITE flag for apply_tinfo (definitive type).

    PT_SIL is a PARSE flag and is wrong to pass to apply_tinfo, whose flags are
    the TINFO_* family. Use TINFO_DEFINITE when available; fall back to 0x1
    (its canonical value) on older SDKs that don't expose the constant.
    """
    return int(getattr(ida_typeinf, "TINFO_DEFINITE", 0x1))


def _type_stuck(ea: int, expected: ida_typeinf.tinfo_t) -> bool:
    """Re-read the type at `ea` and confirm an applied type actually stuck.

    Returns True if a type is now present at `ea` and (when comparable) matches
    the type we just applied. Best-effort: if the re-read itself fails we return
    False so the caller surfaces an error rather than a false success.
    """
    try:
        readback = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(readback, ea):
            return False
        try:
            if readback.equals_to(expected):
                return True
        except Exception:
            pass
        # Fall back to textual comparison when equals_to is unavailable or the
        # decompiler normalised the type representation.
        try:
            return str(readback) == str(expected) or not readback.empty()
        except Exception:
            return not readback.empty()
    except Exception:
        return False


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


@safety("DESTRUCTIVE")
@title("Declare C Types")
@tool
@idasync
def declare_type(
    decls: Annotated[
        list[str] | str,
        "One C declaration per item (or a single string), e.g. "
        "'struct Pkt { uint8_t op; uint16_t len; };' or 'typedef int MyInt;'. "
        "Each is parsed independently and added to the local type library.",
    ],
) -> list[DeclareTypeResult]:
    """WHAT: Parse C type declarations (struct/union/enum/typedef) and register them in the IDB local type library so they can later be applied to globals/locals/stack with set_type.

    WHEN TO USE: Define a recovered struct/enum BEFORE applying it as a type. Pass several declarations at once to satisfy inter-type dependencies in one call.

    RETURNS: One entry per input declaration: {"decl": <source>} on success, or {"decl": <source>, "error": <parser messages>} on failure.

    PITFALL: Declaration ORDER matters within a single call only if a later decl references an earlier one's name; declare base/referenced types first (or in earlier list items). This only DEFINES the type, it does not attach it to any address - use set_type / type_apply_batch for that. Re-declaring an identical type is harmless; a conflicting redefinition surfaces as a parse error rather than silently overwriting.
    """
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
                # A newly declared/changed type can alter any function's
                # pseudocode, so invalidate the whole decompile cache.
                bump_decompile_dirty(None)
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


@safety("DESTRUCTIVE")
@title("Create or Extend Enums")
@tool
@idasync
def enum_upsert(
    queries: Annotated[
        list[EnumUpsert] | EnumUpsert,
        "One or more enum specs. Each: {'name': <enum name>, 'members': "
        "[{'name': <const>, 'value': <int or '0x..' string>}, ...], "
        "'bitfield': <bool, optional>}. Missing enums are created; existing "
        "ones are extended in place.",
    ],
) -> list[EnumUpsertResult]:
    """WHAT: Idempotently create local enums and add members WITHOUT destructive replacement - existing members that already match are skipped, conflicting ones are reported, never overwritten.

    WHEN TO USE: Build up a recovered enum/flags type incrementally (e.g. opcode tables) and re-run safely as you discover more constants. Set bitfield=true for flag enums.

    RETURNS: One entry per enum spec with {name, enum_id, created, bitfield, members:[{name,value,created|skipped|error}], summary:{created,skipped,conflicts}}; a top-level "error" is set when any member conflicts (or for malformed input).

    PITFALL: A member NAME that already exists in a DIFFERENT enum, or an enum VALUE already taken by a different member name, is reported as a conflict and left untouched - resolve the clash by hand rather than expecting an overwrite. Toggling bitfield on an existing enum is rejected (mismatch error) to avoid silently reinterpreting values. Values accept ints or base-prefixed strings ('0x10', '0b1', '8').
    """
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
            # Creating an enum or adding constants can change how the
            # decompiler renders affected functions; drop cached pseudocode.
            if created or created_count > 0:
                bump_decompile_dirty(None)
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


@safety("READ")
@title("Read Struct at Address")
@tool
@idasync
def read_struct(
    queries: Annotated[
        list[StructRead] | StructRead,
        "One or more read requests. Each: {'addr': <ea or symbol name>, "
        "'struct': <type name, optional>}. If 'struct' is omitted the type is "
        "auto-detected from the type already applied at that address.",
    ],
) -> list[ReadStructResult]:
    """WHAT: Overlay a named struct type onto the bytes at an address and return each member's offset, type, size, and decoded value.

    WHEN TO USE: Inspect a live/static instance of a recovered struct (packet buffer, actor object, asset header). Omit 'struct' to reuse the type IDA already has at the address; pass a symbol name in 'addr' to resolve it automatically.

    RETURNS: One entry per request: {addr, struct, members:[{offset,type,name,size,value}]} or {..., error}. Pointer/scalar members render as hex (scalars also show decimal); larger members show the first 16 bytes with an ellipsis.

    PITFALL: Reads are BSS-aware - bytes in uninitialized segments resolve to zero (matching runtime zero-init) rather than failing, so an all-zero value may mean "unmapped" not "actually zero". The struct must already exist in the type library (declare_type first). 'offset' is the member's byte offset within the struct, not an absolute address.
    """

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

                # Read memory value at member address (BSS-aware: unloaded
                # bytes resolve to zero, matching runtime zero-init).
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        ptr_size = 8 if compat.inf_is_64bit() else 4
                        value = read_int_bss_safe(member_addr, ptr_size)
                        value_str = f"0x{value:0{ptr_size * 2}X}"
                    elif member_size in (1, 2, 4, 8):
                        value = read_int_bss_safe(member_addr, member_size)
                        value_str = f"0x{value:0{member_size * 2}X} ({value})"
                    else:
                        capped = min(member_size, 16)
                        raw = read_bytes_bss_safe(member_addr, capped)
                        bytes_data = [f"{b:02X}" for b in raw]
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


@safety("READ")
@title("Search Structs by Name")
@tool
@idasync
def search_structs(
    filter: Annotated[
        str,
        "Case-insensitive substring matched against struct/union names "
        "(e.g. 'pkt', 'actor'). Empty string matches every UDT.",
    ],
) -> list[SearchStructResult]:
    """WHAT: Find local struct/union types whose name contains a substring, returning a compact descriptor for each match.

    WHEN TO USE: Discover which recovered aggregate types already exist before declaring a new one or before calling type_inspect/read_struct. Use the broader type_query for enums/typedefs/functions, kind filtering, pagination, or member projection.

    RETURNS: A list of {name, size, cardinality (member count), is_union, ordinal}.

    PITFALL: This is substring, not regex/glob - 'a*b' is treated literally. Only UDTs (structs/unions) are returned; enums and typedefs are skipped (use type_query for those). On large IDBs prefer a specific filter, as it scans the whole ordinal range.
    """
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


@safety("READ")
@title("Query Type Catalog")
@tool
@idasync
def type_query(
    queries: Annotated[
        list[TypeQuery] | TypeQuery,
        "One or more catalog queries. Each may set: filter (name substring/"
        "pattern), kind ('any'|'struct'|'union'|'enum'|'typedef'|'func'|'ptr'|"
        "'udt'), offset/count (pagination), sort_by ('name'|'size'|'ordinal') "
        "+ descending, include_decl, include_members + max_members, "
        "include_relationships.",
    ],
) -> list[TypeQueryResult]:
    """WHAT: Page and filter the entire local type catalog with projection-friendly output - the full-featured counterpart to search_structs (covers enums/typedefs/funcs/ptrs, supports sorting, pagination, member layout, and cross-type relationships).

    WHEN TO USE: Browse or audit the type library at scale; enumerate all enums or all structs; pull member layouts in bulk; or map which types reference which (include_relationships). Reach for type_inspect instead when you already know the exact name.

    RETURNS: One result per query: {kind, data:[rows], next_offset, total}. Each row carries ordinal/name/size/kind plus optional declaration, member_count/members(+members_truncated), and related_count/related_types(+related_truncated) depending on the include_* flags.

    PITFALL: Member and relationship projection are OFF by default - set include_members / include_relationships to get them. max_members is clamped to [0,4096] and members beyond it set members_truncated=true; related_types is capped at 256. Page via next_offset (null means no more pages); 'total' is the post-filter count, not the page size.
    """
    queries = normalize_dict_list(queries)

    # Build one local catalog and page/filter it per query.
    catalog: list[dict] = []
    limit = compat.get_ordinal_limit()
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


@safety("READ")
@title("Inspect Named Type")
@tool
@idasync
def type_inspect(
    queries: Annotated[
        list[TypeInspectQuery] | TypeInspectQuery,
        "One or more lookups. Each: {'name': <exact type name>, "
        "'include_members': <bool, optional>, 'max_members': <int, optional>}.",
    ],
) -> list[TypeInspectResult]:
    """WHAT: Look up one or more types BY EXACT NAME and report existence, size, kind flags (is_func/is_ptr/is_enum/is_udt), the C declaration, and (optionally) the member layout.

    WHEN TO USE: Confirm a type exists and check its shape before applying it with set_type, or pull a single struct's member offset/size table. Use type_query instead to browse/filter many types at once.

    RETURNS: One entry per name: {name, exists, declaration, size, is_func, is_ptr, is_enum, is_udt, member_count, members} - members is null unless include_members is set; on a miss {name, exists:false, error}.

    PITFALL: Matching is EXACT (not substring) - use search_structs/type_query to find the right name first. max_members is clamped to [0,4096] and silently truncates a larger UDT. Members are only populated for UDTs even if include_members is true (enums/typedefs return member_count 0).
    """
    queries = normalize_dict_list(queries)
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
                    _, udm = tinfo_get_udm(frame_tif, str(edit["name"]))
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
            ok = ida_typeinf.apply_tinfo(
                func.start_ea, tif, _tinfo_definite_flag()
            )
            if ok and not _type_stuck(func.start_ea, tif):
                ok = False
            result = {"edit": edit, "kind": kind, "ok": ok}
            if ok:
                bump_decompile_dirty(func.start_ea)
            else:
                result["error"] = (
                    f"Failed to apply function type at {hex(func.start_ea)} for signature "
                    f"{signature!r}; ensure all referenced types are declared in the local "
                    "type library"
                )
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
            ok = ida_typeinf.apply_tinfo(ea, tif, _tinfo_definite_flag())
            if ok and not _type_stuck(ea, tif):
                ok = False
            result = {"edit": edit, "kind": kind, "ok": ok}
            if ok:
                bump_decompile_dirty(ea)
            else:
                result["error"] = (
                    f"Failed to apply global type at {hex(ea)} for type {type_text!r}"
                )
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
            if ok:
                bump_decompile_dirty(func.start_ea)
            if not ok:
                if not hexrays_local_var_exists(func.start_ea, var_name):
                    result["error"] = (
                        f"Local variable {var_name!r} not found in function at "
                        f"{hex(func.start_ea)}"
                    )
                else:
                    result["error"] = (
                        f"Failed to apply type {type_text!r} to local variable {var_name!r}"
                    )
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

            idx, udm = tinfo_get_udm(frame_tif, stack_name)
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
            if ok:
                bump_decompile_dirty(func.start_ea)
            if not ok:
                result["error"] = (
                    f"Failed to set stack member type for {stack_name!r} at offset "
                    f"{offset} in function at {hex(func.start_ea)}"
                )
            return result

        return {"edit": edit, "kind": kind, "error": f"Unknown kind: {kind}"}
    except Exception as e:
        return {"edit": edit, "error": str(e)}


@safety("DESTRUCTIVE")
@title("Apply Types")
@tool
@idasync
def set_type(
    edits: Annotated[
        list[TypeEdit] | TypeEdit,
        "One or more type edits. Per kind: function -> {addr, signature}; "
        "global -> {name or addr, type}; local (decompiler var) -> "
        "{addr, variable, type}; stack (frame member) -> {addr, name, type}. "
        "'kind' is optional and inferred when omitted. The 'addr:typename' "
        "string shorthand is also accepted.",
    ],
) -> list[SetTypeResult]:
    """WHAT: Apply a recovered type to a function signature, a global, a decompiler local variable, or a stack-frame member - the kind is inferred from the fields you supply unless you set it explicitly.

    WHEN TO USE: Stamp types onto the IDB after declaring them (declare_type). For a function pass its full signature; for a global pass a name or address + type; for a Hex-Rays local pass addr + variable + type; for a frame slot pass addr + name + type.

    RETURNS: One entry per edit: {edit, kind, ok} on success, or {..., error} with a kind-specific message (e.g. function/global not found, local var missing, referenced type not declared).

    PITFALL: Every referenced type must already exist in the local type library or the apply fails - declare_type first. Kind inference is heuristic: addr+name resolves to 'stack' only when that name is a real frame member, otherwise it falls through to 'global'; set 'kind' explicitly to remove ambiguity. For atomic multi-edit application with stop-on-error and an aggregate summary, prefer type_apply_batch.
    """
    normalized_edits = normalize_dict_list(edits, _parse_addr_type_shorthand)
    return [_apply_type_edit(edit) for edit in normalized_edits]


@safety("DESTRUCTIVE")
@title("Apply Types (Batch)")
@tool
@idasync
def type_apply_batch(
    batch: Annotated[
        TypeApplyBatch,
        "{'edits': [<TypeEdit>, ...], 'stop_on_error': <bool, optional>}. "
        "Each edit uses the same shape as set_type "
        "(function/global/local/stack); 'addr:typename' shorthand is accepted.",
    ],
) -> TypeApplyBatchResult:
    """WHAT: Apply many type edits in one call (same per-edit semantics as set_type) and return a rolled-up status with per-edit detail.

    WHEN TO USE: Stamp a whole recovered cluster of types at once and get an aggregate pass/fail count. Set stop_on_error to halt at the first failure (e.g. when later edits depend on earlier ones succeeding).

    RETURNS: {ok (all succeeded), applied, failed, stopped (true iff stop_on_error halted early), results:[<SetTypeResult>...]}.

    PITFALL: This is NOT transactional - edits already applied before a failure stay applied even when stop_on_error halts the rest, so re-running may re-apply some. All referenced types must be declared first (declare_type). For a single edit, set_type is simpler.
    """
    normalized_edits = normalize_dict_list(
        batch.get("edits", []), _parse_addr_type_shorthand
    )
    stop_on_error = bool(batch.get("stop_on_error", False))

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


@safety("READ")
@title("Infer Likely Types")
@tool
@idasync
def infer_types(
    addrs: Annotated[
        list[str] | str,
        "One or more addresses (ea or symbol names) to infer a type for; "
        "accepts a single string or a list.",
    ],
) -> list[InferTypeResult]:
    """WHAT: Suggest the most likely type at each address, trying Hex-Rays inference first, then any type already applied, then a size-based scalar guess - and report which method/confidence produced it.

    WHEN TO USE: Get a starting-point type for an untyped global/data item before committing it. This is advisory ONLY.

    RETURNS: One entry per address: {addr, inferred_type, method ('hexrays'|'existing'|'size_based'|null), confidence ('high'|'low'|'none')} (+ error on failure).

    PITFALL: Despite the action's name this does NOT modify the IDB - it only proposes a type. Feed the result into set_type / type_apply_batch to actually apply it, and treat 'size_based'/'low' confidence guesses skeptically (they only map item size to a uintN_t). A 'none' confidence with null type means nothing could be inferred.
    """
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
