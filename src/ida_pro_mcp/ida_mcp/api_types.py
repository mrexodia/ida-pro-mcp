from typing import Annotated, Any, TypedDict

import ida_bytes
import ida_frame
import ida_hexrays
import ida_nalt
import ida_typeinf
import idaapi

from . import compat
from . import typeutils
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


def _db_endian() -> str:
    """Database byte order as 'little'/'big' for typeutils decode helpers."""
    try:
        import ida_ida

        if hasattr(ida_ida, "inf_is_be") and ida_ida.inf_is_be():
            return "big"
    except Exception:
        pass
    try:
        if idaapi.inf_is_be():
            return "big"
    except Exception:
        pass
    return "little"


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


class StructMemberValueResult(TypedDict, total=False):
    offset: str
    type: str
    name: str
    size: int
    value: str
    repr: str
    kind: str
    bit_offset: int
    bit_width: int


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


class TypeCatalogMemberResult(TypedDict, total=False):
    name: str
    offset: str
    size: int
    type: str
    value: int
    mask: int
    bit_offset: int
    bit_width: int


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
    members_truncated: bool
    error: str


class SetTypeResult(TypedDict, total=False):
    edit: dict[str, Any]
    kind: str
    ok: bool
    preview: bool
    current: str | None
    new: str
    error: str


class TypeApplyBatchResult(TypedDict, total=False):
    ok: bool
    applied: int
    failed: int
    stopped: bool
    preview: bool
    results: list[SetTypeResult]


class InferTypeResult(TypedDict, total=False):
    addr: str
    inferred_type: str | None
    method: str | None
    confidence: str
    detail: str
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


def _enum_member_mask(value: int, bitfield: bool) -> int:
    """Bitmask for an edm_t member.

    For a plain enum, the mask is the all-ones DEFMASK (-1) so the constant is
    not interpreted as a bitfield group. For a BITMASK enum, the mask must be
    the actual bits the constant occupies (value itself for a clean flag),
    NEVER -1 - passing -1 there mis-creates the member as a full-width group and
    corrupts bitfield rendering.
    """
    if not bitfield:
        # DEFMASK_64 / DEFMASK: all-ones => "not a bitmask group".
        return int(getattr(ida_typeinf, "DEFMASK64", getattr(ida_typeinf, "DEFMASK", 0xFFFFFFFFFFFFFFFF)))
    if value == 0:
        # A zero flag (e.g. NONE) has no bits; use the full mask so it does not
        # claim a (nonexistent) single bit group.
        return int(getattr(ida_typeinf, "DEFMASK64", getattr(ida_typeinf, "DEFMASK", 0xFFFFFFFFFFFFFFFF)))
    return value & 0xFFFFFFFFFFFFFFFF


def _load_enum_tinfo(name: str) -> tuple[ida_typeinf.tinfo_t | None, bool]:
    """Load an existing enum tinfo by name. Returns (tif_or_None, is_bitfield)."""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name, ida_typeinf.BTF_ENUM):
        # Fall back to plain lookup (typedef'd enum, etc.).
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return None, False
    resolved = typeutils.resolve_typedef(tif)
    try:
        if not resolved.is_enum():
            return None, False
    except Exception:
        return None, False
    etd = ida_typeinf.enum_type_data_t()
    is_bf = False
    if resolved.get_enum_details(etd):
        try:
            is_bf = bool(etd.is_bf())
        except Exception:
            is_bf = False
    return resolved, is_bf


@safety("DESTRUCTIVE")
@title("Create or Extend Enums")
@tool
@idasync
def enum_upsert(
    queries: Annotated[
        list[EnumUpsert] | EnumUpsert,
        "One or more enum specs. Each: {'name': <enum name>, 'members': "
        "[{'name': <const>, 'value': <int or '0x..' string>}, ...], "
        "'bitfield': <bool, optional>, 'mode': 'skip'|'update'|'error' "
        "(optional, default 'skip')}. Missing enums are created; existing "
        "ones are extended in place.",
    ],
) -> list[EnumUpsertResult]:
    """WHAT: Idempotently create/extend local enums on the IDA 9.x edm_t tinfo API - members that already match are skipped, and a per-spec 'mode' controls what happens when an existing member NAME maps to a DIFFERENT value.

    WHEN TO USE: Build up a recovered enum/flags type incrementally (e.g. opcode tables) and re-run safely as you discover more constants. Set bitfield=true for flag enums (each constant's bitmask is set to its own bits, NOT a bogus -1). Set mode='update' to overwrite a member's value in place, 'error' to reject any change, or 'skip' (default) to leave an existing differing member untouched and count it as a conflict.

    RETURNS: One entry per enum spec with {name, enum_id, created, bitfield, members:[{name,value,created|skipped|error}], summary:{created,skipped,conflicts}}; a top-level "error" is set when any member conflicts (or for malformed input).

    PITFALL: Bitmask enums use each member VALUE as its bitmask (a clean single/multi-bit flag); a value with overlapping/ambiguous bits is stored as-is, so keep flags power-of-two unless you intend a combined mask. Toggling bitfield on an existing enum is rejected (mismatch error) to avoid silently reinterpreting values. Values accept ints or base-prefixed strings ('0x10', '0b1', '8'). mode='update' is the only path that mutates an existing member's value.
    """
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        enum_name = str(query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        bitfield = bool(query.get("bitfield", False))
        mode = str(query.get("mode", "skip") or "skip").strip().lower()
        if mode not in {"skip", "update", "error"}:
            mode = "skip"

        if not enum_name:
            results.append({"name": enum_name, "error": "Enum name is required"})
            continue
        if not members or members == [{}]:
            results.append({"name": enum_name, "error": "At least one enum member is required"})
            continue

        try:
            existing_tif, existing_is_bf = _load_enum_tinfo(enum_name)
            created = existing_tif is None

            if not created and existing_is_bf != bitfield:
                results.append(
                    {
                        "name": enum_name,
                        "error": f"Enum bitfield mismatch for {enum_name} "
                        f"(existing bitfield={existing_is_bf}, requested={bitfield})",
                    }
                )
                continue

            # Build the working enum_type_data_t (load existing members or start
            # fresh) and an index of current name->value.
            etd = ida_typeinf.enum_type_data_t()
            current: dict[str, int] = {}
            if not created:
                existing_tif.get_enum_details(etd)
                for edm in etd:
                    try:
                        current[edm.name] = int(edm.value)
                    except Exception:
                        pass
            if hasattr(etd, "set_bf"):
                try:
                    etd.set_bf(bitfield)
                except Exception:
                    pass
            else:
                # Older builds: toggle the BTE_BITMASK bit on the bte flags.
                bte_bitmask = int(getattr(ida_typeinf, "BTE_BITMASK", 0x10))
                try:
                    if bitfield:
                        etd.bte = etd.bte | bte_bitmask
                    else:
                        etd.bte = etd.bte & ~bte_bitmask
                except Exception:
                    pass

            member_results = []
            created_count = 0
            skipped_count = 0
            conflict_count = 0
            dirty = False

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

                if member_name in current:
                    if current[member_name] == value:
                        member_results.append(
                            {"name": member_name, "value": value, "skipped": True}
                        )
                        skipped_count += 1
                        continue
                    # Existing member, different value -> mode decides.
                    if mode == "update":
                        for edm in etd:
                            if edm.name == member_name:
                                edm.value = value
                                try:
                                    edm.bmask = _enum_member_mask(value, bitfield)
                                except Exception:
                                    pass
                                break
                        current[member_name] = value
                        dirty = True
                        member_results.append(
                            {"name": member_name, "value": value, "created": True}
                        )
                        created_count += 1
                        continue
                    member_results.append(
                        {
                            "name": member_name,
                            "value": value,
                            "error": (
                                f"Member {member_name} already exists with value "
                                f"{current[member_name]} (mode={mode!r}); pass mode='update' to overwrite"
                            ),
                        }
                    )
                    conflict_count += 1
                    continue

                # Value already taken by a DIFFERENT member name (non-bitfield).
                if not bitfield:
                    clash = next(
                        (n for n, v in current.items() if v == value and n != member_name),
                        None,
                    )
                    if clash is not None:
                        member_results.append(
                            {
                                "name": member_name,
                                "value": value,
                                "error": f"Enum value conflict: {value} already belongs to {clash}",
                            }
                        )
                        conflict_count += 1
                        continue

                # New member: append a fresh edm with the CORRECT mask.
                edm = ida_typeinf.edm_t()
                edm.name = member_name
                edm.value = value
                try:
                    edm.bmask = _enum_member_mask(value, bitfield)
                except Exception:
                    pass
                etd.push_back(edm)
                current[member_name] = value
                dirty = True
                member_results.append({"name": member_name, "value": value, "created": True})
                created_count += 1

            # Materialize the enum tinfo and (re)save it under enum_name.
            if dirty or created:
                new_tif = ida_typeinf.tinfo_t()
                if not new_tif.create_enum(etd):
                    results.append(
                        {
                            "name": enum_name,
                            "error": f"Failed to build enum tinfo for {enum_name}",
                        }
                    )
                    continue
                # set_named_type replaces in place; NTF_REPLACE allows update.
                ntf_replace = int(getattr(ida_typeinf, "NTF_REPLACE", 0x20))
                rc = new_tif.set_named_type(None, enum_name, ntf_replace)
                terr_ok = int(getattr(ida_typeinf, "TERR_OK", 0))
                ok_save = rc == 0 or rc == terr_ok
                if not ok_save:
                    results.append(
                        {
                            "name": enum_name,
                            "error": f"Failed to save enum {enum_name}: rc={rc}",
                        }
                    )
                    continue

            enum_id = idaapi.BADADDR
            try:
                lookup = ida_typeinf.tinfo_t()
                if lookup.get_named_type(None, enum_name):
                    enum_id = lookup.get_tid()
            except Exception:
                pass

            result_dict: dict = {
                "name": enum_name,
                "enum_id": hex(enum_id) if enum_id != idaapi.BADADDR else None,
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

    RETURNS: One entry per request: {addr, struct, members:[{offset,type,name,size,value,repr,kind}]} or {..., error}. Members are decoded per their declared type via typeutils.decode_typed_value: signed ints show decimal, floats/doubles as floats, bools as true/false, enums as the member name, char arrays as a string preview, pointers as hex, nested structs one level deep, and bitfields gain bit_offset/bit_width. 'kind' names the decode branch ('int'|'uint'|'float'|'double'|'bool'|'enum'|'pointer'|'char_array'|'array'|'udt'|'bitfield').

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

            endian = _db_endian()
            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_type = typeutils.type_str(member.type)
                member_name = member.name
                member_size = member.type.get_size()
                member_addr = addr + offset

                # Bitfield members: decode bits from the storage unit using the
                # typeutils bitfield layout (bit offset/width preserve sub-byte
                # precision instead of collapsing several bitfields into a byte).
                if typeutils._is_bitfield_member(member):
                    bl = typeutils.bitfield_layout(member)
                    bit_off = bl["bit_offset"]
                    bit_w = bl["bit_width"]
                    # Storage byte span covering the bitfield, relative to addr.
                    start_byte = bit_off // 8
                    end_byte = (bit_off + bit_w + 7) // 8
                    try:
                        unit = read_bytes_bss_safe(
                            addr + start_byte, max(end_byte - start_byte, 1)
                        )
                        local_off = bit_off - start_byte * 8
                        bits = typeutils._extract_bits(unit, local_off, bit_w, endian)
                        value_str = f"0x{bits:X} ({bits})"
                    except Exception:
                        bits = 0
                        value_str = "<failed to read>"
                    members.append(
                        {
                            "offset": f"0x{offset:08X}",
                            "type": member_type,
                            "name": member_name,
                            "size": member_size,
                            "value": value_str,
                            "repr": value_str,
                            "kind": "bitfield",
                            "bit_offset": bit_off,
                            "bit_width": bit_w,
                        }
                    )
                    continue

                # Read memory value at member address (BSS-aware: unloaded
                # bytes resolve to zero, matching runtime zero-init).
                try:
                    read_size = member_size if member_size else 0
                    if member.type.is_ptr() and not read_size:
                        read_size = 8 if compat.inf_is_64bit() else 4
                    raw = read_bytes_bss_safe(member_addr, read_size) if read_size else b""
                    dec = typeutils.decode_typed_value(member.type, raw, endian=endian)
                    value_repr = dec.get("repr", "")
                    member_kind = dec.get("kind", "")
                except Exception:
                    value_repr = "<failed to read>"
                    member_kind = ""

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
                    "value": value_repr,
                    "repr": value_repr,
                    "kind": member_kind,
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


def _project_members(
    tif: ida_typeinf.tinfo_t, max_members: int
) -> tuple[list[dict], int, bool]:
    """Project a type's members into a uniform list for catalog/inspect output.

    Handles both UDTs (struct/union, incl. bitfield bit offset/width) and ENUMs
    (member name/value via typeutils.enum_members - member_count was 0 before).
    Typedef-to-UDT/enum targets are resolved via typeutils.resolve_typedef so a
    typedef'd struct still reports its members.

    Returns (members, member_count, truncated).
    """
    members: list[dict] = []
    member_count = 0
    truncated = False

    target = typeutils.resolve_typedef(tif)

    # --- ENUM members (9.x edm_t API via typeutils) ------------------------
    try:
        is_enum = bool(target.is_enum())
    except Exception:
        is_enum = False
    if is_enum:
        edms = typeutils.enum_members(target)
        member_count = len(edms)
        for idx, m in enumerate(edms):
            if idx >= max_members:
                truncated = True
                break
            row = {
                "name": m.get("name", ""),
                "value": m.get("value", 0),
            }
            if "mask" in m:
                row["mask"] = m["mask"]
            members.append(row)
        return members, member_count, truncated

    # --- UDT members --------------------------------------------------------
    try:
        is_udt = bool(target.is_udt())
    except Exception:
        is_udt = False
    if is_udt:
        udt = ida_typeinf.udt_type_data_t()
        if target.get_udt_details(udt):
            member_count = len(udt)
            for idx, member in enumerate(udt):
                if idx >= max_members:
                    truncated = True
                    break
                row = {
                    "name": member.name,
                    "offset": hex(member.begin() // 8),
                    "size": member.type.get_size(),
                    "type": typeutils.type_str(member.type),
                }
                if typeutils._is_bitfield_member(member):
                    bl = typeutils.bitfield_layout(member)
                    row["bit_offset"] = bl["bit_offset"]
                    row["bit_width"] = bl["bit_width"]
                members.append(row)

    return members, member_count, truncated


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

    RETURNS: One result per query: {kind, data:[rows], next_offset, total}. Each row carries ordinal/name/size/kind plus optional declaration, member_count/members(+members_truncated), and related_count/related_types(+related_truncated) depending on the include_* flags. Members cover both UDTs (offset/size/type, +bit_offset/bit_width for bitfields) and ENUMs (name/value, +mask for bitmask enums).

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
                members, member_count, members_truncated = _project_members(
                    tif, max_members
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

    PITFALL: Matching is EXACT (not substring) - use search_structs/type_query to find the right name first. max_members is clamped to [0,4096] and silently truncates a larger type (members_truncated=true). Members are populated for both UDTs (offset/size/type, plus bit_offset/bit_width for bitfields) and ENUMs (name/value, plus mask for bitmask enums); typedef targets are resolved so a typedef'd struct/enum still reports its members.
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

            # Resolve typedef target so a typedef'd enum/struct reports kind +
            # members honestly instead of looking empty.
            resolved = typeutils.resolve_typedef(tif)
            try:
                if resolved is not tif and not info["is_enum"] and not info["is_udt"]:
                    info["is_enum"] = bool(resolved.is_enum())
                    info["is_udt"] = bool(resolved.is_udt())
            except Exception:
                pass

            if include_members:
                members, member_count, members_truncated = _project_members(
                    tif, max_members
                )
                info["member_count"] = member_count
                if members:
                    info["members"] = members
                info["members_truncated"] = members_truncated

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


def _current_type_at(ea: int) -> str | None:
    """Best-effort current applied type at an address, as a string (or None)."""
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea):
            return typeutils.type_str(tif)
    except Exception:
        pass
    return None


def _current_lvar_type(func_ea: int, var_name: str) -> str | None:
    """Current decompiler local variable type, as a string (or None)."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return None
        for lv in cfunc.get_lvars():
            if lv.name == var_name:
                return typeutils.type_str(lv.type())
    except Exception:
        pass
    return None


def _apply_type_edit(edit: dict[str, Any], dry_run: bool = False) -> SetTypeResult:
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
            if dry_run:
                return {
                    "edit": edit,
                    "kind": kind,
                    "preview": True,
                    "ok": True,
                    "current": _current_type_at(func.start_ea),
                    "new": typeutils.type_str(tif),
                }
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
            if dry_run:
                return {
                    "edit": edit,
                    "kind": kind,
                    "preview": True,
                    "ok": True,
                    "current": _current_type_at(ea),
                    "new": typeutils.type_str(tif),
                }
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

            if dry_run:
                return {
                    "edit": edit,
                    "kind": kind,
                    "preview": True,
                    "ok": True,
                    "current": _current_lvar_type(func.start_ea, var_name),
                    "new": typeutils.type_str(new_tif),
                }

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
            cur_udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(cur_udm, tid)
            offset = cur_udm.offset // 8

            tif = _parse_type_tinfo(type_text)
            if dry_run:
                cur_str = None
                try:
                    cur_str = typeutils.type_str(cur_udm.type)
                except Exception:
                    cur_str = None
                return {
                    "edit": edit,
                    "kind": kind,
                    "preview": True,
                    "ok": True,
                    "current": cur_str,
                    "new": typeutils.type_str(tif),
                }
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

    WHEN TO USE: Stamp types onto the IDB after declaring them (declare_type). For a function pass its full signature; for a global pass a name or address + type; for a Hex-Rays local pass addr + variable + type; for a frame slot pass addr + name + type. Set 'dry_run': true (or 'preview': true) on an edit to RESOLVE and report current->new WITHOUT applying.

    RETURNS: One entry per edit: {edit, kind, ok} on success, or {..., error} with a kind-specific message (e.g. function/global not found, local var missing, referenced type not declared). A dry-run entry adds {preview:true, current, new} and applies nothing.

    PITFALL: Every referenced type must already exist in the local type library or the apply fails - declare_type first. Kind inference is heuristic: addr+name resolves to 'stack' only when that name is a real frame member, otherwise it falls through to 'global'; set 'kind' explicitly to remove ambiguity. After a real (non-preview) apply the decompile cache for the target is invalidated automatically. For atomic multi-edit application with stop-on-error and an aggregate summary, prefer type_apply_batch.
    """
    normalized_edits = normalize_dict_list(edits, _parse_addr_type_shorthand)
    return [
        _apply_type_edit(
            edit, dry_run=bool(edit.get("dry_run") or edit.get("preview"))
        )
        for edit in normalized_edits
    ]


@safety("DESTRUCTIVE")
@title("Apply Types (Batch)")
@tool
@idasync
def type_apply_batch(
    batch: Annotated[
        TypeApplyBatch,
        "{'edits': [<TypeEdit>, ...], 'stop_on_error': <bool, optional>, "
        "'dry_run': <bool, optional>}. Each edit uses the same shape as set_type "
        "(function/global/local/stack); 'addr:typename' shorthand is accepted. "
        "dry_run resolves + reports current->new for every edit without applying.",
    ],
) -> TypeApplyBatchResult:
    """WHAT: Apply many type edits in one call (same per-edit semantics as set_type) and return a rolled-up status with per-edit detail.

    WHEN TO USE: Stamp a whole recovered cluster of types at once and get an aggregate pass/fail count. Set stop_on_error to halt at the first failure (e.g. when later edits depend on earlier ones succeeding). Set dry_run to PREVIEW the whole batch (resolve + current->new) without mutating the IDB.

    RETURNS: {ok (all succeeded), applied, failed, stopped (true iff stop_on_error halted early), preview, results:[<SetTypeResult>...]}. In dry_run mode each result carries {preview:true, current, new} and 'applied' counts previews that resolved.

    PITFALL: This is NOT transactional - edits already applied before a failure stay applied even when stop_on_error halts the rest, so re-running may re-apply some. All referenced types must be declared first (declare_type). For a single edit, set_type is simpler.
    """
    normalized_edits = normalize_dict_list(
        batch.get("edits", []), _parse_addr_type_shorthand
    )
    stop_on_error = bool(batch.get("stop_on_error", False))
    dry_run = bool(batch.get("dry_run", False))

    results: list[dict] = []
    for edit in normalized_edits:
        edit_dry = dry_run or bool(edit.get("dry_run") or edit.get("preview"))
        result = _apply_type_edit(edit, dry_run=edit_dry)
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
        "preview": dry_run,
        "results": results,
    }


def _infer_string_type(ea: int) -> dict | None:
    """If `ea` is a string literal, propose char[N] / wchar based on strtype."""
    try:
        flags = ida_bytes.get_flags(ea)
    except Exception:
        return None
    try:
        if not ida_bytes.is_strlit(flags):
            return None
    except Exception:
        return None
    try:
        strtype = ida_nalt.get_str_type(ea)
    except Exception:
        strtype = 0
    try:
        n = ida_bytes.get_max_strlit_length(ea, strtype) if hasattr(ida_bytes, "get_max_strlit_length") else 0
    except Exception:
        n = 0
    if n <= 0:
        try:
            n = ida_bytes.get_item_size(ea)
        except Exception:
            n = 0
    # Wide-string subtypes report a non-1 char width.
    is_wide = False
    try:
        width = ida_nalt.get_strtype_bpu(strtype) if hasattr(ida_nalt, "get_strtype_bpu") else 1
        is_wide = int(width) > 1
    except Exception:
        is_wide = False
    base = "wchar_t" if is_wide else "char"
    inferred = f"{base}[{n}]" if n > 0 else f"{base}[]"
    return {
        "inferred_type": inferred,
        "method": "strlit",
        "confidence": "high",
        "detail": "address is a string literal (is_strlit)",
    }


def _infer_pointer_or_coderef(ea: int) -> dict | None:
    """Propose a pointer type when the item holds a code/data reference.

    Reads a pointer-width word and checks whether it targets a known function
    (-> function pointer) or any defined item (-> typed pointer). This catches
    globals that the size heuristic would mislabel as a bare uint64_t.
    """
    ptr_size = 8 if compat.inf_is_64bit() else 4
    try:
        size = ida_bytes.get_item_size(ea)
    except Exception:
        size = 0
    if size and size != ptr_size:
        return None
    if not ida_bytes.is_loaded(ea):
        return None
    target = read_int_bss_safe(ea, ptr_size)
    if target == 0 or not ida_bytes.is_loaded(target):
        return None
    # Function pointer?
    func = idaapi.get_func(target)
    if func and func.start_ea == target:
        ftif = compat.get_func_prototype(func)
        if ftif is not None:
            sig = typeutils.type_str(ftif)
            return {
                "inferred_type": f"{sig} *" if sig else "void (*)()",
                "method": "code_ref",
                "confidence": "medium",
                "detail": f"points to function at {hex(target)}",
            }
        return {
            "inferred_type": "void (*)()",
            "method": "code_ref",
            "confidence": "medium",
            "detail": f"points to code at {hex(target)}",
        }
    # Data pointer to a typed item?
    ttif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(ttif, target):
        pointed = typeutils.type_str(ttif)
        if pointed:
            return {
                "inferred_type": f"{pointed} *",
                "method": "data_ref",
                "confidence": "medium",
                "detail": f"points to typed item at {hex(target)}",
            }
    return {
        "inferred_type": "void *",
        "method": "data_ref",
        "confidence": "low",
        "detail": f"holds a pointer-width reference to {hex(target)}",
    }


def _infer_array_of_struct(ea: int) -> dict | None:
    """If the item size is a whole multiple (>=2) of a struct at `ea`, propose T[N]."""
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        return None
    target = typeutils.resolve_typedef(tif)
    try:
        if not target.is_udt():
            return None
        elem_size = int(target.get_size())
    except Exception:
        return None
    if elem_size <= 0:
        return None
    try:
        item_size = ida_bytes.get_item_size(ea)
    except Exception:
        item_size = 0
    if item_size >= elem_size * 2 and item_size % elem_size == 0:
        name = target.get_type_name() or typeutils.type_str(target)
        n = item_size // elem_size
        return {
            "inferred_type": f"{name}[{n}]",
            "method": "array_of_struct",
            "confidence": "medium",
            "detail": f"{item_size} bytes == {n} x {name} ({elem_size}B)",
        }
    return None


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
    """WHAT: Suggest the most likely type at each address using HONEST, ranked detectors: an already-applied type, a string literal (is_strlit), a code/data-reference pointer, an array-of-struct, IDA's heuristic type guess, then a last-resort size->uintN_t guess - each tagged with its real method and confidence.

    WHEN TO USE: Get a starting-point type for an untyped global/data item before committing it. This is advisory ONLY.

    RETURNS: One entry per address: {addr, inferred_type, method ('existing'|'strlit'|'code_ref'|'data_ref'|'array_of_struct'|'guess'|'size_based'|null), confidence ('high'|'medium'|'low'|'none'), detail} (+ error on failure).

    PITFALL: Despite the action's name this does NOT modify the IDB - it only proposes a type. The IDA heuristic guess is labeled method='guess'/confidence='medium' (NOT 'hexrays'/'high') because it is a best-effort inference, not a decompiler-verified type. A known ASCII string is reported as char[N] (method='strlit'), not uint8_t[N]. 'size_based'/'low' guesses only map item size to a uintN_t - treat skeptically. A 'none' confidence with null type means nothing could be inferred.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # 1) Existing applied type wins (decompiler/user authoritative).
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": typeutils.type_str(tif),
                        "method": "existing",
                        "confidence": "high",
                        "detail": "type already applied at address",
                    }
                )
                continue

            # 2) String literal -> char[N] / wchar_t[N], NOT uint8_t[N].
            strres = _infer_string_type(ea)
            if strres is not None:
                strres["addr"] = addr
                results.append(strres)
                continue

            # 3) Array of an existing struct (item spans N elements).
            arrres = _infer_array_of_struct(ea)
            if arrres is not None:
                arrres["addr"] = addr
                results.append(arrres)
                continue

            # 4) Pointer-width word referencing code/data -> pointer type.
            ptrres = _infer_pointer_or_coderef(ea)
            if ptrres is not None:
                ptrres["addr"] = addr
                results.append(ptrres)
                continue

            # 5) IDA's heuristic guess - relabeled honestly (NOT hexrays/high).
            guess = ida_typeinf.tinfo_t()
            if compat.guess_tinfo(guess, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": typeutils.type_str(guess),
                        "method": "guess",
                        "confidence": "medium",
                        "detail": "IDA heuristic type guess (not decompiler-verified)",
                    }
                )
                continue

            # 6) Last resort: map raw item size to a scalar.
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
                        "detail": f"size-only guess from {size}-byte item",
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


# ============================================================================
# Struct field-level editing (9.x udt_type_data_t API)
# ============================================================================


class StructMemberEditResult(TypedDict, total=False):
    struct: str
    op: str
    member: str
    new_name: str
    new_type: str
    offset: str
    ok: bool
    error: str


def _save_udt(tif: ida_typeinf.tinfo_t, name: str) -> tuple[bool, str | None]:
    """Re-save a mutated UDT tinfo under `name` (NTF_REPLACE). (ok, err)."""
    ntf_replace = int(getattr(ida_typeinf, "NTF_REPLACE", 0x20))
    try:
        rc = tif.set_named_type(None, name, ntf_replace)
    except Exception as exc:
        return False, str(exc)
    if rc == 0:
        return True, None
    terr_ok = getattr(ida_typeinf, "TERR_OK", 0)
    if rc == terr_ok:
        return True, None
    return False, f"set_named_type rc={rc}"


@safety("DESTRUCTIVE")
@title("Edit Struct Members")
@tool
@idasync
def struct_member_edit(
    edits: Annotated[
        list[dict] | dict,
        "One or more member edits. Each: {'struct': <struct name>, 'op': "
        "'add'|'rename'|'retype'|'stamp_array', ...}. add -> {member, type, "
        "offset?(bit-append if omitted)}; rename -> {member, new_name}; retype "
        "-> {member, type}; stamp_array -> {member, type(element), count}.",
    ],
) -> list[StructMemberEditResult]:
    """WHAT: Field-level edits to an existing local struct - add a member, rename one, change a member's type, or stamp a member as an element-type[count] array - all on the IDA 9.x udt_type_data_t tinfo API (IDB metadata only; never touches binary bytes).

    WHEN TO USE: Iteratively refine a recovered struct after declare_type: name a field you understood, widen a placeholder to its real type, or turn a run of bytes into an array. For wholesale (re)definition prefer declare_type with a full C decl.

    RETURNS: One entry per edit: {struct, op, member, ok, offset, new_name?/new_type?} on success or {..., error}. Adding at an offset that overlaps an existing member, or referencing an undeclared type, surfaces as an error.

    PITFALL: All referenced element/member types must already exist (declare_type first). 'add' without an explicit offset appends at the end of the struct; with an offset it must land on a free, correctly-sized slot. This rewrites the named struct type in place via NTF_REPLACE, so any address already typed with it re-renders - the decompile cache is invalidated automatically. stamp_array replaces the member's type with type[count]; count must be >= 1.
    """
    edits = normalize_dict_list(edits)
    results: list[dict] = []

    for edit in edits:
        struct_name = str(edit.get("struct", "") or "").strip()
        op = str(edit.get("op", "") or "").strip().lower()
        member_name = str(edit.get("member", "") or "").strip()

        if not struct_name:
            results.append({"struct": struct_name, "op": op, "error": "struct name is required"})
            continue
        if op not in {"add", "rename", "retype", "stamp_array"}:
            results.append({"struct": struct_name, "op": op, "error": f"unknown op: {op!r}"})
            continue

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append({"struct": struct_name, "op": op, "error": f"struct not found: {struct_name}"})
                continue
            if not tif.is_udt():
                results.append({"struct": struct_name, "op": op, "error": f"not a struct/union: {struct_name}"})
                continue

            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                results.append({"struct": struct_name, "op": op, "error": "failed to read struct details"})
                continue

            # Locate target member (not required for plain 'add').
            target_idx = -1
            for i, m in enumerate(udt):
                if m.name == member_name:
                    target_idx = i
                    break

            if op == "add":
                new_type_text = _resolve_type_text(edit) or str(edit.get("type", "")).strip()
                if not new_type_text:
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "type is required for add"})
                    continue
                if not member_name:
                    results.append({"struct": struct_name, "op": op, "error": "member name is required for add"})
                    continue
                if target_idx != -1:
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "member already exists"})
                    continue
                mtif = _parse_type_tinfo(new_type_text)
                new_udm = ida_typeinf.udm_t()
                new_udm.name = member_name
                new_udm.type = mtif
                try:
                    new_udm.size = int(mtif.get_size()) * 8  # bit size
                except Exception:
                    pass
                offset_text = str(edit.get("offset", "") or "").strip()
                if offset_text:
                    byte_off = int(offset_text, 0)
                    new_udm.offset = byte_off * 8
                    # Reject an offset that collides with an existing member.
                    collide = any(
                        m.offset == new_udm.offset for m in udt
                    )
                    if collide:
                        results.append({"struct": struct_name, "op": op, "member": member_name, "error": f"offset {offset_text} overlaps an existing member"})
                        continue
                    # add_udm honors the udm.offset when it is set.
                    udt.add_udm(new_udm)
                else:
                    udt.push_back(new_udm)
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT if not udt.is_union else ida_typeinf.BTF_UNION)
                ok, err = _save_udt(tif, struct_name)
                res = {"struct": struct_name, "op": op, "member": member_name, "new_type": new_type_text, "ok": ok}
                if not ok:
                    res["error"] = err
                else:
                    bump_decompile_dirty(None)
                results.append(res)
                continue

            if target_idx == -1:
                results.append({"struct": struct_name, "op": op, "member": member_name, "error": "member not found"})
                continue

            member = udt[target_idx]
            offset_str = hex(member.begin() // 8)

            if op == "rename":
                new_name = str(edit.get("new_name", "") or "").strip()
                if not new_name:
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "new_name is required"})
                    continue
                member.name = new_name
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT if not udt.is_union else ida_typeinf.BTF_UNION)
                ok, err = _save_udt(tif, struct_name)
                res = {"struct": struct_name, "op": op, "member": member_name, "new_name": new_name, "offset": offset_str, "ok": ok}
                if not ok:
                    res["error"] = err
                else:
                    bump_decompile_dirty(None)
                results.append(res)
                continue

            if op == "retype":
                new_type_text = _resolve_type_text(edit) or str(edit.get("type", "")).strip()
                if not new_type_text:
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "type is required for retype"})
                    continue
                mtif = _parse_type_tinfo(new_type_text)
                member.type = mtif
                try:
                    member.size = int(mtif.get_size()) * 8
                except Exception:
                    pass
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT if not udt.is_union else ida_typeinf.BTF_UNION)
                ok, err = _save_udt(tif, struct_name)
                res = {"struct": struct_name, "op": op, "member": member_name, "new_type": new_type_text, "offset": offset_str, "ok": ok}
                if not ok:
                    res["error"] = err
                else:
                    bump_decompile_dirty(None)
                results.append(res)
                continue

            if op == "stamp_array":
                elem_text = _resolve_type_text(edit) or str(edit.get("type", "")).strip()
                count = int(edit.get("count", 0) or 0)
                if count < 1:
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "count must be >= 1"})
                    continue
                # If no element type given, array-of-current member type.
                if elem_text:
                    elem_tif = _parse_type_tinfo(elem_text)
                else:
                    elem_tif = member.type
                arr_tif = ida_typeinf.tinfo_t()
                if not arr_tif.create_array(elem_tif, count):
                    results.append({"struct": struct_name, "op": op, "member": member_name, "error": "failed to build array type"})
                    continue
                member.type = arr_tif
                try:
                    member.size = int(arr_tif.get_size()) * 8
                except Exception:
                    pass
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT if not udt.is_union else ida_typeinf.BTF_UNION)
                ok, err = _save_udt(tif, struct_name)
                res = {
                    "struct": struct_name,
                    "op": op,
                    "member": member_name,
                    "new_type": f"{typeutils.type_str(elem_tif)}[{count}]",
                    "offset": offset_str,
                    "ok": ok,
                }
                if not ok:
                    res["error"] = err
                else:
                    bump_decompile_dirty(None)
                results.append(res)
                continue

        except Exception as exc:
            results.append({"struct": struct_name, "op": op, "member": member_name, "error": str(exc)})

    return results


# ============================================================================
# Type library (TIL) loading / listing
# ============================================================================


class AddTilResult(TypedDict, total=False):
    name: str
    loaded: bool
    error: str


class ListTilResult(TypedDict, total=False):
    name: str
    description: str


@safety("DESTRUCTIVE")
@title("Load Type Library")
@tool
@idasync
def add_til(
    names: Annotated[
        list[str] | str,
        "One or more type-library (TIL) base names to load, e.g. 'mssdk64', "
        "'gnulnx_x64', 'vc10_64'. Omit the '.til' extension.",
    ],
) -> list[AddTilResult]:
    """WHAT: Load a named IDA type library (TIL) into the IDB so its WinAPI / libc / SDK structs, typedefs and function prototypes become available to declare_type/set_type/type_inspect.

    WHEN TO USE: Before applying platform types you have not declared by hand (e.g. you need _RTL_CRITICAL_SECTION or a Win32 prototype). Pair with list_tils to discover which libraries IDA ships for this target.

    RETURNS: One entry per name: {name, loaded:true} on success or {name, loaded:false, error}. Loading an already-loaded library is reported as loaded:true (idempotent).

    PITFALL: TIL base names are platform/compiler specific - a 64-bit MSVC target wants 'mssdk64'/'vc10_64', a Linux target 'gnulnx_x64'; loading a mismatched library pulls in wrong-width types. This adds the library to the IDB but does NOT auto-apply any type - follow up with type_inspect to confirm a needed type now resolves, then set_type to stamp it.
    """
    names = normalize_list_input(names)
    results: list[dict] = []

    for name in names:
        base = str(name or "").strip()
        if not base:
            results.append({"name": base, "loaded": False, "error": "til name is required"})
            continue
        if base.lower().endswith(".til"):
            base = base[:-4]
        try:
            # add_default_til loads a library by name into the IDB's idati.
            rc = ida_typeinf.add_default_til(base)
            # rc: ADDTIL_OK(1)/ADDTIL_COMP(2) on success, ADDTIL_FAILED(0).
            loaded = bool(rc)
            res = {"name": base, "loaded": loaded}
            if not loaded:
                res["error"] = f"failed to load til: {base}"
            else:
                # New library types can change pseudocode rendering everywhere.
                bump_decompile_dirty(None)
            results.append(res)
        except Exception as exc:
            results.append({"name": base, "loaded": False, "error": str(exc)})

    return results


@safety("READ")
@title("List Loaded Type Libraries")
@tool
@idasync
def list_tils() -> list[ListTilResult]:
    """WHAT: List the type libraries (TILs) currently loaded into this IDB, with their human-readable descriptions.

    WHEN TO USE: Check whether the SDK/libc library you need is already loaded before calling add_til, or audit which platform types are in scope for set_type/declare_type.

    RETURNS: A list of {name, description} for each loaded library (the base library plus any added via add_til). Empty list if none are loaded.

    PITFALL: This reflects loaded LIBRARIES, not individual types - use type_query/type_inspect to enumerate the actual types a library contributed. A library appearing here does not guarantee a specific type name exists in it (compiler/version variants differ).
    """
    results: list[dict] = []
    try:
        idati = ida_typeinf.get_idati()
    except Exception:
        return results

    # The base idati plus its chained 'bases'. Walk what the SDK exposes.
    seen: set[str] = set()

    def _emit(til) -> None:
        if til is None:
            return
        try:
            name = getattr(til, "name", "") or ""
        except Exception:
            name = ""
        if not name or name in seen:
            return
        seen.add(name)
        try:
            desc = getattr(til, "desc", "") or ""
        except Exception:
            desc = ""
        results.append({"name": name, "description": desc})

    _emit(idati)
    try:
        nbases = idati.nbases() if hasattr(idati, "nbases") else 0
        for i in range(nbases):
            _emit(idati.base(i))
    except Exception:
        pass

    return results
