"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import re
from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_nalt
import idaapi

from .rpc import tool, safety, title
from .sync import idasync
from .consent import (
    capture_original,
    patch_decision,
    patching_allowed,
    revert_span,
    span_status,
    withheld_hint,
)
from .utils import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
    normalize_list_input,
    parse_address,
    read_bytes_bss_safe,
    read_int_bss_safe,
)


class BytesReadResult(TypedDict):
    addr: str | None
    data: str | None
    error: NotRequired[str]


class IntReadResult(TypedDict):
    addr: str
    ty: str
    value: int | None
    error: NotRequired[str]


class StringReadResult(TypedDict):
    addr: str
    value: str | None
    encoding: NotRequired[str]  # detected encoding (e.g. "utf-8", "utf-16-le", "pascal-utf-8")
    error: NotRequired[str]


class GlobalValueResult(TypedDict):
    query: str
    value: str | None
    error: NotRequired[str]


class PatchResult(TypedDict):
    addr: str | None
    size: int
    error: NotRequired[str]


class IntWriteResult(TypedDict):
    addr: str
    ty: str
    value: str | None
    error: NotRequired[str]


class PatchItemResult(TypedDict, total=False):
    addr: str | None
    size: int
    original: str  # hex of the bytes currently at addr (pre-write)
    new: str  # hex of the bytes that were / would be written
    applied: bool  # whether THIS item was actually written
    ty: str  # put_int only: normalized integer class
    value: str  # put_int only: echoed value
    error: str


class PatchResponse(TypedDict, total=False):
    applied: bool  # whether ANY byte was actually written this call
    dry_run: bool
    allowed: bool  # server-level patch gate state
    reason: str  # ok | dry_run | confirm_required | server_gate_closed
    consent: str  # guidance shown when the write was withheld
    results: list[PatchItemResult]


class RevertResult(TypedDict, total=False):
    addr: str
    reverted: int  # count of bytes restored to their original value
    error: str


class PatchListEntry(TypedDict):
    addr: str
    original: str  # hex original byte
    patched: str  # hex current (patched) byte


class PatchListResult(TypedDict, total=False):
    count: int
    patches: list[PatchListEntry]
    truncated: bool


# ============================================================================
# Memory Reading Operations
# ============================================================================


@safety("READ")
@title("Read Raw Bytes")
@tool
@idasync
def get_bytes(
    regions: Annotated[
        list[MemoryRead] | MemoryRead,
        "One or more {addr, size} read requests; a single dict is accepted and wrapped",
    ],
) -> list[BytesReadResult]:
    """Read raw bytes from one or more memory regions, returned as hex text.

    WHAT: For each {addr, size} region, reads `size` bytes starting at `addr`
    and returns them as a space-separated hex string (e.g. "0x4d 0x5a ..").
    Reads are BSS-safe (uninitialized .bss bytes come back as zeros instead of
    failing).
    WHEN-TO-USE: Dumping an opcode/struct blob, sampling a buffer, or any time
    you need exact byte values rather than a decoded integer or string.
    RETURNS: One result per region, in input order: {addr, data} on success or
    {addr, data: null, error} on failure. Per-region failures never abort the
    batch.
    PITFALL: `data` is a hex STRING, not a byte array; parse it before doing
    arithmetic. For typed scalar reads prefer get_int (handles width/signedness/
    endianness); reserve this for opaque byte spans.
    """
    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            raw = read_bytes_bss_safe(ea, size)
            data = " ".join(f"{x:#02x}" for x in raw)
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    explicit = match.group("endian")  # "le" | "be" | None
    if explicit:
        # An explicit suffix is authoritative regardless of DB byte order.
        byte_order = "little" if explicit == "le" else "big"
        endian = explicit
    else:
        # No suffix: honor the database's recorded byte order (idaapi inf is_be).
        byte_order = _db_byte_order()
        endian = "be" if byte_order == "big" else "le"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _parse_int_value(text: str, signed: bool, bits: int) -> int:
    if text is None:
        raise ValueError("Missing integer value")

    value_text = str(text).strip()
    try:
        value = int(value_text, 0)
    except ValueError:
        raise ValueError(f"Invalid integer value: {text}")

    if not signed and value < 0:
        raise ValueError(f"Negative value not allowed for u{bits}")

    return value


def _db_byte_order() -> str:
    """Database default byte order ("big" or "little") per idaapi inf.

    Used when an integer class carries no explicit le|be suffix so reads/writes
    honor the analysed image's endianness instead of always assuming little.
    Falls back to "little" if the inf flag cannot be queried. Mirrors the
    robust probe in api_types._db_endian (ida_ida first, then idaapi).
    """
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


# STRTYPE low-byte layout (IDA SDK):
#   STRWIDTH mask (bits 0-1): character width / encoding selector
#       0 -> 1 byte (C/UTF-8), 1 -> 2 byte (UTF-16), 2 -> 4 byte (UTF-32)
#   STRLYT  (bits 6-7, value = (strtype >> 6) & 3): 0 = terminated, >0 = Pascal
# Codecs are resolved from the width code; the DB byte order picks LE/BE for the
# multi-byte forms.
_STR_WIDTH_MASK = 0x03
_STR_LAYOUT_SHIFT = 6
_STR_LAYOUT_MASK = 0x03


def _strtype_codec(strtype: int) -> str:
    """Map a STRTYPE_* value to a Python codec name, honoring DB endianness."""
    width = strtype & _STR_WIDTH_MASK
    if width == 1:
        return "utf-16-be" if _db_byte_order() == "big" else "utf-16-le"
    if width == 2:
        return "utf-32-be" if _db_byte_order() == "big" else "utf-32-le"
    return "utf-8"


def _strtype_encoding_label(strtype: int) -> str:
    """Human-readable encoding label for a STRTYPE_* value (additive report)."""
    codec = _strtype_codec(strtype)
    layout = (strtype >> _STR_LAYOUT_SHIFT) & _STR_LAYOUT_MASK
    return f"pascal-{codec}" if layout else codec


@safety("READ")
@title("Read Typed Integers")
@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "One or more {ty, addr} read requests; ty selects width/sign/endianness "
        "(i8/u8/i16/u16/i32/u32/i64/u64, optional le|be suffix; without a suffix "
        "the database byte order is used); a single dict is accepted and wrapped",
    ],
) -> list[IntReadResult]:
    """Read width-, sign-, and endian-aware integers from memory.

    WHAT: For each {ty, addr}, parses the `ty` class to derive byte width,
    signedness, and byte order, reads that many bytes (BSS-safe), and decodes a
    Python int. When `ty` has no le|be suffix the database byte order (idaapi
    inf is_be) is used, so a big-endian image reads big-endian by default. `ty`
    is normalized in the result to the byte order actually used (e.g. on a
    little-endian DB "u32" -> "u32le", on a big-endian DB "u32" -> "u32be").
    WHEN-TO-USE: Reading a scalar field at a known offset (length prefix, flag
    word, pointer-sized value) when you want the decoded number, not raw bytes.
    RETURNS: One result per query, in input order: {addr, ty, value} on success
    (ty is the normalized class) or {addr, ty, value: null, error} on failure.
    PITFALL: An explicit suffix is always authoritative; pass "u32be" to force
    big-endian (e.g. network byte order) regardless of the database byte order,
    or "u32le" to force little. Unsigned classes always yield a non-negative
    value.
    """
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for item in queries:
        addr = item.get("addr", "")
        ty = item.get("ty", "")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            ea = parse_address(addr)
            size = bits // 8
            data = read_bytes_bss_safe(ea, size)
            if len(data) != size:
                raise ValueError(f"Failed to read {size} bytes at {addr}")

            value = int.from_bytes(data, byte_order, signed=signed)
            results.append(
                {"addr": addr, "ty": normalized, "value": value}
            )
        except Exception as e:
            results.append({"addr": addr, "ty": ty, "value": None, "error": str(e)})

    return results


@safety("READ")
@title("Read String Literals")
@tool
@idasync
def get_string(
    addrs: Annotated[
        list[str] | str,
        "One or more addresses (hex or decimal) where a defined string literal "
        "starts; a single string is accepted and wrapped",
    ],
) -> list[StringReadResult]:
    """Read defined string literals from memory, encoding-aware.

    WHAT: For each address, detects IDA's string TYPE at that exact start address
    (ida_nalt.get_str_type) and decodes the literal per its STRTYPE_* class:
    C/UTF-8, UTF-16, UTF-32, or Pascal-length-prefixed forms. The multi-byte
    encodings follow the database byte order. Undecodable bytes are replaced,
    never raising. The detected encoding is reported alongside the value.
    WHEN-TO-USE: Resolving a string pointer/xref target to its text, or reading
    a known string constant by address (including wide/UTF-16 strings).
    RETURNS: One result per address, in input order: {addr, value, encoding} on
    success or {addr, value: null, error} on failure ("No string at address"
    when IDA has no string item there). `encoding` names the detected codec
    (e.g. "utf-8", "utf-16-le", "pascal-utf-8").
    PITFALL: This reads only IDA's DEFINED string item at the precise address;
    it does not scan for an arbitrary null-terminated run, and an address in the
    middle of a string yields no result. When IDA has no string type recorded at
    the address the C/UTF-8 class is assumed; use get_bytes to recover the raw
    bytes for an exotic encoding (e.g. CP949) where replacement chars appear.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            strtype = ida_nalt.get_str_type(ea)
            if strtype is None or strtype < 0:
                strtype = ida_nalt.STRTYPE_C
            raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            codec = _strtype_codec(strtype)
            value = raw.decode(codec, errors="replace")
            results.append(
                {
                    "addr": addr,
                    "value": value,
                    "encoding": _strtype_encoding_label(strtype),
                }
            )
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


def _is_char_array(tif) -> bool:
    """True when ``tif`` is an array whose element is a (signed/unsigned) char."""
    try:
        if not tif.is_array():
            return False
    except Exception:
        return False
    try:
        elem = tif.get_array_element()
    except Exception:
        return False
    if elem is None:
        return False
    try:
        if elem.is_decl_char():
            return True
    except Exception:
        pass
    # Fallback: a 1-byte integral element behaves like a char array for display.
    try:
        return bool(elem.is_integral()) and int(elem.get_size()) == 1
    except Exception:
        return False


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    have_type = ida_nalt.get_tinfo(tif, ea)
    if not have_type:
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    # A char[] global renders as a quoted string. The previous guard required
    # size == 0, which never holds for a real char[N] (size N), so char arrays
    # fell through to the byte-dump branch. Decode as a string whenever the type
    # is a char array (size is irrelevant), honoring the recorded string type.
    if have_type and _is_char_array(tif):
        strtype = ida_nalt.get_str_type(ea)
        if strtype is None or strtype < 0:
            strtype = ida_nalt.STRTYPE_C
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
        if not raw:
            return '""'
        return_string = raw.decode(_strtype_codec(strtype), errors="replace").strip()
        return f'"{return_string}"'

    if size in (1, 2, 4, 8):
        return hex(read_int_bss_safe(ea, size))
    return " ".join(hex(b) for b in read_bytes_bss_safe(ea, size))


@safety("READ")
@title("Read Global Variable Values")
@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str,
        "One or more global variable references, each either an address (hex or "
        "decimal) or a symbol name; a single string is accepted and wrapped",
    ],
) -> list[GlobalValueResult]:
    """Read global variable values by address or symbol name, type-aware.

    WHAT: Resolves each query (address first when it looks like one, else a name
    lookup), then renders the value using the variable's declared type/size:
    char arrays come back as a quoted string, 1/2/4/8-byte scalars as a hex
    number, and anything else as space-separated hex bytes.
    WHEN-TO-USE: Inspecting a named global/config value or a data symbol without
    having to know its width up front; the symbol-name path saves resolving the
    address yourself.
    RETURNS: One result per query, in input order: {query, value} on success or
    {query, value: null, error} on failure ("Not found" when neither the address
    nor the name resolves).
    PITFALL: The rendering depends on IDA's type info for the symbol; an
    untyped/mis-sized global may render as a hex scalar or raw bytes rather than
    the logical value. When you need an exact width/sign decode, use get_int.
    """
    from .utils import looks_like_address

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@safety("PATCH")
@title("Patch Bytes")
@tool
@idasync
def patch(
    patches: Annotated[
        list[MemoryPatch] | MemoryPatch,
        "One or more {addr, data} patches; data is a hex byte string (spaces "
        "optional, e.g. '90 90' or '9090'); a single dict is accepted and wrapped",
    ],
    confirm: Annotated[
        bool,
        "Explicit consent to write. With confirm=false (default) the call only "
        "PREVIEWS (original vs new bytes); set confirm=true AND dry_run=false to apply.",
    ] = False,
    dry_run: Annotated[
        bool,
        "When true (default) the call previews and writes nothing. Set false "
        "(with confirm=true) to actually patch.",
    ] = True,
) -> PatchResponse:
    """Overwrite bytes of the analysed program, gated by explicit consent (PATCH).

    WHAT: For each {addr, data}, parses `data` as hex bytes, validates that every
    byte of the span is mapped, captures the current (original) bytes, and — only
    when the server patch gate is open AND confirm=true AND dry_run=false — writes
    the new bytes into the IDB at `addr`. Otherwise it returns a non-writing
    PREVIEW (original vs new) and touches nothing.
    WHEN-TO-USE: ONLY when the user has explicitly asked to patch the binary
    (e.g. NOP a check, flip a constant). Patching is never part of analysis; the
    default previews so that understanding a binary never mutates it (axis-7
    never-patch-without-consent rule).
    RETURNS: A PatchResponse {applied, dry_run, allowed, reason, consent?,
    results[]}. Each result is {addr, size, original, new, applied} on success or
    {addr, size:0, error}. `allowed` reflects the server gate
    (IDA_MCP_ALLOW_PATCH / set_patch_allowed); `reason` explains any withholding.
    PITFALL: Patching does NOT auto-align to instruction boundaries; a partial
    instruction leaves stale disassembly until re-analysed. Use revert_patch to
    undo and list_patches to review. To write a typed scalar (width/endianness
    handled) prefer put_int over hand-encoding hex here.
    """
    if isinstance(patches, dict):
        patches = [patches]

    will_write, reason = patch_decision(confirm, dry_run)
    results: list[dict] = []
    any_applied = False

    for item in patches:
        addr_str = item.get("addr") if isinstance(item, dict) else None
        try:
            ea = parse_address(item["addr"])
            data = bytes.fromhex(item["data"])
            size = len(data)
            if size == 0:
                raise ValueError("empty patch data")
            mapped, bad_ea = span_status(ea, size)
            if not mapped:
                raise ValueError(
                    f"Address span not fully mapped (first unmapped byte at "
                    f"{hex(bad_ea)} in {hex(ea)}..{hex(ea + size)})"
                )
            entry: dict = {
                "addr": item["addr"],
                "size": size,
                "original": capture_original(ea, size),
                "new": data.hex(),
                "applied": False,
            }
            if will_write:
                ida_bytes.patch_bytes(ea, data)
                entry["applied"] = True
                any_applied = True
            results.append(entry)
        except Exception as e:
            results.append({"addr": addr_str, "size": 0, "error": str(e)})

    response: dict = {
        "applied": any_applied,
        "dry_run": dry_run,
        "allowed": patching_allowed(),
        "reason": reason,
        "results": results,
    }
    if not will_write:
        response["consent"] = withheld_hint(reason)
    return response


@safety("PATCH")
@title("Write Typed Integers")
@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "One or more {ty, addr, value} writes; ty selects width/sign/endianness "
        "(i8/u8/.../u64, optional le|be; without a suffix the database byte order "
        "is used); value is a STRING decimal or 0x.. (negatives allowed for "
        "signed types); a single dict is accepted and wrapped",
    ],
    confirm: Annotated[
        bool,
        "Explicit consent to write. confirm=false (default) previews only; set "
        "confirm=true AND dry_run=false to apply.",
    ] = False,
    dry_run: Annotated[
        bool,
        "When true (default) previews and writes nothing; set false (with "
        "confirm=true) to actually write.",
    ] = True,
) -> PatchResponse:
    """Encode and write width-/sign-/endian-aware integers, gated by consent (PATCH).

    WHAT: For each {ty, addr, value}, parses the integer class and the string
    value, encodes it to the target width/byte order (rejecting out-of-range or
    wrongly-signed values), validates the span is mapped, captures the original
    bytes, and writes only when the patch gate is open AND confirm=true AND
    dry_run=false; otherwise PREVIEWS without writing.
    WHEN-TO-USE: Setting a scalar field/constant by its logical value (without
    hand-encoding hex), ONLY when the user explicitly asked to patch. Complements
    patch (raw bytes) and get_int (the read side).
    RETURNS: A PatchResponse {applied, dry_run, allowed, reason, consent?,
    results[]}; each result is {addr, ty, value, size, original, new, applied} on
    success or {addr, ty, value, error} on failure.
    PITFALL: `value` is a STRING ("0x10", "-5"). Without an le|be suffix the
    database byte order is used; pass an explicit be class for big-endian/network
    targets or le to force little regardless of the DB. Patching is withheld
    unless explicitly enabled and confirmed (axis-7 rule).
    """
    if isinstance(items, dict):
        items = [items]

    will_write, reason = patch_decision(confirm, dry_run)
    results: list[dict] = []
    any_applied = False

    for item in items:
        addr = item.get("addr", "")
        ty = item.get("ty", "")
        value_text = item.get("value")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            value = _parse_int_value(value_text, signed, bits)
            size = bits // 8
            try:
                data = value.to_bytes(size, byte_order, signed=signed)
            except OverflowError:
                raise ValueError(f"Value {value_text} does not fit in {normalized}")

            ea = parse_address(addr)
            mapped, bad_ea = span_status(ea, size)
            if not mapped:
                raise ValueError(
                    f"Address span not fully mapped (first unmapped byte at "
                    f"{hex(bad_ea)} in {hex(ea)}..{hex(ea + size)})"
                )
            entry: dict = {
                "addr": addr,
                "ty": normalized,
                "value": str(value_text),
                "size": size,
                "original": capture_original(ea, size),
                "new": data.hex(),
                "applied": False,
            }
            if will_write:
                ida_bytes.patch_bytes(ea, data)
                entry["applied"] = True
                any_applied = True
            results.append(entry)
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    "error": str(e),
                }
            )

    response: dict = {
        "applied": any_applied,
        "dry_run": dry_run,
        "allowed": patching_allowed(),
        "reason": reason,
        "results": results,
    }
    if not will_write:
        response["consent"] = withheld_hint(reason)
    return response


@safety("PATCH")
@title("Revert Patched Bytes")
@tool
@idasync
def revert_patch(
    addr: Annotated[str, "Address (hex like '0x401000' or a symbol) of the first byte to revert."],
    size: Annotated[int, "Number of bytes to revert starting at addr (default 1)."] = 1,
) -> RevertResult:
    """Restore previously-patched bytes to their ORIGINAL values (the patch undo).

    WHAT: Reverts IDA's recorded patched bytes over [addr, addr+size) back to the
    values they held before any patch, using IDA's native patched-byte store — so
    it can only ever RESTORE original content, never introduce new bytes. For that
    reason it is always permitted (it is the antidote to patching, not a patch).
    WHEN-TO-USE: To undo a patch applied via patch / put_int / patch_asm, or to
    clean up an experiment.
    RETURNS: {addr, reverted} where reverted is the count of bytes actually
    restored (bytes that were never patched are left untouched), or {addr,
    reverted:0, error} on a bad address.
    PRO-TIP: Call list_patches first to see exactly which bytes are patched.
    """
    try:
        ea = parse_address(addr)
    except Exception as e:
        return {"addr": addr, "reverted": 0, "error": str(e)}
    if size < 1:
        size = 1
    return {"addr": addr, "reverted": revert_span(ea, size)}


@safety("READ")
@title("List Patched Bytes")
@tool
@idasync
def list_patches(
    limit: Annotated[int, "Maximum patched bytes to report; clamped to 1..100000 (default 1000)."] = 1000,
) -> PatchListResult:
    """List every byte currently patched in the database (original vs current).

    WHAT: Enumerates IDA's patched-byte store across the whole image, reporting
    each location's original and current (patched) byte. This is the read side of
    the patch lifecycle and never mutates anything.
    WHEN-TO-USE: To audit what has been patched (before reverting, or to confirm a
    read-only workflow left the binary untouched — an empty list proves no bytes
    were patched).
    RETURNS: {count, patches:[{addr, original, patched}], truncated}; `truncated`
    is true when more patched bytes exist than `limit`.
    """
    if limit < 1:
        limit = 1
    elif limit > 100000:
        limit = 100000

    entries: list[dict] = []
    state = {"truncated": False}

    def _visit(ea: int, fpos: int, org_val: int, patch_val: int) -> int:
        if len(entries) >= limit:
            state["truncated"] = True
            return 1  # non-zero stops the walk
        entries.append(
            {
                "addr": hex(ea),
                "original": f"{org_val & 0xFF:02x}",
                "patched": f"{patch_val & 0xFF:02x}",
            }
        )
        return 0

    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, _visit)
    return {
        "count": len(entries),
        "patches": entries,
        "truncated": state["truncated"],
    }
