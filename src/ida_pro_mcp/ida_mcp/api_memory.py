"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import re
from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import idaapi

from .rpc import tool, safety, title
from .sync import idasync
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
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
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


@safety("READ")
@title("Read Typed Integers")
@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "One or more {ty, addr} read requests; ty selects width/sign/endianness "
        "(i8/u8/i16/u16/i32/u32/i64/u64, optional le|be suffix, default le); "
        "a single dict is accepted and wrapped",
    ],
) -> list[IntReadResult]:
    """Read width-, sign-, and endian-aware integers from memory.

    WHAT: For each {ty, addr}, parses the `ty` class to derive byte width,
    signedness, and byte order, reads that many bytes (BSS-safe), and decodes a
    Python int. `ty` is normalized in the result (e.g. "u32" -> "u32le").
    WHEN-TO-USE: Reading a scalar field at a known offset (length prefix, flag
    word, pointer-sized value) when you want the decoded number, not raw bytes.
    RETURNS: One result per query, in input order: {addr, ty, value} on success
    (ty is the normalized class) or {addr, ty, value: null, error} on failure.
    PITFALL: Endianness defaults to little-endian; pass an explicit be suffix
    (e.g. "u32be") for big-endian data such as network byte order. Unsigned
    classes always yield a non-negative value.
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
    """Read defined string literals from memory.

    WHAT: For each address, fetches the string-literal contents IDA recognizes
    at that exact start address and decodes them as UTF-8 (undecodable bytes are
    replaced, never raising).
    WHEN-TO-USE: Resolving a string pointer/xref target to its text, or reading
    a known string constant by address.
    RETURNS: One result per address, in input order: {addr, value} on success or
    {addr, value: null, error} on failure ("No string at address" when IDA has
    no string item there).
    PITFALL: This reads only IDA's DEFINED string item at the precise address;
    it does not scan for an arbitrary null-terminated run, and an address in the
    middle of a string yields no result. For non-UTF-8 encodings (e.g. CP949)
    the replacement chars are expected; use get_bytes to recover the raw bytes.
    """
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            value = raw.decode("utf-8", errors="replace")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if not raw:
            return '""'
        return_string = raw.decode("utf-8", errors="replace").strip()
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


@safety("DESTRUCTIVE")
@title("Patch Bytes")
@tool
@idasync
def patch(
    patches: Annotated[
        list[MemoryPatch] | MemoryPatch,
        "One or more {addr, data} patches; data is a hex byte string (spaces "
        "optional, e.g. '90 90' or '9090'); a single dict is accepted and wrapped",
    ],
) -> list[PatchResult]:
    """Overwrite bytes in the database at one or more addresses (DESTRUCTIVE).

    WHAT: For each {addr, data}, parses `data` as hex bytes, verifies the
    address is mapped, and patches the bytes into the IDB at `addr`. The patch
    length equals the number of hex bytes supplied.
    WHEN-TO-USE: Applying a binary edit (NOP-ing an instruction, flipping a
    constant, neutralizing a check) directly in the database.
    RETURNS: One result per patch, in input order: {addr, size} on success
    (size = bytes written) or {addr, size: 0, error} on failure (e.g. "Address
    not mapped" or a malformed hex string). Per-patch failures never abort the
    batch.
    PITFALL: This mutates the IDB and does NOT auto-align to instruction
    boundaries; patching a partial instruction leaves stale disassembly until
    re-analyzed. To write a typed scalar with width/endianness handled for you,
    prefer put_int over hand-encoding hex here.
    """
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            if not ida_bytes.is_mapped(ea):
                raise ValueError(f"Address not mapped: {patch['addr']}")

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data)}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results


@safety("DESTRUCTIVE")
@title("Write Typed Integers")
@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "One or more {ty, addr, value} writes; ty selects width/sign/endianness "
        "(i8/u8/.../u64, optional le|be, default le); value is a STRING decimal "
        "or 0x.. (negatives allowed for signed types); a single dict is accepted "
        "and wrapped",
    ],
) -> list[IntWriteResult]:
    """Encode and write width-/sign-/endian-aware integers to memory (DESTRUCTIVE).

    WHAT: For each {ty, addr, value}, parses the integer class and the string
    value, encodes it to the target width/byte order (rejecting out-of-range or
    wrongly-signed values), verifies the address is mapped, and patches the bytes
    into the IDB at `addr`.
    WHEN-TO-USE: Setting a scalar field/constant by its logical value without
    hand-encoding hex; complements patch (raw bytes) and get_int (the read side).
    RETURNS: One result per item, in input order: {addr, ty, value} on success
    (ty normalized, value echoed as a string) or {addr, ty, value, error} on
    failure (overflow, negative-into-unsigned, unmapped address, bad value).
    Per-item failures never abort the batch.
    PITFALL: `value` is a STRING, not a number, so quote it ("0x10", "-5"); a
    bare unquoted int will be coerced but the string form is the contract.
    Default endianness is little-endian; pass an explicit be class for
    big-endian/network targets. This mutates the IDB.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
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
            if not ida_bytes.is_mapped(ea):
                raise ValueError(f"Address not mapped: {addr}")
            ida_bytes.patch_bytes(ea, data)
            results.append(
                {
                    "addr": addr,
                    "ty": normalized,
                    "value": str(value_text),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    "error": str(e),
                }
            )

    return results
