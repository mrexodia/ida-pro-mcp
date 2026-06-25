"""
Typed-value decode / type-introspection helpers (Batch-5 SEAM).

Shared, pure helpers used by both the static `read_struct` (api_types) and the
live `read_struct_live` (api_probes) overlays so that typed struct members decode
to meaningful values instead of "everything is an unsigned int".

Design notes:
- No `@tool` / `@idasync` decorators here. These are plain functions; the IDA
  thread-safety contract is the caller's responsibility (read_struct and
  read_struct_live already run under @idasync).
- IDA modules are imported lazily so the module can be imported in environments
  where ida_typeinf / ida_bytes are unavailable (e.g. doc generation).
- Targets the IDA 9.x type API: ENUM members are enumerated through the
  `edm_t` / `enum_type_data_t` API (not the legacy idc enum shim), and bitfield
  members are read off `udm_t.offset` / `udm_t.width` to preserve sub-byte bit
  precision (begin()//8 alone collapses several bitfields into the same byte).

Public surface (see `api` in the returned JSON):
    decode_typed_value(tif, raw, *, endian="little") -> dict
    enum_members(tif) -> list[dict]
    bitfield_layout(udm) -> dict
    resolve_typedef(tif) -> tinfo_t
    type_str(tif) -> str
"""

from __future__ import annotations

import struct as _struct
from typing import Any

# Cap on how many array elements we will decode element-wise before truncating.
_ARRAY_DECODE_CAP = 64

# Cap on raw-byte fallback rendering.
_RAW_PREVIEW_CAP = 16


# ============================================================================
# Type-string helpers
# ============================================================================


def type_str(tif: Any) -> str:
    """Render a tinfo_t as its C type string using the public ``str(tif)``.

    Replaces the private ``tinfo_t._print()`` usage. Returns an empty string for
    a None/empty type rather than raising.
    """
    if tif is None:
        return ""
    try:
        s = str(tif)
        return s if s is not None else ""
    except Exception:
        return ""


def resolve_typedef(tif: Any) -> Any:
    """Follow a typedef chain to its ultimate (non-typedef) target tinfo_t.

    Returns the original ``tif`` when it is not a typedef (or when the chain
    cannot be resolved). Guards against cyclic/self-referential typedefs with a
    bounded loop.
    """
    if tif is None:
        return tif

    cur = tif
    seen: set[str] = set()
    for _ in range(64):  # generous bound; real typedef chains are shallow
        try:
            if not cur.is_typeref() and not cur.is_typedef():
                break
        except Exception:
            break

        # `get_final_type_name` is not always available; walk one level instead.
        nxt = _next_typedef_target(cur)
        if nxt is None:
            break

        key = type_str(nxt)
        if key and key in seen:
            break
        if key:
            seen.add(key)
        cur = nxt
    return cur


def _next_typedef_target(tif: Any) -> Any:
    """Resolve one typedef hop, or None if it cannot be advanced."""
    import ida_typeinf

    # tinfo_t.get_realtype()/get_final_type yield realized types in some builds,
    # but the portable path is get_next_type_name + get_named_type. We instead
    # rely on get_final_type() when available.
    try:
        nxt = ida_typeinf.tinfo_t()
        # get_final_type() copies the fully-resolved type into nxt.
        if hasattr(tif, "get_final_type") and tif.get_final_type(nxt):
            # Only accept if it actually changed (avoid infinite no-op loops).
            if type_str(nxt) and type_str(nxt) != type_str(tif):
                return nxt
    except Exception:
        pass

    # Fallback: resolve the referenced named type by name.
    try:
        name = tif.get_next_type_name() if hasattr(tif, "get_next_type_name") else None
        if not name:
            name = tif.get_type_name() if hasattr(tif, "get_type_name") else None
        if name:
            nxt = ida_typeinf.tinfo_t()
            if nxt.get_named_type(None, name) and type_str(nxt) != type_str(tif):
                return nxt
    except Exception:
        pass

    return None


# ============================================================================
# Enum introspection (9.x edm_t API)
# ============================================================================


def enum_members(tif: Any) -> list[dict]:
    """Enumerate ENUM members of ``tif`` via the 9.x ``enum_type_data_t`` API.

    Returns a list of ``{name, value}`` (plus ``mask`` for bitfield-style /
    bitmask enums when the underlying edm exposes a bmask). Returns an empty
    list when ``tif`` is not an enum or details cannot be read.
    """
    import ida_typeinf

    target = resolve_typedef(tif)
    try:
        if not target.is_enum():
            return []
    except Exception:
        return []

    etd = ida_typeinf.enum_type_data_t()
    try:
        if not target.get_enum_details(etd):
            return []
    except Exception:
        return []

    # A bitmask/bitfield enum carries a per-group bmask; expose it as `mask`.
    is_bf = False
    try:
        is_bf = bool(getattr(etd, "is_bf", lambda: False)())
    except Exception:
        is_bf = False

    out: list[dict] = []
    for edm in etd:
        try:
            entry: dict[str, Any] = {"name": edm.name, "value": int(edm.value)}
        except Exception:
            continue
        if is_bf:
            mask = getattr(edm, "bmask", None)
            if mask is not None:
                try:
                    entry["mask"] = int(mask)
                except Exception:
                    pass
        out.append(entry)
    return out


def _enum_name_for_value(tif: Any, value: int) -> str | None:
    """Resolve a raw integer to the matching enum member NAME (exact match)."""
    for m in enum_members(tif):
        if m.get("value") == value:
            return m.get("name")
    return None


# ============================================================================
# Bitfield layout (udm_t.offset / udm_t.width)
# ============================================================================


def bitfield_layout(udm: Any) -> dict:
    """Return ``{bit_offset, bit_width}`` for a struct member that is a bitfield.

    Uses ``udm.offset`` (the member's offset in BITS, per the 9.x udm_t API) and
    ``udm.width`` (bit width). Unlike ``begin()//8`` this preserves sub-byte bit
    precision, so several bitfields sharing one byte keep distinct offsets.

    For a non-bitfield member, ``bit_width`` is reported as the member's full
    bit size and ``bit_offset`` as its bit offset, so callers can treat the
    result uniformly.
    """
    bit_offset = 0
    bit_width = 0
    try:
        # udm.offset is in bits.
        bit_offset = int(getattr(udm, "offset", 0))
    except Exception:
        bit_offset = 0
    try:
        bit_width = int(getattr(udm, "width", 0))
    except Exception:
        bit_width = 0

    if not bit_width:
        # Fall back to the member's type size in bits when width is unset
        # (non-bitfield members report width 0 on some builds).
        try:
            sz = udm.type.get_size()
            if sz:
                bit_width = int(sz) * 8
        except Exception:
            pass

    return {"bit_offset": bit_offset, "bit_width": bit_width}


def _is_bitfield_member(udm: Any) -> bool:
    """True when ``udm`` describes a bitfield (has a non-byte-aligned width)."""
    try:
        if hasattr(udm, "is_bitfield") and udm.is_bitfield():
            return True
    except Exception:
        pass
    # Heuristic: a positive width that is not a whole-byte multiple of the type
    # size, or offset not byte-aligned, indicates a bitfield.
    try:
        width = int(getattr(udm, "width", 0))
        offset = int(getattr(udm, "offset", 0))
        if width and (offset % 8 != 0 or width % 8 != 0):
            return True
        if width:
            sz = udm.type.get_size()
            if sz and width != int(sz) * 8:
                return True
    except Exception:
        pass
    return False


def _extract_bits(raw: bytes, bit_offset: int, bit_width: int, endian: str) -> int:
    """Extract a bitfield value of ``bit_width`` bits starting at ``bit_offset``.

    ``raw`` is the byte slice covering at least the containing storage unit. The
    integer is reconstructed honoring ``endian`` for the byte order, with bit 0
    as the least-significant bit of the chosen byte order.
    """
    if not raw or bit_width <= 0:
        return 0
    big = int.from_bytes(raw, "big" if endian == "big" else "little")
    mask = (1 << bit_width) - 1
    return (big >> bit_offset) & mask


# ============================================================================
# Typed value decode
# ============================================================================


def decode_typed_value(tif: Any, raw: bytes, *, endian: str = "little") -> dict:
    """Decode ``raw`` bytes according to the type ``tif``.

    Branches on the resolved tinfo:
      - floating  -> float / double
      - bool      -> True / False
      - enum      -> member NAME (with raw value retained)
      - signed    -> signed integer decode
      - pointer   -> hex string
      - array     -> element-wise decode (capped; reports element count)
      - UDT       -> ONE level of struct/union member decode (recurses once)
      - default   -> unsigned integer (last resort)

    ``endian`` selects byte order ("little" or "big").

    Returns ``{"value": ..., "repr": str, "kind": str}``. ``value`` is a
    JSON-friendly Python value; ``repr`` is a human-readable rendering; ``kind``
    names the decode branch taken.
    """
    return _decode(tif, raw, endian=endian, _depth=0)


def _decode(tif: Any, raw: bytes, *, endian: str, _depth: int) -> dict:
    if tif is None:
        return _decode_unsigned(raw, endian)

    target = resolve_typedef(tif)

    # --- floating point -----------------------------------------------------
    try:
        if target.is_floating():
            return _decode_float(target, raw, endian)
    except Exception:
        pass

    # --- bool ---------------------------------------------------------------
    try:
        if target.is_bool():
            v = int.from_bytes(raw, _byteorder(endian)) if raw else 0
            b = bool(v)
            return {"value": b, "repr": "true" if b else "false", "kind": "bool"}
    except Exception:
        pass

    # --- enum ---------------------------------------------------------------
    try:
        if target.is_enum():
            return _decode_enum(target, raw, endian)
    except Exception:
        pass

    # --- pointer ------------------------------------------------------------
    try:
        if target.is_ptr():
            v = int.from_bytes(raw, _byteorder(endian)) if raw else 0
            width = len(raw) if raw else 8
            return {
                "value": v,
                "repr": f"0x{v:0{max(width, 1) * 2}X}",
                "kind": "pointer",
            }
    except Exception:
        pass

    # --- array --------------------------------------------------------------
    try:
        if target.is_array():
            return _decode_array(target, raw, endian, _depth)
    except Exception:
        pass

    # --- UDT (struct/union), one level deep ---------------------------------
    try:
        if target.is_udt():
            return _decode_udt(target, raw, endian, _depth)
    except Exception:
        pass

    # --- signed integer -----------------------------------------------------
    try:
        if target.is_integral() and target.is_signed():
            return _decode_signed(raw, endian)
    except Exception:
        pass

    # --- default: unsigned int (last resort) --------------------------------
    return _decode_unsigned(raw, endian)


def _byteorder(endian: str) -> str:
    return "big" if endian == "big" else "little"


def _decode_unsigned(raw: bytes, endian: str) -> dict:
    v = int.from_bytes(raw, _byteorder(endian)) if raw else 0
    return {"value": v, "repr": f"0x{v:X} ({v})", "kind": "uint"}


def _decode_signed(raw: bytes, endian: str) -> dict:
    if not raw:
        return {"value": 0, "repr": "0", "kind": "int"}
    v = int.from_bytes(raw, _byteorder(endian), signed=True)
    return {"value": v, "repr": str(v), "kind": "int"}


def _decode_float(tif: Any, raw: bytes, endian: str) -> dict:
    size = 0
    try:
        size = int(tif.get_size())
    except Exception:
        size = len(raw)
    if not size:
        size = len(raw)

    order = "<" if endian != "big" else ">"
    try:
        if size == 4 and len(raw) >= 4:
            v = _struct.unpack(order + "f", raw[:4])[0]
            return {"value": v, "repr": repr(v), "kind": "float"}
        if size == 8 and len(raw) >= 8:
            v = _struct.unpack(order + "d", raw[:8])[0]
            return {"value": v, "repr": repr(v), "kind": "double"}
        if size == 2 and len(raw) >= 2:
            v = _struct.unpack(order + "e", raw[:2])[0]
            return {"value": v, "repr": repr(v), "kind": "float16"}
    except Exception:
        pass
    # long double / unsupported width: fall back to raw hex.
    return {
        "value": raw.hex(),
        "repr": f"<float{size * 8} {raw[:_RAW_PREVIEW_CAP].hex()}>",
        "kind": "float",
    }


def _decode_enum(tif: Any, raw: bytes, endian: str) -> dict:
    signed = False
    try:
        signed = bool(tif.is_signed())
    except Exception:
        signed = False
    v = int.from_bytes(raw, _byteorder(endian), signed=signed) if raw else 0
    name = _enum_name_for_value(tif, v)
    if name:
        return {
            "value": name,
            "repr": f"{name} (0x{v & ((1 << (max(len(raw), 1) * 8)) - 1):X})",
            "kind": "enum",
            "raw": v,
        }
    # No exact member; try to decompose as OR of bitmask members.
    decomposed = _decompose_enum_flags(tif, v)
    if decomposed:
        return {
            "value": decomposed,
            "repr": " | ".join(decomposed) + f" (0x{v:X})",
            "kind": "enum",
            "raw": v,
        }
    return {
        "value": v,
        "repr": f"<enum 0x{v:X}>",
        "kind": "enum",
        "raw": v,
    }


def _decompose_enum_flags(tif: Any, value: int) -> list[str]:
    """Best-effort decompose a value into OR'd enum member names (flags)."""
    if value == 0:
        return []
    names: list[str] = []
    remaining = value
    for m in enum_members(tif):
        mv = m.get("value", 0)
        if mv and (remaining & mv) == mv:
            names.append(m.get("name", ""))
            remaining &= ~mv
    if remaining != 0:
        return []  # leftover bits -> not a clean flag decomposition
    return [n for n in names if n]


def _decode_array(tif: Any, raw: bytes, endian: str, _depth: int) -> dict:
    elem = None
    try:
        elem = tif.get_array_element()
    except Exception:
        elem = None

    n = 0
    try:
        n = int(tif.get_array_nelems())
    except Exception:
        n = 0

    elem_size = 0
    try:
        elem_size = int(elem.get_size()) if elem is not None else 0
    except Exception:
        elem_size = 0

    if not elem or not elem_size or n <= 0:
        return {
            "value": raw[:_RAW_PREVIEW_CAP].hex(),
            "repr": f"[array {raw[:_RAW_PREVIEW_CAP].hex()}{'...' if len(raw) > _RAW_PREVIEW_CAP else ''}]",
            "kind": "array",
            "count": n,
        }

    # Char arrays -> render as a string preview (common, useful case).
    is_char = False
    try:
        is_char = bool(elem.is_char()) or (elem_size == 1 and elem.is_integral())
    except Exception:
        is_char = elem_size == 1

    capped = min(n, _ARRAY_DECODE_CAP)
    if is_char and elem_size == 1:
        chunk = raw[: n if n <= 4096 else 4096]
        text = chunk.split(b"\x00", 1)[0]
        try:
            preview = text.decode("latin-1")
        except Exception:
            preview = chunk[:_RAW_PREVIEW_CAP].hex()
        return {
            "value": preview,
            "repr": repr(preview),
            "kind": "char_array",
            "count": n,
        }

    elements: list[Any] = []
    for i in range(capped):
        off = i * elem_size
        sub = raw[off:off + elem_size]
        if len(sub) < elem_size:
            break
        dec = _decode(elem, sub, endian=endian, _depth=_depth + 1)
        elements.append(dec.get("value"))

    truncated = n > capped
    return {
        "value": elements,
        "repr": f"[{', '.join(str(e) for e in elements)}{', ...' if truncated else ''}]",
        "kind": "array",
        "count": n,
        "truncated": truncated,
    }


def _decode_udt(tif: Any, raw: bytes, endian: str, _depth: int) -> dict:
    import ida_typeinf

    # Only recurse ONE level into nested UDTs.
    if _depth >= 1:
        return {
            "value": raw[:_RAW_PREVIEW_CAP].hex(),
            "repr": f"<{type_str(tif)} {raw[:_RAW_PREVIEW_CAP].hex()}{'...' if len(raw) > _RAW_PREVIEW_CAP else ''}>",
            "kind": "udt",
        }

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return _decode_unsigned(raw, endian)

    members: dict[str, Any] = {}
    reprs: list[str] = []
    for udm in udt:
        name = udm.name or f"field_{(udm.offset // 8):x}"
        if _is_bitfield_member(udm):
            bl = bitfield_layout(udm)
            # Determine the storage unit byte span covering the bitfield.
            start_byte = bl["bit_offset"] // 8
            # bytes needed to cover bit_offset+bit_width from start_byte
            end_bit = bl["bit_offset"] + bl["bit_width"]
            end_byte = (end_bit + 7) // 8
            unit = raw[start_byte:end_byte]
            local_off = bl["bit_offset"] - start_byte * 8
            bits = _extract_bits(unit, local_off, bl["bit_width"], endian)
            members[name] = {
                "value": bits,
                "bit_offset": bl["bit_offset"],
                "bit_width": bl["bit_width"],
                "kind": "bitfield",
            }
            reprs.append(f"{name}={bits}")
            continue

        off = udm.offset // 8  # byte offset
        try:
            msize = int(udm.type.get_size())
        except Exception:
            msize = 0
        sub = raw[off:off + msize] if msize else b""
        dec = _decode(udm.type, sub, endian=endian, _depth=_depth + 1)
        members[name] = {
            "value": dec.get("value"),
            "kind": dec.get("kind"),
            "offset": off,
        }
        reprs.append(f"{name}={dec.get('repr')}")

    return {
        "value": members,
        "repr": "{" + ", ".join(reprs) + "}",
        "kind": "udt",
    }
