"""Signature creation and scanning tools for IDA Pro MCP.

This module integrates sigmaker.py functionality to provide:
- Unique signature generation for addresses/functions
- Range-based signature generation (selection)
- XREF-based signature discovery
- Multiple output formats: IDA, x64dbg, mask, bitmask
"""

from typing import Annotated, NotRequired, TypedDict

import ida_funcs
import idaapi

from . import _sigmaker as _sm
from ._kernel.rpc import safety, title, tool
from ._kernel.sync import idasync
from ._kernel.utils import parse_address, normalize_list_input

# ---------------------------------------------------------------------------
# Output format helpers
# ---------------------------------------------------------------------------

_FORMAT_ALIASES = {
    "ida": "ida",
    "x64dbg": "x64dbg",
    "mask": "mask",
    "bitmask": "bitmask",
}


def _resolve_format(fmt: str) -> "str":
    key = fmt.lower().strip()
    if key not in _FORMAT_ALIASES:
        raise ValueError(
            f"Unknown signature format '{fmt}'. "
            f"Valid formats: ida, x64dbg, mask, bitmask"
        )
    return _FORMAT_ALIASES[key]


def _make_config(
    fmt: str,
    wildcard_operands: bool = True,
    continue_outside_function: bool = True,
    max_length: int = 1000,
) -> "object":
    return _sm.SigMakerConfig(
        output_format=_sm.SignatureType(fmt),
        wildcard_operands=wildcard_operands,
        continue_outside_of_function=continue_outside_function,
        wildcard_optimized=False,
        ask_longer_signature=False,
        max_single_signature_length=max_length,
        max_xref_signature_length=max_length,
    )


def _resolve_addr(addr_str: str) -> int:
    """Resolve an address string or name to an ea."""
    try:
        return parse_address(addr_str)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
        if ea == idaapi.BADADDR:
            raise ValueError(f"Cannot resolve address or name: {addr_str}")
        return ea


def _format_sig(sig, fmt: str) -> str:
    return format(sig, fmt)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class MakeSigResult(TypedDict):
    query: str
    addr: str | None
    signature: str | None
    format: str
    unique: NotRequired[bool]
    error: NotRequired[str]


class MakeSigForFunctionResult(TypedDict):
    query: str
    addr: str | None
    name: str | None
    signature: str | None
    format: str
    error: NotRequired[str]


class XrefSigEntry(TypedDict):
    xref_addr: str | None
    signature: str
    length: int


class XrefSigResult(TypedDict):
    query: str
    addr: str | None
    signatures: list[XrefSigEntry] | None
    total_xrefs: NotRequired[int]
    error: NotRequired[str]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@safety("READ")
@title("Make Unique Signatures")
@tool
@idasync
def make_signature(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to create unique signatures for "
        "(e.g. '0x401000', 'main', or ['0x401000', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: one of 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands so the signature survives relocation/rebuild (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up on uniqueness (default: 1000)",
    ] = 1000,
) -> list[MakeSigResult]:
    """WHAT: Builds the shortest UNIQUE byte-pattern signature starting at each given address by
    walking instructions forward and wildcarding operands until the pattern matches exactly one
    place in the image.

    WHEN TO USE: When you need a stable, relocation-tolerant locator for an in-function code site
    (not the function entry — use make_signature_for_function for that, and find_xref_signatures
    for data/strings that have no signaturable bytes of their own).

    RETURNS: One MakeSigResult per input. Each carries the resolved `addr`, the rendered
    `signature` in the requested `format`, and a `unique` flag (uniqueness is re-verified by an
    actual scan). Failed entries instead carry an `error` string and null signature.

    PITFALL: `unique` can be false if max_length was hit before a distinguishing pattern emerged —
    raise max_length or pick a more distinctive start address. Names are resolved via the IDB, so a
    stale/renamed symbol will fail to resolve."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
    maker = sm.SignatureMaker()
    addrs_list = normalize_list_input(addrs)

    results: list[MakeSigResult] = []
    for addr_str in addrs_list:
        try:
            ea = _resolve_addr(addr_str)
            result = maker.make_signature(ea, cfg)
            sig_str = _format_sig(result.signature, fmt)
            # Verify uniqueness
            is_unique = sm.SignatureSearcher.is_unique(f"{result.signature:ida}")
            results.append({
                "query": addr_str,
                "addr": hex(ea),
                "signature": sig_str,
                "format": format,
                "unique": is_unique,
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if 'ea' in dir() else None,
                "signature": None,
                "format": format,
                "error": str(e),
            })
    return results


@safety("READ")
@title("Make Function Signatures")
@tool
@idasync
def make_signature_for_function(
    addrs: Annotated[
        list[str] | str,
        "Function address(es) or name(s) to create signatures for "
        "(e.g. 'main', '0x401000', or ['main', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: one of 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands so the signature survives relocation/rebuild (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up on uniqueness (default: 1000)",
    ] = 1000,
) -> list[MakeSigForFunctionResult]:
    """WHAT: Resolves each input to its enclosing function and builds the shortest UNIQUE signature
    starting at that function's entry point (start_ea), regardless of where inside the function the
    input address landed.

    WHEN TO USE: The go-to for signaturing a whole function by name or by any address within it.
    Prefer this over make_signature when you want the canonical entry-point pattern rather than a
    mid-function one.

    RETURNS: One MakeSigForFunctionResult per input, with the function `addr` (start_ea), its
    `name`, and the rendered `signature`. Entries where no function contains the address, or where
    resolution fails, carry an `error` and null signature.

    PITFALL: An address inside a chunk/thunk that IDA has not attached to a function yields
    "No function at ..." — define the function first. Unlike make_signature, the result has no
    `unique` flag, though uniqueness is still the generation goal."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
    maker = sm.SignatureMaker()
    addrs_list = normalize_list_input(addrs)

    results: list[MakeSigForFunctionResult] = []
    for addr_str in addrs_list:
        ea = None
        try:
            ea = _resolve_addr(addr_str)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({
                    "query": addr_str,
                    "addr": hex(ea),
                    "name": None,
                    "signature": None,
                    "format": format,
                    "error": f"No function at {hex(ea)}",
                })
                continue

            func_ea = func.start_ea
            func_name = idaapi.get_func_name(func_ea) or None
            result = maker.make_signature(func_ea, cfg)
            sig_str = _format_sig(result.signature, fmt)
            results.append({
                "query": addr_str,
                "addr": hex(func_ea),
                "name": func_name,
                "signature": sig_str,
                "format": format,
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if ea is not None else None,
                "name": None,
                "signature": None,
                "format": format,
                "error": str(e),
            })
    return results


@safety("READ")
@title("Make Range Signature")
@tool
@idasync
def make_signature_for_range(
    start: Annotated[str, "Start address or name, inclusive (e.g. '0x401000')"],
    end: Annotated[str, "End address or name, EXCLUSIVE (e.g. '0x401020')"],
    format: Annotated[
        str,
        "Output format: one of 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands so the signature survives relocation/rebuild (default: true)",
    ] = True,
) -> MakeSigResult:
    """WHAT: Encodes the exact byte range [start, end) into a signature, wildcarding operands if
    requested, and reports whether the resulting pattern happens to be unique.

    WHEN TO USE: When you already know the precise span you want signatured (e.g. a region you
    selected in the disassembly) and want full control over its bounds rather than letting the
    maker auto-extend for uniqueness.

    RETURNS: A single MakeSigResult with `addr` = start, the rendered `signature`, and a `unique`
    flag from a real scan. On failure, `signature` is null and `error` is set.

    PITFALL: Unlike make_signature, this does NOT extend the range to GUARANTEE uniqueness — a short
    range can easily yield `unique: false`. Check the flag, and remember `end` is exclusive, so an
    off-by-one drops the last instruction."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, wildcard_operands=wildcard_operands)
    maker = sm.SignatureMaker()

    try:
        start_ea = _resolve_addr(start)
        end_ea = _resolve_addr(end)
        result = maker.make_signature(start_ea, cfg, end=end_ea)
        sig_str = _format_sig(result.signature, fmt)
        is_unique = sm.SignatureSearcher.is_unique(f"{result.signature:ida}")
        return {
            "query": f"{start}-{end}",
            "addr": hex(start_ea),
            "signature": sig_str,
            "format": format,
            "unique": is_unique,
        }
    except Exception as e:
        return {
            "query": f"{start}-{end}",
            "addr": None,
            "signature": None,
            "format": format,
            "error": str(e),
        }


@safety("READ")
@title("Find XREF Signatures")
@tool
@idasync
def find_xref_signatures(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to find XREF signatures for "
        "(e.g. a data address, vtable slot, or string referenced by code)",
    ],
    format: Annotated[
        str,
        "Output format: one of 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    top: Annotated[
        int,
        "Number of shortest signatures to return per address (default: 5)",
    ] = 5,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes for each xref-site signature (default: 250)",
    ] = 250,
) -> list[XrefSigResult]:
    """WHAT: For each input address, finds all CODE cross-references pointing AT it, builds a unique
    signature at each referencing site, and returns the `top` shortest ones.

    WHEN TO USE: The right tool when the target itself has no signaturable bytes — data addresses,
    vtable entries, globals, or string literals. Instead of signaturing the datum, you signature the
    code that touches it so you can relocate the datum indirectly.

    RETURNS: One XrefSigResult per input. Its `signatures` is a list of XrefSigEntry (each with the
    referencing `xref_addr`, the rendered `signature`, and its byte `length`), plus `total_xrefs`
    (how many xrefs were found before the top-N cut). On failure, `signatures` is null and `error`
    is set.

    PITFALL: A target with no incoming code xrefs returns an empty `signatures` list — not an error.
    Heavily-referenced data can be slow; keep `top` small. Only CODE xrefs are considered (data-to-
    data references are ignored)."""
    sm = _sm
    fmt = _resolve_format(format)
    cfg = _make_config(fmt, max_length=max_length)
    import dataclasses
    cfg = dataclasses.replace(cfg, print_top_x=top)
    finder = sm.XrefFinder()
    addrs_list = normalize_list_input(addrs)

    results: list[XrefSigResult] = []
    for addr_str in addrs_list:
        ea = None
        try:
            ea = _resolve_addr(addr_str)
            xref_result = finder.find_xrefs(ea, cfg)

            sigs = []
            for gs in xref_result.signatures[:top]:
                sig_str = _format_sig(gs.signature, fmt)
                sigs.append({
                    "xref_addr": hex(int(gs.address)) if gs.address else None,
                    "signature": sig_str,
                    "length": len(gs.signature),
                })

            results.append({
                "query": addr_str,
                "addr": hex(ea),
                "signatures": sigs,
                "total_xrefs": len(xref_result.signatures),
            })
        except Exception as e:
            results.append({
                "query": addr_str,
                "addr": hex(ea) if ea is not None else None,
                "signatures": None,
                "error": str(e),
            })
    return results
