"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

import inspect
from typing import Annotated, Optional

import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

from ._kernel import compat
from ._kernel import rpc
from ._kernel.rpc import resource
from ._kernel.sync import idasync
from ._kernel.utils import (
    Metadata,
    Segment,
    StructureDefinition,
    StructureMember,
    get_image_size,
    parse_address,
)


# ============================================================================
# Resource pagination helpers
# ============================================================================
#
# The list-style resources (types / structs / xrefs) historically materialized
# their entire result set into one JSON blob. On large IDBs that is both slow
# and routinely tripped the server's 50k-char output limiter, which then
# replaced the payload with a download stub. These helpers add opt-in
# pagination via the ?offset= / ?count= query string carried in the resource
# URI, while keeping the default (no query) behaviour additive: callers that
# do not paginate still get a list, just capped at a sane default page size.

_DEFAULT_PAGE = 200
_MAX_PAGE = 2000


def _parse_resource_query(value: Optional[str]) -> dict[str, str]:
    """Parse the trailing ?k=v&k2=v2 query carried by a resource path segment."""
    if not value or "?" not in value:
        return {}
    _, _, query = value.partition("?")
    out: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        out[k.strip()] = v.strip()
    return out


def _strip_query(value: str) -> str:
    """Return the path segment with any trailing ?query removed."""
    return value.split("?", 1)[0]


def _page_bounds(query: dict[str, str]) -> tuple[int, int]:
    """Resolve (offset, count) from a parsed query dict with safe clamping."""
    try:
        offset = max(0, int(query.get("offset", "0"), 0))
    except (ValueError, TypeError):
        offset = 0
    try:
        count = int(query.get("count", str(_DEFAULT_PAGE)), 0)
    except (ValueError, TypeError):
        count = _DEFAULT_PAGE
    if count <= 0:
        count = _DEFAULT_PAGE
    count = min(count, _MAX_PAGE)
    return offset, count


def _paged(items: list, offset: int, count: int) -> dict:
    """Wrap a slice of `items` with pagination metadata.

    Shape: {"data": [...], "total": int, "offset": int, "count": int,
    "next_offset": int|None}. `next_offset` is None when the slice reaches the
    end, otherwise the offset to pass on the next request.
    """
    total = len(items)
    window = items[offset: offset + count]
    next_offset = offset + count if (offset + count) < total else None
    return {
        "data": window,
        "total": total,
        "offset": offset,
        "count": len(window),
        "next_offset": next_offset,
    }


# ============================================================================
# Headless / GUI gating
# ============================================================================
#
# Several resources surface live UI state (the disassembly cursor, the current
# selection). Under headless idalib there is no UI, and the underlying kernwin
# calls return defaults (ea == BADADDR, empty selection) that look like real
# data. We detect headless mode and return an explicit not-available envelope
# so a client can tell "no GUI" apart from "cursor happens to be at 0".


def _is_headless() -> bool:
    """True when running under idalib (no interactive UI)."""
    try:
        import ida_kernwin

        # is_idaq() is True only inside the Qt GUI; idalib returns False.
        is_idaq = getattr(ida_kernwin, "is_idaq", None)
        if is_idaq is not None:
            return not bool(is_idaq())
    except Exception:
        pass
    # Fall back to the idalib marker on idaapi when kernwin is unavailable.
    return bool(getattr(idaapi, "is_idalib", lambda: False)())


def _gui_unavailable(what: str) -> dict:
    """Uniform 'GUI-only resource under headless' envelope."""
    return {
        "available": False,
        "reason": "headless",
        "detail": f"{what} requires an interactive IDA UI; running under idalib.",
    }


# ============================================================================
# Core IDB State
# ============================================================================


def _arch_info() -> dict:
    """Best-effort architecture / bitness / endianness / compiler block.

    Every probe is guarded: on an IDB where any of these are unset we return a
    string sentinel rather than raising, so the metadata resource never fails
    just because (e.g.) no compiler was detected.
    """
    import ida_ida

    # Processor / architecture name.
    try:
        procname = getattr(ida_ida, "inf_get_procname", None)
        arch = str(procname()) if procname else ""
        if not arch:
            info = idaapi.get_inf_structure()
            arch = str(getattr(info, "procname", "") or "")
    except Exception:
        arch = ""

    # Bitness (16 / 32 / 64).
    try:
        if compat.inf_is_64bit():
            bitness = 64
        else:
            app_bitness = getattr(ida_ida, "inf_get_app_bitness", None)
            bitness = int(app_bitness()) if app_bitness else 32
    except Exception:
        bitness = 0

    # Endianness.
    try:
        is_be_fn = getattr(ida_ida, "inf_is_be", None)
        if is_be_fn is not None:
            big_endian = bool(is_be_fn())
        else:
            big_endian = bool(idaapi.inf_is_be())
    except Exception:
        big_endian = False

    # Compiler id -> human name.
    compiler = "unknown"
    try:
        cc = ida_typeinf.compiler_info_t()
        if ida_typeinf.inf_get_cc(cc):
            name = ida_typeinf.get_compiler_name(cc.id)
            if name:
                compiler = str(name)
    except Exception:
        try:
            info = idaapi.get_inf_structure()
            cc_id = getattr(getattr(info, "cc", None), "id", None)
            if cc_id is not None:
                name = ida_typeinf.get_compiler_name(cc_id)
                if name:
                    compiler = str(name)
        except Exception:
            pass

    return {
        "arch": arch or "unknown",
        "bitness": bitness,
        "endianness": "big" if big_endian else "little",
        "compiler": compiler,
    }


@resource("ida://idb/metadata")
@idasync
def idb_metadata_resource() -> Metadata:
    """Get IDB file metadata (path, arch, bitness, endianness, compiler, base, size, hashes)"""
    import hashlib

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())

    input_path = ida_nalt.get_input_file_path()
    # Prefer IDA's recorded input hashes (cheap, no file read); fall back to
    # hashing the input file on disk when the IDB does not carry them.
    md5 = sha256 = crc32 = filesize = "unavailable"
    try:
        retrieved_md5 = ida_nalt.retrieve_input_file_md5()
        if retrieved_md5:
            md5 = retrieved_md5.hex() if isinstance(retrieved_md5, (bytes, bytearray)) else str(retrieved_md5)
    except Exception:
        pass
    try:
        retrieved_sha = ida_nalt.retrieve_input_file_sha256()
        if retrieved_sha:
            sha256 = retrieved_sha.hex() if isinstance(retrieved_sha, (bytes, bytearray)) else str(retrieved_sha)
    except Exception:
        pass
    try:
        crc32 = hex(ida_nalt.retrieve_input_file_crc32() & 0xFFFFFFFF)
    except Exception:
        pass
    try:
        fsz = ida_nalt.retrieve_input_file_size()
        if fsz:
            filesize = hex(int(fsz))
    except Exception:
        pass

    # Backfill anything still missing by reading the input file (best-effort).
    if "unavailable" in (md5, sha256, crc32, filesize):
        try:
            with open(input_path, "rb") as f:
                data = f.read()
            import zlib

            if md5 == "unavailable":
                md5 = hashlib.md5(data).hexdigest()
            if sha256 == "unavailable":
                sha256 = hashlib.sha256(data).hexdigest()
            if crc32 == "unavailable":
                crc32 = hex(zlib.crc32(data) & 0xFFFFFFFF)
            if filesize == "unavailable":
                filesize = hex(len(data))
        except Exception:
            pass

    result = {
        "path": path,
        "module": module,
        "base": base,
        "size": size,
        "md5": md5,
        "sha256": sha256,
        "crc32": crc32,
        "filesize": filesize,
    }
    # Additive enrichment: arch / bitness / endianness / compiler. Returned as a
    # plain dict (resources are JSON-serialized verbatim, not schema-validated),
    # so the new keys ride alongside the original Metadata fields.
    result.update(_arch_info())
    return result  # type: ignore[return-value]


@resource("ida://idb/segments")
@idasync
def idb_segments_resource() -> list[Segment]:
    """Get all memory segments with permissions"""
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            perms = []
            if seg.perm & idaapi.SEGPERM_READ:
                perms.append("r")
            if seg.perm & idaapi.SEGPERM_WRITE:
                perms.append("w")
            if seg.perm & idaapi.SEGPERM_EXEC:
                perms.append("x")

            segments.append(
                Segment(
                    name=ida_segment.get_segm_name(seg),
                    start=hex(seg.start_ea),
                    end=hex(seg.end_ea),
                    size=hex(seg.size()),
                    permissions="".join(perms) if perms else "---",
                )
            )
    return segments


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    entrypoints = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


# ============================================================================
# Tool Catalog (live registry - single source of truth)
# ============================================================================
#
# This resource reflects the REAL tool surface straight from the live registry
# (rpc.MCP_SERVER.tools + MCP_UNSAFE + MCP_EXTENSIONS + each function's
# __mcp_title__ / __mcp_annotations__). Docs and prompts can be generated from
# here so they can never drift away from what the server actually exposes.

# Cache of func-id -> bool: whether the function's source carries @safety("PATCH").
# PATCH and DESTRUCTIVE share identical MCP annotation flags, so source is the
# only deterministic way to recover the PATCH tier post-decoration.
_patch_source_cache: dict[int, bool] = {}


def _is_patch_tool(func) -> bool:
    target = inspect.unwrap(func)
    key = id(target)
    cached = _patch_source_cache.get(key)
    if cached is not None:
        return cached
    result = False
    try:
        src = inspect.getsource(target)
        result = '@safety("PATCH")' in src or "@safety('PATCH')" in src
    except (OSError, TypeError):
        result = False
    _patch_source_cache[key] = result
    return result


def _safety_class(name: str, func) -> str:
    """Derive READ/WRITE/DESTRUCTIVE/PATCH/EXECUTE from annotations + MCP_UNSAFE.

    READ        -> readOnlyHint True
    EXECUTE     -> destructive + openWorldHint True (arbitrary code / debugger world)
    PATCH       -> destructive AND rewrites program bytes (@safety("PATCH"))
    DESTRUCTIVE -> destructive otherwise
    WRITE       -> mutates IDB but not destructive
    """
    annotations = getattr(func, "__mcp_annotations__", None) or {}
    read_only = bool(annotations.get("readOnlyHint"))
    destructive = bool(annotations.get("destructiveHint"))
    open_world = bool(annotations.get("openWorldHint"))

    if read_only:
        return "READ"
    if destructive:
        if open_world:
            return "EXECUTE"
        if _is_patch_tool(func):
            return "PATCH"
        return "DESTRUCTIVE"
    if not annotations:
        # No explicit annotations: fall back to the unsafe set as the only
        # available signal, otherwise treat as a read.
        return "DESTRUCTIVE" if name in rpc.MCP_UNSAFE else "READ"
    return "WRITE"


def _tool_family(func) -> str:
    """Module-derived family, e.g. ...ida_mcp.api_analysis -> 'analysis'."""
    module = getattr(func, "__module__", "") or ""
    leaf = module.rsplit(".", 1)[-1]
    if leaf.startswith("api_"):
        return leaf[len("api_"):]
    return leaf or "core"


def _ext_group_for(name: str) -> Optional[str]:
    for group, members in rpc.MCP_EXTENSIONS.items():
        if name in members:
            return group
    return None


@resource("ida://tools")
@idasync
def tools_catalog_resource() -> dict:
    """Catalog of the live tool surface (single source of truth for clients/docs).

    Emitted straight from the running registry so it can never drift from what
    the server actually exposes. Each entry carries: name, title, safety
    (READ/WRITE/DESTRUCTIVE/PATCH/EXECUTE), unsafe (whether the name is gated in
    MCP_UNSAFE), ext (extension group such as "dbg", or null for the default
    surface), family (module-derived), and the raw MCP annotations.

    RETURNS: {"server", "total", "extensions": {group: [names]}, "tools": [
    {name, title, safety, unsafe, ext, family, annotations}]} sorted by name.
    """
    tools = []
    for name, func in rpc.MCP_SERVER.tools.methods.items():
        annotations = getattr(func, "__mcp_annotations__", None) or {}
        title = getattr(func, "__mcp_title__", None)
        ext_group = _ext_group_for(name)
        tools.append(
            {
                "name": name,
                "title": title,
                "safety": _safety_class(name, func),
                "unsafe": name in rpc.MCP_UNSAFE,
                "ext": ext_group,
                "family": _tool_family(func),
                "annotations": dict(annotations),
            }
        )
    tools.sort(key=lambda t: t["name"])
    return {
        "server": rpc.MCP_SERVER.name,
        "total": len(tools),
        "extensions": {g: sorted(m) for g, m in rpc.MCP_EXTENSIONS.items()},
        "tools": tools,
    }


# ============================================================================
# UI State
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
    """Get current cursor position and function (GUI only; not available headless)"""
    if _is_headless():
        return _gui_unavailable("Cursor position")

    import ida_kernwin

    ea = ida_kernwin.get_screen_ea()
    func = idaapi.get_func(ea)

    result = {"addr": hex(ea)}
    if func:
        func_name = compat.get_func_name(func)

        result["function"] = {
            "addr": hex(func.start_ea),
            "name": func_name,
        }

    return result


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
    """Get current selection range, if any (GUI only; not available headless)"""
    if _is_headless():
        return _gui_unavailable("Selection range")

    import ida_kernwin

    start = ida_kernwin.read_range_selection(None)
    if start:
        return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
    return {"selection": None}


# ============================================================================
# Type Information
# ============================================================================


@resource("ida://types")
@idasync
def types_resource(query: Annotated[str, "Optional ?offset=&count= pagination"] = "") -> dict:
    """Get local types (paginated via ?offset=&count=)"""
    offset, count = _page_bounds(_parse_resource_query(query))
    types = []
    for ordinal in range(1, compat.get_ordinal_limit(None)):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            name = tif.get_type_name()
            types.append({"ordinal": ordinal, "name": name, "type": str(tif)})
    return _paged(types, offset, count)


@resource("ida://structs")
@idasync
def structs_resource(query: Annotated[str, "Optional ?offset=&count= pagination"] = "") -> dict:
    """Get structures/unions (paginated via ?offset=&count=)"""
    offset, count = _page_bounds(_parse_resource_query(query))
    structs = []
    limit = compat.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal) and tif.is_udt():
            udt_data = ida_typeinf.udt_type_data_t()
            is_union = False
            if tif.get_udt_details(udt_data):
                is_union = udt_data.is_union
            structs.append(
                {
                    "name": tif.get_type_name(),
                    "size": hex(tif.get_size()),
                    "is_union": is_union,
                }
            )
    return _paged(structs, offset, count)


@resource("ida://struct/{name}")
@idasync
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
    """Get structure definition with fields"""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        return {"error": f"Structure not found: {name}"}

    if not tif.is_udt():
        return {"error": f"'{name}' is not a structure/union"}

    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return {"error": f"Failed to get struct details for '{name}'"}

    members = []
    for member in udt_data:
        members.append(
            StructureMember(
                name=member.name,
                offset=hex(member.offset // 8),
                size=hex(member.size // 8),
                type=str(member.type),
            )
        )

    return StructureDefinition(name=name, size=hex(tif.get_size()), members=members)


# ============================================================================
# Import/Export Lookup by Name
# ============================================================================


@resource("ida://import/{name}")
@idasync
def import_name_resource(name: Annotated[str, "Import name"]) -> dict:
    """Get specific import details by name"""
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module = ida_nalt.get_import_module_name(i)
        result = {}

        def callback(ea, imp_name, ordinal):
            if imp_name == name or f"ord_{ordinal}" == name:
                result.update(
                    {
                        "addr": hex(ea),
                        "name": imp_name or f"ord_{ordinal}",
                        "module": module,
                        "ordinal": ordinal,
                    }
                )
                return False  # Stop enumeration
            return True

        ida_nalt.enum_import_names(i, callback)
        if result:
            return result

    return {"error": f"Import not found: {name}"}


@resource("ida://export/{name}")
@idasync
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
    """Get specific export details by name"""
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        entry_name = compat.get_entry_name(ordinal)

        if entry_name == name:
            return {
                "addr": hex(ea),
                "name": entry_name,
                "ordinal": ordinal,
            }

    return {"error": f"Export not found: {name}"}


# ============================================================================
# Cross-references
# ============================================================================


def _xref_type_name(xref) -> str:
    """code/data classification matching the existing xrefs/from shape."""
    return "code" if xref.iscode else "data"


@resource("ida://xrefs/from/{addr}")
@idasync
def xrefs_from_resource(
    addr: Annotated[str, "Source address (supports trailing ?offset=&count=)"]
) -> dict:
    """Get cross-references FROM an address (paginated via ?offset=&count=)"""
    query = _parse_resource_query(addr)
    offset, count = _page_bounds(query)
    ea = parse_address(_strip_query(addr))
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            {
                "addr": hex(xref.to),
                "type": _xref_type_name(xref),
            }
        )
    page = _paged(xrefs, offset, count)
    page["from"] = hex(ea)
    return page


@resource("ida://xrefs/to/{addr}")
@idasync
def xrefs_to_resource(
    addr: Annotated[str, "Target address (supports trailing ?offset=&count=)"]
) -> dict:
    """Get cross-references TO an address - the dominant inbound direction (paginated via ?offset=&count=)

    Mirrors ida://xrefs/from but enumerates inbound refs: callers, jumps, and
    data references that point AT `addr`. Each entry is {addr (the referencing
    site), type ("code"/"data")}.
    """
    query = _parse_resource_query(addr)
    offset, count = _page_bounds(query)
    ea = parse_address(_strip_query(addr))
    xrefs = []
    for xref in idautils.XrefsTo(ea, 0):
        xrefs.append(
            {
                "addr": hex(xref.frm),
                "type": _xref_type_name(xref),
            }
        )
    page = _paged(xrefs, offset, count)
    page["to"] = hex(ea)
    return page
