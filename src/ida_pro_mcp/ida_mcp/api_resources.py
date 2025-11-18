"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

from typing import Annotated

import ida_funcs
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from .rpc import resource
from .sync import idaread
from .utils import (
    Function,
    Global,
    Import,
    Metadata,
    Page,
    Segment,
    String,
    StructureDefinition,
    StructureMember,
    get_image_size,
    paginate,
    parse_address,
    pattern_filter,
)

# ============================================================================
# Core IDB Resources
# ============================================================================


@resource("ida://idb/metadata")
@idaread
def idb_metadata_resource() -> Metadata:
    """Get IDB file metadata (path, arch, base address, size, hashes)"""
    import hashlib

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())

    input_path = ida_nalt.get_input_file_path()
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        import zlib

        crc32 = hex(zlib.crc32(data) & 0xFFFFFFFF)
        filesize = hex(len(data))
    except Exception:
        md5 = sha256 = crc32 = filesize = "unavailable"

    return Metadata(
        path=path,
        module=module,
        base=base,
        size=size,
        md5=md5,
        sha256=sha256,
        crc32=crc32,
        filesize=filesize,
    )


@resource("ida://idb/segments")
@idaread
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
@idaread
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    entrypoints = []
    entry_count = ida_nalt.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_nalt.get_entry_ordinal(i)
        ea = ida_nalt.get_entry(ordinal)
        name = ida_nalt.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


# ============================================================================
# Code Resources (functions & globals)
# ============================================================================


@resource("ida://functions")
@idaread
def functions_resource(
    filter: Annotated[str, "Optional glob pattern to filter by name"] = "",
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[Function]:
    """List all functions in the IDB"""
    funcs = []
    for ea in idautils.Functions():
        fn = idaapi.get_func(ea)
        if fn:
            try:
                name = fn.get_name()
            except AttributeError:
                name = ida_funcs.get_func_name(fn.start_ea)

            funcs.append(
                Function(addr=hex(ea), name=name, size=hex(fn.end_ea - fn.start_ea))
            )

    if filter:
        funcs = pattern_filter(funcs, filter, "name")

    return paginate(funcs, offset, count)


@resource("ida://function/{addr}")
@idaread
def function_addr_resource(
    addr: Annotated[str, "Function address (hex or decimal)"],
) -> dict:
    """Get function details by address (no decompilation - use decompile tool)"""
    ea = parse_address(addr)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {hex(ea)}"}

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    # Get prototype if available
    try:
        from .utils import get_prototype

        prototype = get_prototype(fn)
    except Exception:
        prototype = None

    return {
        "addr": hex(fn.start_ea),
        "name": name,
        "size": hex(fn.end_ea - fn.start_ea),
        "end_ea": hex(fn.end_ea),
        "prototype": prototype,
        "flags": fn.flags,
    }


@resource("ida://globals")
@idaread
def globals_resource(
    filter: Annotated[str, "Optional glob pattern to filter by name"] = "",
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[Global]:
    """List all global variables"""
    globals_list = []
    for ea, name in idautils.Names():
        # Skip functions
        if idaapi.get_func(ea):
            continue
        globals_list.append(Global(addr=hex(ea), name=name))

    if filter:
        globals_list = pattern_filter(globals_list, filter, "name")

    return paginate(globals_list, offset, count)


@resource("ida://global/{name_or_addr}")
@idaread
def global_id_resource(name_or_addr: Annotated[str, "Global name or address"]) -> dict:
    """Get specific global variable details"""
    # Try as address first
    try:
        ea = parse_address(name_or_addr)
        name = idc.get_name(ea)
    except Exception:
        # Try as name
        ea = idc.get_name_ea_simple(name_or_addr)
        if ea == idaapi.BADADDR:
            return {"error": f"Global not found: {name_or_addr}"}
        name = name_or_addr

    # Get type info
    tif = idaapi.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        type_str = str(tif)
    else:
        type_str = None

    # Get size
    item_size = idc.get_item_size(ea)

    return {
        "addr": hex(ea),
        "name": name,
        "type": type_str,
        "size": hex(item_size) if item_size else None,
    }


# ============================================================================
# Data Resources (strings & imports)
# ============================================================================


@resource("ida://strings")
@idaread
def strings_resource(
    filter: Annotated[str, "Optional pattern to match in strings"] = "",
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[String]:
    """Get all strings in binary"""
    strings = []
    sc = idaapi.string_info_t()
    for i in range(idaapi.get_strlist_qty()):
        if idaapi.get_strlist_item(sc, i):
            try:
                str_content = idc.get_strlit_contents(sc.ea)
                if str_content:
                    decoded = str_content.decode("utf-8", errors="replace")
                    if not filter or filter.lower() in decoded.lower():
                        strings.append(
                            String(addr=hex(sc.ea), length=sc.length, string=decoded)
                        )
            except Exception:
                pass

    return paginate(strings, offset, count)


@resource("ida://string/{addr}")
@idaread
def string_addr_resource(addr: Annotated[str, "String address"]) -> dict:
    """Get specific string details"""
    ea = parse_address(addr)
    try:
        str_content = idc.get_strlit_contents(ea)
        if str_content:
            return {
                "addr": hex(ea),
                "length": len(str_content),
                "string": str_content.decode("utf-8", errors="replace"),
                "type": ida_nalt.get_str_type(ea),
            }
        return {"error": f"No string at {hex(ea)}"}
    except Exception as e:
        return {"error": str(e)}


@resource("ida://imports")
@idaread
def imports_resource(
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[Import]:
    """Get all imported functions"""
    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module = ida_nalt.get_import_module_name(i)

        def callback(ea, name, ordinal):
            imports.append(
                Import(
                    addr=hex(ea), imported_name=name or f"ord_{ordinal}", module=module
                )
            )
            return True

        ida_nalt.enum_import_names(i, callback)

    return paginate(imports, offset, count)


@resource("ida://import/{name}")
@idaread
def import_name_resource(name: Annotated[str, "Import name"]) -> dict:
    """Get specific import details"""
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


@resource("ida://exports")
@idaread
def exports_resource(
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[dict]:
    """Get all exported functions"""
    exports = []
    entry_count = ida_nalt.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_nalt.get_entry_ordinal(i)
        ea = ida_nalt.get_entry(ordinal)
        name = ida_nalt.get_entry_name(ordinal)
        exports.append({"addr": hex(ea), "name": name, "ordinal": ordinal})

    return paginate(exports, offset, count)


@resource("ida://export/{name}")
@idaread
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
    """Get specific export details"""
    entry_count = ida_nalt.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_nalt.get_entry_ordinal(i)
        ea = ida_nalt.get_entry(ordinal)
        entry_name = ida_nalt.get_entry_name(ordinal)

        if entry_name == name:
            return {
                "addr": hex(ea),
                "name": entry_name,
                "ordinal": ordinal,
            }

    return {"error": f"Export not found: {name}"}


# ============================================================================
# Type Resources (structures & types)
# ============================================================================


@resource("ida://types")
@idaread
def types_resource() -> list[dict]:
    """Get all local types"""
    import ida_typeinf

    types = []
    for ordinal in range(1, ida_typeinf.get_ordinal_qty(None)):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            name = tif.get_type_name()
            types.append({"ordinal": ordinal, "name": name, "type": str(tif)})
    return types


@resource("ida://structs")
@idaread
def structs_resource() -> list[dict]:
    """Get all structures/unions"""
    import ida_struct

    structs = []
    for idx in range(ida_struct.get_struc_qty()):
        tid = ida_struct.get_struc_by_idx(idx)
        struc = ida_struct.get_struc(tid)
        if struc:
            structs.append(
                {
                    "name": ida_struct.get_struc_name(tid),
                    "size": hex(ida_struct.get_struc_size(struc)),
                    "is_union": struc.is_union(),
                }
            )
    return structs


@resource("ida://struct/{name}")
@idaread
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
    """Get structure definition with fields"""
    import ida_struct
    import ida_typeinf

    sid = ida_struct.get_struc_id(name)
    if sid == idaapi.BADADDR:
        return {"error": f"Structure not found: {name}"}

    struc = ida_struct.get_struc(sid)
    if not struc:
        return {"error": f"Structure not found: {name}"}

    members = []
    for i in range(struc.memqty):
        member = struc.get_member(i)
        if member:
            mname = ida_struct.get_member_name(member.id)
            tif = ida_typeinf.tinfo_t()
            if ida_struct.get_member_tinfo(tif, member):
                type_str = str(tif)
            else:
                type_str = "unknown"

            members.append(
                StructureMember(
                    name=mname,
                    offset=hex(member.soff),
                    size=hex(ida_struct.get_member_size(member)),
                    type=type_str,
                )
            )

    return StructureDefinition(
        name=name, size=hex(ida_struct.get_struc_size(struc)), members=members
    )


# ============================================================================
# Analysis Resources (xrefs & stack)
# ============================================================================


@resource("ida://xrefs/to/{addr}")
@idaread
def xrefs_to_addr_resource(addr: Annotated[str, "Target address"]) -> list[dict]:
    """Get cross-references to address"""
    ea = parse_address(addr)
    xrefs = []
    for xref in idautils.XrefsTo(ea, 0):
        xrefs.append(
            {
                "addr": hex(xref.frm),
                "type": "code" if xref.iscode else "data",
            }
        )
    return xrefs


@resource("ida://xrefs/from/{addr}")
@idaread
def xrefs_from_resource(addr: Annotated[str, "Source address"]) -> list[dict]:
    """Get cross-references from address"""
    ea = parse_address(addr)
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            {
                "addr": hex(xref.to),
                "type": "code" if xref.iscode else "data",
            }
        )
    return xrefs


@resource("ida://stack/{func_addr}")
@idaread
def stack_func_resource(func_addr: Annotated[str, "Function address"]) -> dict:
    """Get stack frame variables for a function"""
    from .utils import get_stack_frame_variables_internal

    ea = parse_address(func_addr)
    variables = get_stack_frame_variables_internal(ea, raise_error=True)
    return {"addr": hex(ea), "variables": variables}


# ============================================================================
# Context Resources (current state)
# ============================================================================


@resource("ida://cursor")
@idaread
def cursor_resource() -> dict:
    """Get current cursor position and function"""
    import ida_kernwin

    ea = ida_kernwin.get_screen_ea()
    func = idaapi.get_func(ea)

    result = {"addr": hex(ea)}
    if func:
        try:
            func_name = func.get_name()
        except AttributeError:
            func_name = ida_funcs.get_func_name(func.start_ea)

        result["function"] = {
            "addr": hex(func.start_ea),
            "name": func_name,
        }

    return result


@resource("ida://selection")
@idaread
def selection_resource() -> dict:
    """Get current selection range (if any)"""
    import ida_kernwin

    start = ida_kernwin.read_range_selection(None)
    if start:
        return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
    return {"selection": None}


# ============================================================================
# Debug Resources (when debugger is active)
# ============================================================================


@resource("ida://debug/breakpoints")
@idaread
def debug_breakpoints_resource() -> list[dict]:
    """Get all debugger breakpoints"""
    import ida_dbg

    if not ida_dbg.is_debugger_on():
        return []

    breakpoints = []
    n = ida_dbg.get_bpt_qty()
    for i in range(n):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                {
                    "addr": hex(bpt.ea),
                    "enabled": bpt.is_enabled(),
                    "type": bpt.type,
                    "size": bpt.size,
                }
            )
    return breakpoints


@resource("ida://debug/registers")
@idaread
def debug_registers_resource() -> dict:
    """Get current debugger register values"""
    import ida_dbg
    import ida_idd

    if not ida_dbg.is_debugger_on():
        return {"error": "Debugger not active"}

    registers = {}
    # Get register values
    rv = ida_idd.regval_t()
    for reg_name in ida_dbg.dbg_get_registers():
        if ida_dbg.get_reg_val(reg_name, rv):
            registers[reg_name] = hex(rv.ival)

    return {"registers": registers}


@resource("ida://debug/callstack")
@idaread
def debug_callstack_resource() -> list[dict]:
    """Get current debugger call stack"""
    import ida_dbg

    if not ida_dbg.is_debugger_on():
        return []

    stack = []
    trace = ida_dbg.get_stack_trace()
    if trace:
        for i in range(len(trace)):
            frame = trace[i]
            stack.append(
                {
                    "index": i,
                    "addr": hex(frame.ea),
                    "sp": hex(frame.sp) if frame.sp else None,
                    "fp": hex(frame.fp) if frame.fp else None,
                    "func_name": idc.get_name(frame.ea) if frame.ea else None,
                }
            )
    return stack
