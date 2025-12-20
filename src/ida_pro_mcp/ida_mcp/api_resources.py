"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

from typing import Annotated

import ida_dbg
import ida_entry
import ida_funcs
import ida_idd
import ida_kernwin
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import resource
from .sync import idasync
from .tests import (
    test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    get_any_function,
    get_any_string,
)
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
@idasync
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


@test()
def test_resource_idb_metadata():
    """idb_metadata_resource returns valid metadata with all required fields"""
    meta = idb_metadata_resource()
    assert_has_keys(meta, "path", "module", "base", "size", "md5", "sha256")
    assert_non_empty(meta["path"])
    assert_non_empty(meta["module"])
    assert_valid_address(meta["base"])
    assert_valid_address(meta["size"])


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


@test()
def test_resource_idb_segments():
    """idb_segments_resource returns list of segments with proper structure"""
    segs = idb_segments_resource()
    assert_is_list(segs, min_length=1)
    seg = segs[0]
    assert_has_keys(seg, "name", "start", "end", "size", "permissions")
    assert_valid_address(seg["start"])
    assert_valid_address(seg["end"])
    assert_valid_address(seg["size"])


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    entrypoints = []
    entry_count = ida_entry.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


@test()
def test_resource_idb_entrypoints():
    """idb_entrypoints_resource returns list of entry points"""
    result = idb_entrypoints_resource()
    assert_is_list(result)
    # If there are entry points, check structure
    if result:
        entry = result[0]
        assert_has_keys(entry, "addr", "name", "ordinal")
        assert_valid_address(entry["addr"])


# ============================================================================
# Code Resources (functions & globals)
# ============================================================================


@resource("ida://functions")
@idasync
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


@test()
def test_resource_functions():
    """functions_resource returns paginated list of functions"""
    result = functions_resource()
    assert_has_keys(result, "data", "next_offset")
    assert_is_list(result["data"], min_length=1)
    # Check first function has required keys
    fn = result["data"][0]
    assert_has_keys(fn, "addr", "name", "size")
    assert_valid_address(fn["addr"])


@resource("ida://function/{addr}")
@idasync
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


@test()
def test_resource_function_addr():
    """function_addr_resource returns function details for valid address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = function_addr_resource(fn_addr)
    # Should not have error for valid function
    assert "error" not in result or result.get("error") is None
    assert_has_keys(result, "addr", "name", "size", "end_ea", "flags")
    assert_valid_address(result["addr"])
    assert_valid_address(result["end_ea"])


@resource("ida://globals")
@idasync
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


@test()
def test_resource_globals():
    """globals_resource returns paginated list of globals"""
    result = globals_resource()
    assert_has_keys(result, "data", "next_offset")
    assert_is_list(result["data"])
    # If there are globals, check structure
    if result["data"]:
        glob = result["data"][0]
        assert_has_keys(glob, "addr", "name")
        assert_valid_address(glob["addr"])


@resource("ida://global/{name_or_addr}")
@idasync
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


@test()
def test_resource_global_id():
    """global_id_resource returns global details for valid address"""
    # First get a global from globals_resource
    result = globals_resource()
    if not result["data"]:
        return  # Skip if no globals

    glob = result["data"][0]
    # Test by address
    detail = global_id_resource(glob["addr"])
    assert "error" not in detail or detail.get("error") is None
    assert_has_keys(detail, "addr", "name")
    assert_valid_address(detail["addr"])


# ============================================================================
# Data Resources (strings & imports)
# ============================================================================


@resource("ida://strings")
@idasync
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


@test()
def test_resource_strings():
    """strings_resource returns paginated list of strings"""
    result = strings_resource()
    assert_has_keys(result, "data", "next_offset")
    assert_is_list(result["data"])
    # If there are strings, check structure
    if result["data"]:
        string_item = result["data"][0]
        assert_has_keys(string_item, "addr", "length", "string")
        assert_valid_address(string_item["addr"])


@resource("ida://string/{addr}")
@idasync
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


@test()
def test_resource_string_addr():
    """string_addr_resource returns string details for valid address"""
    str_addr = get_any_string()
    if not str_addr:
        return  # Skip if no strings

    result = string_addr_resource(str_addr)
    assert "error" not in result or result.get("error") is None
    assert_has_keys(result, "addr", "length", "string", "type")
    assert_valid_address(result["addr"])


@resource("ida://imports")
@idasync
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


@test()
def test_resource_imports():
    """imports_resource returns paginated list of imports"""
    result = imports_resource()
    assert_has_keys(result, "data", "next_offset")
    assert_is_list(result["data"])
    # If there are imports, check structure
    if result["data"]:
        imp = result["data"][0]
        assert_has_keys(imp, "addr", "imported_name", "module")
        assert_valid_address(imp["addr"])


@resource("ida://import/{name}")
@idasync
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


@test()
def test_resource_import_name():
    """import_name_resource returns import details for valid name"""
    # First get an import from imports_resource
    result = imports_resource()
    if not result["data"]:
        return  # Skip if no imports

    imp = result["data"][0]
    # Test by name
    detail = import_name_resource(imp["imported_name"])
    assert "error" not in detail or detail.get("error") is None
    assert_has_keys(detail, "addr", "name", "module", "ordinal")
    assert_valid_address(detail["addr"])


@resource("ida://exports")
@idasync
def exports_resource(
    offset: Annotated[int, "Starting index"] = 0,
    count: Annotated[int, "Maximum results (0=all)"] = 50,
) -> Page[dict]:
    """Get all exported functions"""
    exports = []
    entry_count = ida_entry.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        exports.append({"addr": hex(ea), "name": name, "ordinal": ordinal})

    return paginate(exports, offset, count)


@test()
def test_resource_exports():
    """exports_resource returns paginated list of exports"""
    result = exports_resource()
    assert_has_keys(result, "data", "next_offset")
    assert_is_list(result["data"])
    # If there are exports, check structure
    if result["data"]:
        export = result["data"][0]
        assert_has_keys(export, "addr", "name", "ordinal")
        assert_valid_address(export["addr"])


@resource("ida://export/{name}")
@idasync
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
    """Get specific export details"""
    entry_count = ida_entry.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        entry_name = ida_entry.get_entry_name(ordinal)

        if entry_name == name:
            return {
                "addr": hex(ea),
                "name": entry_name,
                "ordinal": ordinal,
            }

    return {"error": f"Export not found: {name}"}


@test()
def test_resource_export_name():
    """export_name_resource returns export details for valid name"""
    # First get an export from exports_resource
    result = exports_resource()
    if not result["data"]:
        return  # Skip if no exports

    export = result["data"][0]
    if not export["name"]:
        return  # Skip if export has no name

    # Test by name
    detail = export_name_resource(export["name"])
    assert "error" not in detail or detail.get("error") is None
    assert_has_keys(detail, "addr", "name", "ordinal")
    assert_valid_address(detail["addr"])


# ============================================================================
# Type Resources (structures & types)
# ============================================================================


@resource("ida://types")
@idasync
def types_resource() -> list[dict]:
    """Get all local types"""
    types = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            name = tif.get_type_name()
            types.append({"ordinal": ordinal, "name": name, "type": str(tif)})
    return types


@test()
def test_resource_types():
    """types_resource returns list of local types"""
    result = types_resource()
    assert_is_list(result)
    # If there are types, check structure
    if result:
        type_item = result[0]
        assert_has_keys(type_item, "ordinal", "name", "type")


@resource("ida://structs")
@idasync
def structs_resource() -> list[dict]:
    """Get all structures/unions"""
    structs = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            structs.append(
                {
                    "name": tif.get_type_name(),
                    "size": hex(tif.get_size()),
                    "is_union": tif.is_union(),
                }
            )
    return structs


@test()
def test_resource_structs():
    """structs_resource returns list of structures"""
    result = structs_resource()
    assert_is_list(result)
    # If there are structs, check structure
    if result:
        struct_item = result[0]
        assert_has_keys(struct_item, "name", "size", "is_union")
        assert_valid_address(struct_item["size"])


@resource("ida://struct/{name}")
@idasync
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
    """Get structure definition with fields"""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        return {"error": f"Structure not found: {name}"}

    if not tif.is_udt():
        return {"error": f"'{name}' is not a structure/union"}

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {"error": f"Failed to get structure details for: {name}"}

    members = []
    for udm in udt:
        members.append(
            StructureMember(
                name=udm.name,
                offset=hex(udm.offset // 8),
                size=hex(udm.size // 8),
                type=str(udm.type),
            )
        )

    return StructureDefinition(name=name, size=hex(tif.get_size()), members=members)


@test()
def test_resource_struct_name():
    """struct_name_resource returns struct details for valid name"""
    # First get a struct from structs_resource
    struct_list = structs_resource()
    if not struct_list:
        return  # Skip if no structs

    name = struct_list[0]["name"]
    result = struct_name_resource(name)
    assert "error" not in result or result.get("error") is None
    assert_has_keys(result, "name", "size", "members")
    assert_valid_address(result["size"])
    assert_is_list(result["members"])


# ============================================================================
# Analysis Resources (xrefs & stack)
# ============================================================================


@resource("ida://xrefs/to/{addr}")
@idasync
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


@test()
def test_resource_xrefs_to():
    """xrefs_to_addr_resource returns list of cross-references to address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = xrefs_to_addr_resource(fn_addr)
    assert_is_list(result)
    # If there are xrefs, check structure
    if result:
        xref = result[0]
        assert_has_keys(xref, "addr", "type")
        assert_valid_address(xref["addr"])
        assert xref["type"] in ("code", "data")


@resource("ida://xrefs/from/{addr}")
@idasync
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


@test()
def test_resource_xrefs_from():
    """xrefs_from_resource returns list of cross-references from address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = xrefs_from_resource(fn_addr)
    assert_is_list(result)
    # If there are xrefs, check structure
    if result:
        xref = result[0]
        assert_has_keys(xref, "addr", "type")
        assert_valid_address(xref["addr"])
        assert xref["type"] in ("code", "data")


@resource("ida://stack/{func_addr}")
@idasync
def stack_func_resource(func_addr: Annotated[str, "Function address"]) -> dict:
    """Get stack frame variables for a function"""
    from .utils import get_stack_frame_variables_internal

    ea = parse_address(func_addr)
    variables = get_stack_frame_variables_internal(ea, raise_error=True)
    return {"addr": hex(ea), "variables": variables}


@test()
def test_resource_stack_func():
    """stack_func_resource returns stack frame for valid function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = stack_func_resource(fn_addr)
    assert_has_keys(result, "addr", "variables")
    assert_valid_address(result["addr"])
    assert_is_list(result["variables"])


# ============================================================================
# Context Resources (current state)
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
    """Get current cursor position and function"""
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


@test()
def test_resource_cursor():
    """cursor_resource returns current cursor position"""
    result = cursor_resource()
    assert_has_keys(result, "addr")
    assert_valid_address(result["addr"])
    # Function key is optional, but if present should have proper structure
    if "function" in result and result["function"]:
        assert_has_keys(result["function"], "addr", "name")
        assert_valid_address(result["function"]["addr"])


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
    """Get current selection range (if any)"""
    start = ida_kernwin.read_range_selection(None)
    if start:
        return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
    return {"selection": None}


@test()
def test_resource_selection():
    """selection_resource returns selection or null"""
    result = selection_resource()
    # Result should have either start/end or selection key
    assert isinstance(result, dict)
    if "selection" in result:
        # No selection case
        assert result["selection"] is None
    else:
        # Selection exists
        assert_has_keys(result, "start")
        assert_valid_address(result["start"])


# ============================================================================
# Debug Resources (when debugger is active)
# ============================================================================


@resource("ida://debug/breakpoints")
@idasync
def debug_breakpoints_resource() -> list[dict]:
    """Get all debugger breakpoints"""
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


@test()
def test_resource_debug_breakpoints():
    """debug_breakpoints_resource returns list (empty if debugger not active)"""
    result = debug_breakpoints_resource()
    assert_is_list(result)
    # If there are breakpoints, check structure
    if result:
        bp = result[0]
        assert_has_keys(bp, "addr", "enabled", "type", "size")
        assert_valid_address(bp["addr"])


@resource("ida://debug/registers")
@idasync
def debug_registers_resource() -> dict:
    """Get current debugger register values"""
    if not ida_dbg.is_debugger_on():
        return {"error": "Debugger not active"}

    registers = {}
    # Get register values
    rv = ida_idd.regval_t()
    for reg_name in ida_dbg.dbg_get_registers():
        if ida_dbg.get_reg_val(reg_name, rv):
            registers[reg_name] = hex(rv.ival)

    return {"registers": registers}


@test()
def test_resource_debug_registers():
    """debug_registers_resource returns error or registers dict"""
    result = debug_registers_resource()
    assert isinstance(result, dict)
    # Either has error (debugger not active) or registers
    if "error" in result:
        assert result["error"] == "Debugger not active"
    else:
        assert_has_keys(result, "registers")
        assert isinstance(result["registers"], dict)


@resource("ida://debug/callstack")
@idasync
def debug_callstack_resource() -> list[dict]:
    """Get current debugger call stack"""
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


@test()
def test_resource_debug_callstack():
    """debug_callstack_resource returns list (empty if debugger not active)"""
    result = debug_callstack_resource()
    assert_is_list(result)
    # If there are frames, check structure
    if result:
        frame = result[0]
        assert_has_keys(frame, "index", "addr")
        assert_valid_address(frame["addr"])
