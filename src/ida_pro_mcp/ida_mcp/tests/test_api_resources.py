"""Tests for api_resources API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_valid_address,
    assert_has_keys,
    assert_non_empty,
    assert_is_list,
    assert_all_have_keys,
    get_any_function,
    get_any_string,
    get_first_segment,
    get_n_functions,
    get_n_strings,
    get_data_address,
    get_unmapped_address,
    get_functions_with_calls,
    get_functions_with_callers,
)

# Import functions under test
from ..api_resources import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_resource_idb_metadata():
    """idb_metadata_resource returns valid metadata with all required fields"""
    meta = idb_metadata_resource()
    assert_has_keys(meta, "path", "module", "base", "size", "md5", "sha256")
    assert_non_empty(meta["path"])
    assert_non_empty(meta["module"])
    assert_valid_address(meta["base"])
    assert_valid_address(meta["size"])


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


@test()
def test_resource_types():
    """types_resource returns list of local types"""
    result = types_resource()
    assert_is_list(result)
    # If there are types, check structure
    if result:
        type_item = result[0]
        assert_has_keys(type_item, "ordinal", "name", "type")


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


