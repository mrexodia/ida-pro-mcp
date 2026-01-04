"""Tests for api_resources MCP resource functions."""

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

# Import resource functions under test
from ..api_resources import (
    idb_metadata_resource,
    idb_segments_resource,
    idb_entrypoints_resource,
    cursor_resource,
    selection_resource,
    types_resource,
    structs_resource,
    struct_name_resource,
    import_name_resource,
    export_name_resource,
    xrefs_from_resource,
)

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests for idb_metadata_resource
# ============================================================================


@test()
def test_resource_idb_metadata():
    """idb_metadata_resource returns IDB metadata"""
    result = idb_metadata_resource()
    assert isinstance(result, dict)
    assert_has_keys(result, "path", "module", "base", "size")
    assert_non_empty(result["path"])
    assert_valid_address(result["base"])


# ============================================================================
# Tests for idb_segments_resource
# ============================================================================


@test()
def test_resource_idb_segments():
    """idb_segments_resource returns segments list"""
    result = idb_segments_resource()
    assert isinstance(result, list)
    if result:
        assert_has_keys(result[0], "name", "start", "end")


# ============================================================================
# Tests for idb_entrypoints_resource
# ============================================================================


@test()
def test_resource_idb_entrypoints():
    """idb_entrypoints_resource returns entry points"""
    result = idb_entrypoints_resource()
    assert isinstance(result, list)


# ============================================================================
# Tests for cursor_resource
# ============================================================================


@test()
def test_resource_cursor():
    """cursor_resource returns cursor info"""
    try:
        result = cursor_resource()
        assert isinstance(result, dict)
        # Should have addr key
        assert_has_keys(result, "addr")
    except IDAError:
        pass  # May fail in headless mode


# ============================================================================
# Tests for selection_resource
# ============================================================================


@test()
def test_resource_selection():
    """selection_resource returns selection info"""
    try:
        result = selection_resource()
        assert isinstance(result, dict)
    except IDAError:
        pass  # May fail in headless mode


# ============================================================================
# Tests for types_resource
# ============================================================================


@test()
def test_resource_types():
    """types_resource returns local types"""
    result = types_resource()
    assert isinstance(result, list)


# ============================================================================
# Tests for structs_resource
# ============================================================================


@test()
def test_resource_structs():
    """structs_resource returns structures list"""
    result = structs_resource()
    assert isinstance(result, list)


# ============================================================================
# Tests for struct_name_resource
# ============================================================================


@test()
def test_resource_struct_name():
    """struct_name_resource returns structure info"""
    # Try to get a structure (may not exist)
    try:
        result = struct_name_resource("test")
        assert isinstance(result, dict)
    except IDAError:
        pass  # Structure may not exist


@test()
def test_resource_struct_name_not_found():
    """struct_name_resource handles non-existent structure"""
    try:
        result = struct_name_resource("NonExistentStruct12345")
        # Should return error or empty
    except IDAError:
        pass  # Expected for non-existent struct


# ============================================================================
# Tests for import_name_resource
# ============================================================================


@test()
def test_resource_import_name():
    """import_name_resource returns import info"""
    # Try to get an import (name depends on binary)
    try:
        result = import_name_resource("printf")
        assert isinstance(result, dict)
    except IDAError:
        pass  # Import may not exist in this binary


# ============================================================================
# Tests for export_name_resource
# ============================================================================


@test()
def test_resource_export_name():
    """export_name_resource returns export info"""
    # Try to get main
    try:
        result = export_name_resource("main")
        assert isinstance(result, dict)
    except IDAError:
        pass  # Export may not exist


# ============================================================================
# Tests for xrefs_from_resource
# ============================================================================


@test()
def test_resource_xrefs_from():
    """xrefs_from_resource returns cross-references"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = xrefs_from_resource(fn_addr)
    assert isinstance(result, list)
