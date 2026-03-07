"""Tests for api_resources MCP resource functions."""

from ..framework import (
    test,
    skip_test,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
)
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
from ..sync import IDAError


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"
CRACKME_CALL_TO_CHECK_PW = "0x12d3"


@test(binary="crackme03.elf")
def test_resource_idb_metadata():
    """idb_metadata_resource returns crackme metadata with valid hashes and addresses."""
    result = idb_metadata_resource()
    assert_non_empty(result["path"])
    assert result["module"] == "crackme03.elf"
    assert_valid_address(result["base"])
    assert_valid_address(result["size"])
    assert len(result["md5"]) == 32
    assert len(result["sha256"]) == 64


@test()
def test_resource_idb_segments():
    """idb_segments_resource returns a non-empty segment list with sane ranges."""
    result = idb_segments_resource()
    assert_is_list(result, min_length=1)
    for segment in result:
        assert_non_empty(segment["name"])
        assert_valid_address(segment["start"])
        assert_valid_address(segment["end"])
        assert_valid_address(segment["size"])
        assert int(segment["end"], 16) >= int(segment["start"], 16)


@test(binary="crackme03.elf")
def test_resource_idb_entrypoints_contains_known_symbols():
    """idb_entrypoints_resource exposes the known crackme entrypoints."""
    result = idb_entrypoints_resource()
    assert_is_list(result, min_length=1)
    by_name = {entry["name"]: entry["addr"] for entry in result}
    assert by_name.get("main") == CRACKME_MAIN
    assert by_name.get("check_pw") == CRACKME_CHECK_PW


@test()
def test_resource_cursor():
    """cursor_resource returns a structured cursor object or a runtime skip in unsupported mode."""
    try:
        result = cursor_resource()
    except IDAError as e:
        skip_test(str(e))
    assert_valid_address(result["addr"])
    if "function" in result:
        assert_valid_address(result["function"]["addr"])
        assert_non_empty(result["function"]["name"])


@test()
def test_resource_selection():
    """selection_resource returns either a selection range or an explicit null selection."""
    try:
        result = selection_resource()
    except IDAError as e:
        skip_test(str(e))
    if "selection" in result:
        assert result["selection"] is None
    else:
        assert_valid_address(result["start"])
        if result["end"] is not None:
            assert_valid_address(result["end"])


@test()
def test_resource_types_non_empty():
    """types_resource returns at least one local type."""
    result = types_resource()
    assert_is_list(result, min_length=1)
    for item in result:
        assert item["ordinal"] > 0
        assert_non_empty(item["name"])
        assert_non_empty(item["type"])


@test()
def test_resource_structs_non_empty():
    """structs_resource returns at least one structure."""
    result = structs_resource()
    assert_is_list(result, min_length=1)
    for item in result:
        assert_non_empty(item["name"])
        assert_valid_address(item["size"])
        assert isinstance(item["is_union"], bool)


@test()
def test_resource_struct_name_known_struct():
    """struct_name_resource round-trips a real structure name returned by structs_resource."""
    structs = structs_resource()
    assert_is_list(structs, min_length=1)

    target = None
    result = None
    for item in structs[:100]:
        candidate = struct_name_resource(item["name"])
        if candidate.get("error") is None and candidate.get("members"):
            target = item
            result = candidate
            break

    if result is None:
        skip_test("no populated structure definition available in this IDB")

    assert result.get("error") is None
    assert result["name"] == target["name"]
    assert result["size"] == target["size"]
    assert_is_list(result["members"], min_length=1)
    for member in result["members"]:
        assert_non_empty(member["name"])
        assert_valid_address(member["offset"])
        assert_valid_address(member["size"])


@test()
def test_resource_struct_name_not_found():
    """struct_name_resource reports a missing structure deterministically."""
    result = struct_name_resource("NonExistentStruct12345")
    assert "Structure not found" in result["error"]


@test(binary="crackme03.elf")
def test_resource_import_name():
    """import_name_resource returns the known printf import."""
    result = import_name_resource("printf@@GLIBC_2.2.5")
    assert result["addr"] == "0x4040"
    assert result["name"] == "printf@@GLIBC_2.2.5"
    assert result["module"] == ".dynsym"


@test(binary="crackme03.elf")
def test_resource_export_name():
    """export_name_resource returns the known main export/entrypoint."""
    result = export_name_resource("main")
    assert result["addr"] == CRACKME_MAIN
    assert result["name"] == "main"
    assert result["ordinal"] > 0


@test(binary="crackme03.elf")
def test_resource_xrefs_from():
    """xrefs_from_resource returns the known outgoing references from the check_pw call site."""
    result = xrefs_from_resource(CRACKME_CALL_TO_CHECK_PW)
    assert_is_list(result, min_length=1)
    by_addr = {entry["addr"]: entry["type"] for entry in result}
    assert by_addr.get(CRACKME_CHECK_PW) == "code"
    assert by_addr.get("0x12d8") == "code"
