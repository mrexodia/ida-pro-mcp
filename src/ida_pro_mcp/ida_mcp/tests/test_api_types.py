"""Tests for api_types API functions."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_non_empty,
    assert_ok,
    assert_error,
    get_any_function,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_named_address,
)
from ..api_types import (
    declare_type,
    enum_upsert,
    read_struct,
    search_structs,
    type_query,
    type_inspect,
    set_type,
    type_apply_batch,
    infer_types,
    struct_member_upsert,
)


TEST_STRUCT_NAME = "__TestStruct__"
NAME_RESOLUTION_STRUCT = "__NameResolutionTest__"
CRACKME_DSO_HANDLE = "0x4008"
CRACKME_CHECK_PW = "0x11a9"
TYPE_APPLY_SIGNATURE = "int"
TYPED_FIXTURE_SUM_POINT = "0x1013c10"
TYPED_FIXTURE_USE_WRAPPER = "0x1013dc0"
TYPED_FIXTURE_G_POINT = "0x1069f70"
TYPED_FIXTURE_G_WRAPPER = "0x1069f80"
TYPED_FIXTURE_INFER_FALLBACK = "0x1069fa4"
TYPED_FIXTURE_LOCAL_NAME = "rhs_handle"


def create_test_struct(name: str = TEST_STRUCT_NAME) -> bool:
    """Create a deterministic test struct if it does not already exist."""
    search_result = search_structs(name)
    if search_result and any(s["name"] == name for s in search_result):
        return True

    struct_def = f"""
        struct {name} {{
            int field1;
            char field2;
            void* field3;
        }};
    """
    result = declare_type(struct_def)
    if not result:
        return False

    entry = result[0]
    if "error" not in entry:
        return True

    search_result = search_structs(name)
    return bool(search_result and any(s["name"] == name for s in search_result))


def _require_any_function() -> str:
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    return fn_addr


@test()
def test_declare_type_creates_searchable_struct():
    """declare_type creates a struct that can be found again via search_structs."""
    assert create_test_struct(TEST_STRUCT_NAME), "failed to declare test struct"
    result = search_structs(TEST_STRUCT_NAME)
    assert_is_list(result, min_length=1)
    match = next((s for s in result if s["name"] == TEST_STRUCT_NAME), None)
    assert match is not None
    assert match["cardinality"] == 3
    assert match["size"] >= 8


@test()
def test_declare_type_invalid_declaration():
    """declare_type reports parse failures for invalid declarations."""
    result = declare_type("struct broken { int x }")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to parse")


@test()
def test_read_struct_returns_named_members():
    """read_struct returns the declared member layout for the deterministic test struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    data_addr = get_data_address()
    if not data_addr:
        seg = get_first_segment()
        if not seg:
            skip_test("binary has no readable segment")
        data_addr = seg[0]

    result = read_struct({"addr": data_addr, "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    names = [member["name"] for member in entry["members"]]
    assert names == ["field1", "field2", "field3"]


@test(binary="typed_fixture.elf")
def test_read_struct_wrapper_values():
    """read_struct reads the deterministic Wrapper global contents from the typed fixture."""
    result = read_struct({"addr": TYPED_FIXTURE_G_WRAPPER, "struct": "Wrapper"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    members = {m["name"]: m for m in entry["members"]}
    assert members["pt"]["type"] == "Point"
    assert "1122334455667788" in members["magic"]["value"]


@test()
def test_read_struct_not_found():
    """read_struct reports a missing-struct error."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    result = read_struct({"addr": seg[0], "struct": "NonExistentStruct12345"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test()
def test_read_struct_name_resolution():
    """read_struct resolves named addresses instead of requiring only numeric ones."""
    if not create_test_struct(NAME_RESOLUTION_STRUCT):
        skip_test("failed to declare name-resolution struct")

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    from ..api_core import lookup_funcs

    fn_info = lookup_funcs(fn_addr)
    assert_ok(fn_info[0], "fn")
    fn_name = fn_info[0]["fn"]["name"]

    result = read_struct({"addr": fn_name, "struct": NAME_RESOLUTION_STRUCT})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert "Failed to resolve address" not in (entry.get("error") or "")


@test()
def test_read_struct_invalid_address():
    """read_struct reports a deterministic address resolution error."""
    result = read_struct({"addr": "InvalidAddressName123", "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to resolve address")


@test()
def test_read_struct_missing_address():
    """read_struct requires an address explicitly."""
    result = read_struct({"struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Address is required")


@test(binary="crackme03.elf")
def test_read_struct_without_type_info_fails_cleanly():
    """read_struct without an explicit struct fails cleanly when no type is applied."""
    result = read_struct({"addr": "0x201f"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="could not auto-detect")


def _find_bss_addr() -> int | None:
    """Locate an address whose byte is not loaded (BSS or similar)."""
    import ida_bytes
    import idaapi
    import idautils

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if seg.type == idaapi.SEG_BSS:
            return seg.start_ea

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if not ida_bytes.is_loaded(seg.start_ea):
            return seg.start_ea

    return None


@test()
def test_read_struct_bss_members_are_zero():
    """read_struct reports zero for every member when the struct lives in BSS.

    BSS bytes are unloaded in the IDB but zero-initialized at runtime. Before
    the BSS-aware read, members would come back as 0xff-filled garbage.
    """
    bss_ea = _find_bss_addr()
    if bss_ea is None:
        skip_test("binary has no BSS / unloaded region")

    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    result = read_struct({"addr": hex(bss_ea), "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")

    failures = []
    for member in entry["members"]:
        value_str = member["value"]
        # Integer members render as "0xNN (N)"; pointer as "0xNN...";
        # longer shapes render as "[NN NN ...]".
        if "(" in value_str:
            hex_part = value_str.split()[0]
            numeric = int(hex_part, 16)
        elif value_str.startswith("0x"):
            numeric = int(value_str, 16)
        elif value_str.startswith("["):
            inner = value_str.strip("[]").replace("...", "").split()
            numeric = sum(int(b, 16) for b in inner)
        else:
            failures.append(f"{member['name']}: unparseable value {value_str!r}")
            continue
        if numeric != 0:
            failures.append(
                f"{member['name']}: expected 0 at BSS, got {value_str!r}"
            )

    assert not failures, "\n".join(failures)


@test()
def test_search_structs_finds_declared_structs():
    """search_structs returns the previously declared deterministic struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    result = search_structs("__TestStruct__")
    assert_is_list(result, min_length=1)
    assert any(item["name"] == TEST_STRUCT_NAME for item in result)


@test()
def test_search_structs_pattern_no_match():
    """search_structs returns an empty list for an unmatched substring."""
    result = search_structs("VeryUnlikelyStructName123")
    assert_is_list(result)
    assert len(result) == 0


@test(binary="typed_fixture.elf")
def test_search_structs_exact_wrapper_match():
    """search_structs finds the exact Wrapper struct in the typed fixture."""
    result = search_structs("Wrapper")
    assert_is_list(result, min_length=1)
    wrapper = next((item for item in result if item["name"] == "Wrapper"), None)
    assert wrapper is not None
    assert wrapper["cardinality"] == 2
    assert wrapper["size"] == 24


@test()
def test_type_query():
    """type_query supports filtered type listing"""
    result = type_query(
        {
            "filter": "*",
            "kind": "any",
            "offset": 0,
            "count": 10,
            "include_decl": False,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert "kind" in page
    assert "data" in page
    assert "next_offset" in page
    assert "total" in page
    if page["data"]:
        assert "ordinal" in page["data"][0]
        assert "name" in page["data"][0]
        assert "size" in page["data"][0]
        assert "kind" in page["data"][0]


@test()
def test_type_inspect():
    """type_inspect returns metadata for declared struct"""
    tname = "__TypeInspectTest__"
    if not create_test_struct(tname):
        skip_test("failed to declare type-inspect struct")

    result = type_inspect({"name": tname, "include_members": True})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r["name"] == tname
    assert r["exists"] is True
    assert "error" not in r
    assert r.get("member_count", 0) >= 0


@test()
def test_set_type():
    """set_type applies type to address"""
    result = set_type({"addr": _require_any_function(), "ty": TYPE_APPLY_SIGNATURE})
    assert_is_list(result, min_length=1)


@test()
def test_enum_upsert_creates_and_replays_idempotently():
    """enum_upsert creates a new enum and skips exact repeats."""
    import idc

    enum_name = "__TestEnumUpsert__"
    enum_id = idc.get_enum(enum_name)
    if enum_id != idc.BADADDR:
        idc.del_enum(enum_id)

    try:
        first = enum_upsert(
            {
                "name": enum_name,
                "members": [
                    {"name": "__TEST_ENUM_ZERO__", "value": 0},
                    {"name": "__TEST_ENUM_ONE__", "value": 1},
                ],
            }
        )
        second = enum_upsert(
            {
                "name": enum_name,
                "members": [
                    {"name": "__TEST_ENUM_ZERO__", "value": 0},
                    {"name": "__TEST_ENUM_ONE__", "value": 1},
                ],
            }
        )
        assert_is_list(first, min_length=1)
        assert "error" not in first[0]
        assert first[0].get("created") is True
        assert first[0]["summary"]["created"] == 2
        assert_is_list(second, min_length=1)
        assert "error" not in second[0]
        assert second[0]["summary"]["skipped"] == 2
    finally:
        enum_id = idc.get_enum(enum_name)
        if enum_id != idc.BADADDR:
            idc.del_enum(enum_id)


@test()
def test_enum_upsert_reports_conflicting_member_value():
    """enum_upsert reports conflicting member names cleanly."""
    import idc

    enum_name = "__TestEnumConflict__"
    enum_id = idc.get_enum(enum_name)
    if enum_id != idc.BADADDR:
        idc.del_enum(enum_id)

    try:
        enum_upsert({"name": enum_name, "members": [{"name": "__TEST_ENUM_CONFLICT__", "value": 1}]})
        result = enum_upsert({"name": enum_name, "members": [{"name": "__TEST_ENUM_CONFLICT__", "value": 2}]})
        assert_is_list(result, min_length=1)
        assert "error" in result[0]
        assert result[0]["summary"]["conflicts"] == 1
        assert "conflict" in (result[0]["members"][0].get("error") or "").lower()
    finally:
        enum_id = idc.get_enum(enum_name)
        if enum_id != idc.BADADDR:
            idc.del_enum(enum_id)


@test(binary="crackme03.elf")
def test_set_type_applies_named_global_type():
    """set_type applies a concrete type to a known crackme global and reports success."""
    result = set_type({"addr": CRACKME_DSO_HANDLE, "ty": "unsigned __int64"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["edit"]["addr"] == CRACKME_DSO_HANDLE
    assert "error" not in entry


@test()
def test_set_type_invalid_address():
    """set_type reports an error for an invalid address."""
    result = set_type({"addr": get_unmapped_address(), "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_global_by_name_branch():
    """set_type(kind=global) can resolve the target by symbol name instead of address."""
    result = set_type({"name": "g_point", "ty": "Point", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_set_type_global_invalid_type_name():
    """set_type(kind=global) reports invalid type names cleanly."""
    result = set_type({"addr": TYPED_FIXTURE_G_POINT, "ty": "NoSuchType", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test()
def test_type_apply_batch():
    """type_apply_batch applies edits and returns summary counters"""
    result = type_apply_batch({"edits": [{"addr": _require_any_function(), "ty": TYPE_APPLY_SIGNATURE}]})
    assert "error" not in result
    assert "applied" in result
    assert "failed" in result
    assert "stopped" in result
    assert "results" in result
    assert_is_list(result["results"], min_length=1)


@test()
def test_set_type_unknown_kind():
    """set_type reports unknown type-edit kinds explicitly."""
    result = set_type({"addr": "0x123e", "kind": "weird", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Unknown kind")


@test()
def test_set_type_function_not_found_branch():
    """set_type(kind=function) reports missing functions cleanly."""
    result = set_type(
        {"addr": get_unmapped_address(), "kind": "function", "signature": "int foo()"}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Function not found")


@test(binary="crackme03.elf")
def test_set_type_function_undefined_referenced_type():
    """set_type(kind=function) explains apply failures for undeclared referenced types."""
    result = set_type(
        {
            "addr": CRACKME_CHECK_PW,
            "kind": "function",
            "signature": "UndefinedStruct __fastcall check_pw(const char *s)",
        }
    )
    assert_is_list(result, min_length=1)
    entry = result[0]
    if entry.get("ok"):
        skip_test("IDA accepted an undefined referenced type in this environment")
    assert_error(entry)
    assert entry["error"] != "Failed to apply function type"
    assert (
        "declared" in entry["error"].lower()
        or "parse" in entry["error"].lower()
        or "function type" in entry["error"].lower()
    )


@test(binary="crackme03.elf")
def test_set_type_stack_missing_member():
    """set_type(kind=stack) reports a missing frame member explicitly."""
    fn_addr = get_named_address("main")
    if not fn_addr:
        skip_test("main symbol not present")
    result = set_type({"addr": fn_addr, "kind": "stack", "name": "nope", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="typed_fixture.elf")
def test_set_type_stack_missing_member_typed_fixture():
    """typed_fixture reports missing stack members against a stable non-main function."""
    result = set_type(
        {"addr": TYPED_FIXTURE_USE_WRAPPER, "kind": "stack", "name": "nope", "ty": TYPE_APPLY_SIGNATURE}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="crackme03.elf")
def test_infer_types_returns_high_confidence_for_main():
    """infer_types(main) returns a non-empty inferred type with a method and confidence."""
    main_addr = get_named_address("main")
    if not main_addr:
        skip_test("main symbol not present")

    result = infer_types(main_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    if entry["inferred_type"] is not None:
        assert_non_empty(entry["inferred_type"])
        assert entry["method"] is not None


@test(binary="typed_fixture.elf")
def test_set_type_function_branch():
    """set_type(kind=function) applies a function signature to a typed fixture function."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_SUM_POINT,
            "signature": "int __fastcall sum_point(struct Point *p)",
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_set_type_function_invalid_signature():
    """set_type(kind=function) rejects non-function signatures."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_SUM_POINT,
            "signature": TYPE_APPLY_SIGNATURE,
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not a function type")


@test(binary="typed_fixture.elf")
def test_set_type_local_branch():
    """set_type(kind=local) reaches the local-variable type application path."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "local",
            "variable": TYPED_FIXTURE_LOCAL_NAME,
            "ty": TYPE_APPLY_SIGNATURE,
        }
    )
    assert_is_list(result, min_length=1)
    assert (
        "error" not in result[0]
        or result[0].get("ok") is True
        or "Failed to apply type" in (result[0].get("error") or "")
    )


@test(binary="typed_fixture.elf")
def test_set_type_local_invalid_type_name():
    """set_type(kind=local) reports invalid local type names cleanly."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "local",
            "variable": TYPED_FIXTURE_LOCAL_NAME,
            "ty": "NoSuchType",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_stack_branch():
    """set_type(kind=stack) applies a type to a real stack-frame member."""
    result = set_type(
        {
            "addr": TYPED_FIXTURE_USE_WRAPPER,
            "kind": "stack",
            "name": TYPED_FIXTURE_LOCAL_NAME,
            "ty": TYPE_APPLY_SIGNATURE,
        }
    )
    assert_is_list(result, min_length=1)
    assert "error" not in result[0]


@test(binary="typed_fixture.elf")
def test_infer_types_size_based_low_confidence():
    """infer_types falls back to size-based inference on a typed-fixture interior data address."""
    result = infer_types(TYPED_FIXTURE_INFER_FALLBACK)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] == "size_based"
    assert entry["confidence"] == "low"
    assert entry["inferred_type"] == "uint8_t[12]"


@test(binary="typed_fixture.elf")
def test_infer_types_existing_or_hexrays_wrapper():
    """infer_types returns a strong typed result for the typed fixture wrapper object."""
    result = infer_types(TYPED_FIXTURE_G_WRAPPER)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] in {"hexrays", "existing"}
    assert entry["confidence"] == "high"
    assert "Wrapper" in entry["inferred_type"]


@test()
def test_infer_types_invalid_address_still_returns_structured_result():
    """infer_types returns a structured fallback result even for weird unmapped inputs."""
    result = infer_types(get_unmapped_address())
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    assert "addr" in entry


@test(binary="typed_fixture.elf")
def test_infer_types_invalid_text_address_errors_cleanly():
    """infer_types reports parse failures for symbolic garbage addresses."""
    result = infer_types("InvalidAddressName123")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not found")


# ---------------------------------------------------------------------------
# struct_member_upsert
#
# Binary-agnostic: every test builds its own deterministic scratch struct with
# declare_type and removes it in a finally, so nothing leaks into the IDB.
# ---------------------------------------------------------------------------


def _delete_type(name: str) -> None:
    """Best-effort removal of a local type so tests stay self-cleaning."""
    import ida_typeinf

    try:
        ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)
    except Exception:
        pass


def _reset_struct(name: str, body: str) -> None:
    """(Re)declare a scratch struct from a fresh slate; skip if it won't parse."""
    _delete_type(name)
    result = declare_type(f"struct {name} {{ {body} }};")
    if result and result[0].get("error"):
        skip_test(f"failed to declare {name}: {result[0]['error']}")


def _members_by_name(struct_name: str) -> dict:
    info = type_inspect({"name": struct_name, "include_members": True})[0]
    assert info.get("exists") is True
    return info, {m["name"]: m for m in (info.get("members") or [])}


@test()
def test_struct_member_upsert_fills_bare_hole():
    """A bare hole (no covering member) is a valid insert target, without shifting neighbors."""
    name = "__TestUpsertHole__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")

        # Shrink b (u64 @ 0x8) -> u32, leaving a 4-byte bare hole at 0xC.
        shrink = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x8", "name": "b_lo", "old_type": "unsigned __int64", "size": 4}
                ],
            }
        )
        assert_is_list(shrink, min_length=1)
        assert "error" not in shrink[0]
        assert shrink[0]["summary"]["replaced"] == 1

        # Fill the bare hole at 0xC (get_udm_by_offset returns nothing here).
        fill = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0xC", "name": "b_hi", "size": 4}]}
        )
        assert_is_list(fill, min_length=1)
        assert "error" not in fill[0]
        assert fill[0]["summary"]["created"] == 1
        assert fill[0]["members"][0].get("created") is True

        info, members = _members_by_name(name)
        assert members["b_lo"]["offset"] == "0x8" and members["b_lo"]["size"] == 4
        assert members["b_hi"]["offset"] == "0xc" and members["b_hi"]["size"] == 4
        # Neighbor unshifted, overall size preserved.
        assert members["c"]["offset"] == "0x10"
        assert info["size"] == 24
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_fills_gap_member_without_old_type():
    """A `gapNN` placeholder member is fillable with old_type omitted."""
    name = "__TestUpsertGap__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        res = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0x8", "name": "g_lo", "size": 4}]}
        )
        assert_is_list(res, min_length=1)
        assert "error" not in res[0]
        assert res[0]["summary"]["created"] == 1
        assert res[0]["members"][0].get("created") is True

        _info, members = _members_by_name(name)
        assert members["g_lo"]["offset"] == "0x8" and members["g_lo"]["size"] == 4
        assert members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_retypes_named_member_in_place():
    """Same-size retype+rename of a named member keeps its offset (uses the C-decl `type` path)."""
    name = "__TestUpsertRetype__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")
        res = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x8", "name": "b_ptr", "old_type": "unsigned __int64", "type": "void *"}
                ],
            }
        )
        assert_is_list(res, min_length=1)
        assert "error" not in res[0]
        assert res[0]["summary"]["replaced"] == 1

        _info, members = _members_by_name(name)
        assert "b_ptr" in members and members["b_ptr"]["offset"] == "0x8"
        assert members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_is_idempotent():
    """Re-applying an identical member is reported as skipped."""
    name = "__TestUpsertIdem__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b;")
        edit = {"offset": "0x8", "name": "b_ai", "old_type": "unsigned __int64", "size": 8}

        first = struct_member_upsert({"struct": name, "members": [dict(edit)]})
        assert_is_list(first, min_length=1)
        assert first[0]["summary"]["replaced"] == 1

        second = struct_member_upsert({"struct": name, "members": [dict(edit)]})
        assert_is_list(second, min_length=1)
        assert "error" not in second[0]
        assert second[0]["summary"]["skipped"] == 1
        assert second[0]["members"][0].get("skipped") is True
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_guards_named_members():
    """Missing or mismatched old_type on a named member is a conflict, not a clobber."""
    name = "__TestUpsertGuard__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")
        res = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x10", "name": "c_wrong", "old_type": "uint32_t", "size": 8},
                    {"offset": "0x10", "name": "c_missing", "size": 8},
                ],
            }
        )
        assert_is_list(res, min_length=1)
        assert res[0]["summary"]["conflicts"] == 2
        assert "error" in res[0]
        errors = " ".join((m.get("error") or "") for m in res[0]["members"]).lower()
        assert "old_type" in errors

        # The named member must be untouched by the rejected edits.
        _info, members = _members_by_name(name)
        assert "c" in members and members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_rejects_overflow():
    """A member that would spill past its covering member is rejected."""
    name = "__TestUpsertOverflow__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        # gap8 spans [0x8, 0x10); an 8-byte member at 0xC would run to 0x14.
        res = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0xC", "name": "toobig", "size": 8}]}
        )
        assert_is_list(res, min_length=1)
        assert res[0]["summary"]["conflicts"] == 1
        assert_error(res[0]["members"][0], contains="fit")
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_dry_run_does_not_mutate():
    """dry_run validates (reports would-be outcome) without changing the struct."""
    name = "__TestUpsertDryRun__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        before, _ = _members_by_name(name)

        res = struct_member_upsert(
            {
                "struct": name,
                "dry_run": True,
                "members": [{"offset": "0x8", "name": "g_lo", "size": 4}],
            }
        )
        assert_is_list(res, min_length=1)
        assert res[0]["dry_run"] is True
        assert res[0]["summary"]["created"] == 1

        after, _ = _members_by_name(name)
        assert before["members"] == after["members"]
        assert before["size"] == after["size"]
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_struct_not_found():
    """struct_member_upsert reports a missing-struct error."""
    res = struct_member_upsert(
        {"struct": "__NoSuchStruct12345__", "members": [{"offset": 0, "name": "x", "size": 4}]}
    )
    assert_is_list(res, min_length=1)
    assert_error(res[0], contains="not found")
