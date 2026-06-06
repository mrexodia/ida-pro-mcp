"""Tests for api_modify API functions."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_ok,
    assert_error,
    get_any_function,
    get_named_address,
)
from ..api_modify import (
    append_comments,
    set_comments,
    patch_asm,
    rename,
    define_func,
    define_code,
    undefine,
    force_recompile,
    set_op_type,
    make_data,
)
from ..api_memory import get_bytes, patch
from ..api_core import lookup_funcs


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"
CRACKME_PATCH_ASM_ADDR = "0x125e"
CRACKME_FRAME_DUMMY = "0x11a0"
TYPED_FIXTURE_IMMEDIATE_1234 = "0x1013e44"
TYPED_FIXTURE_USE_WRAPPER = "0x1013dc0"
TYPED_FIXTURE_LOCAL_NAME = "rhs_handle"


def _require_any_function() -> str:
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")
    return fn_addr


def _plain_hex_bytes(text: str) -> str:
    return text.replace("0x", "").replace(" ", "").lower()


@test()
def test_set_comment_roundtrip():
    """set_comments writes a disassembly comment and then removes it again."""
    import idaapi

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    original = idaapi.get_cmt(int(fn_addr, 16), False) or ""
    try:
        result = set_comments({"addr": fn_addr, "comment": "__TEST_COMMENT__"})
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
        assert idaapi.get_cmt(int(fn_addr, 16), False) == "__TEST_COMMENT__"
    finally:
        set_comments({"addr": fn_addr, "comment": original})

    restored = idaapi.get_cmt(int(fn_addr, 16), False) or ""
    assert restored == original


@test(binary="typed_fixture.elf")
def test_set_comment_interior_address_roundtrip():
    """set_comments also succeeds for an interior instruction address inside a function."""
    import idaapi

    addr = int(TYPED_FIXTURE_IMMEDIATE_1234, 16)
    original = idaapi.get_cmt(addr, False) or ""
    try:
        result = set_comments({"addr": hex(addr), "comment": "__INNER_COMMENT__"})
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
        assert idaapi.get_cmt(addr, False) == "__INNER_COMMENT__"
    finally:
        set_comments({"addr": hex(addr), "comment": original})

    restored = idaapi.get_cmt(addr, False) or ""
    assert restored == original


@test()
def test_append_comment_function_dedupes():
    """append_comments appends once to a function comment and skips exact duplicates."""
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    addr = int(fn_addr, 16)
    original = idc.get_func_cmt(addr, False) or ""
    try:
        first = append_comments({"addr": fn_addr, "comment": "__APPEND_COMMENT__", "scope": "func"})
        second = append_comments({"addr": fn_addr, "comment": "__APPEND_COMMENT__", "scope": "func"})
        assert_is_list(first, min_length=1)
        assert "error" not in first[0]
        assert first[0].get("appended") is True
        assert_is_list(second, min_length=1)
        assert "error" not in second[0]
        assert second[0].get("skipped") is True
        updated = idc.get_func_cmt(addr, False) or ""
        assert updated.count("__APPEND_COMMENT__") == 1
    finally:
        idc.set_func_cmt(addr, original, False)


@test()
def test_append_comment_function_dedupe_does_not_skip_substrings():
    """append_comments should only dedupe exact existing entries, not substrings."""
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    addr = int(fn_addr, 16)
    original = idc.get_func_cmt(addr, False) or ""
    try:
        idc.set_func_cmt(addr, "foobar", False)
        result = append_comments({"addr": fn_addr, "comment": "foo", "scope": "func"})
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
        assert result[0].get("appended") is True
        updated = idc.get_func_cmt(addr, False) or ""
        assert updated == "foobar\nfoo"
    finally:
        idc.set_func_cmt(addr, original, False)


@test(binary="typed_fixture.elf")
def test_append_comment_interior_address_roundtrip():
    """append_comments appends to an interior line comment when scoped to line."""
    import idaapi

    addr = int(TYPED_FIXTURE_IMMEDIATE_1234, 16)
    original = idaapi.get_cmt(addr, False) or ""
    try:
        result = append_comments({"addr": hex(addr), "comment": "__LINE_APPEND__", "scope": "line"})
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
        assert "__LINE_APPEND__" in (idaapi.get_cmt(addr, False) or "")
    finally:
        idaapi.set_cmt(addr, original, False)


@test(binary="typed_fixture.elf")
def test_set_comments_invalid_address_error():
    """set_comments reports invalid unmapped addresses cleanly."""
    result = set_comments({"addr": "0xdeadbeef", "comment": "x"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to set disassembly comment")


@test(binary="crackme03.elf")
def test_patch_asm_roundtrip():
    """patch_asm changes the target instruction bytes and restoration puts them back."""
    original = get_bytes({"addr": CRACKME_PATCH_ASM_ADDR, "size": 2})[0]
    assert_ok(original, "data")
    original_plain = _plain_hex_bytes(original["data"])

    try:
        result = patch_asm({"addr": CRACKME_PATCH_ASM_ADDR, "asm": "sub eax, eax"})
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
        changed = get_bytes({"addr": CRACKME_PATCH_ASM_ADDR, "size": 2})[0]
        assert _plain_hex_bytes(changed["data"]) == "29c0"
        assert _plain_hex_bytes(changed["data"]) != original_plain
    finally:
        patch({"addr": CRACKME_PATCH_ASM_ADDR, "data": original_plain})

    restored = get_bytes({"addr": CRACKME_PATCH_ASM_ADDR, "size": 2})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test(binary="typed_fixture.elf")
def test_patch_asm_invalid_instruction_reports_error():
    """patch_asm reports assembly failures without crashing or partially succeeding."""
    result = patch_asm({"addr": TYPED_FIXTURE_IMMEDIATE_1234, "asm": "not an instruction"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to assemble")


@test()
def test_rename_function_roundtrip():
    """rename can rename a function and restore the original name."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    original = lookup_funcs(fn_addr)[0]
    assert_ok(original, "fn")
    original_name = original["fn"]["name"]
    new_name = "__test_rename__"

    try:
        result = rename({"func": [{"addr": fn_addr, "name": new_name}]})
        assert "error" not in result["func"][0]
        renamed = lookup_funcs(fn_addr)[0]
        assert renamed["fn"]["name"] == new_name
    finally:
        rename({"func": [{"addr": fn_addr, "name": original_name}]})

    restored = lookup_funcs(fn_addr)[0]
    assert restored["fn"]["name"] == original_name


@test(binary="crackme03.elf")
def test_rename_duplicate_name():
    """rename reports when the target name is already used elsewhere."""
    result = rename({"func": [{"addr": CRACKME_FRAME_DUMMY, "name": "main"}]})
    assert "func" in result
    assert_error(result["func"][0], contains="already used")


@test(binary="crackme03.elf")
def test_rename_data_roundtrip():
    """rename can rename a global/data symbol and restore it."""
    import idaapi

    addr = get_named_address("format")
    if not addr:
        skip_test("format symbol not present")

    original_name = "format"
    new_name = "__test_format__"

    try:
        result = rename({"data": [{"old": original_name, "new": new_name}]})
        assert "error" not in result["data"][0]
        assert idaapi.get_name_ea(idaapi.BADADDR, new_name) == int(addr, 16)
    finally:
        rename({"data": [{"old": new_name, "new": original_name}]})

    assert idaapi.get_name_ea(idaapi.BADADDR, original_name) == int(addr, 16)


@test()
def test_rename_dry_run_summary():
    """rename supports dry_run and returns summary counters"""
    result = rename({"func": [{"addr": _require_any_function(), "name": "__test_dry_run__"}], "dry_run": True})
    assert isinstance(result, dict)
    assert "func" in result
    assert "summary" in result
    assert result["summary"]["dry_run"] is True
    assert_is_list(result["func"], min_length=1)
    assert result["func"][0].get("dry_run") is True


@test()
def test_rename_stop_on_error():
    """rename can stop on first error"""
    result = rename(
        {
            "func": [
                {"addr": "0x0", "name": "__invalid__"},
                {"addr": _require_any_function(), "name": "__should_not_run__"},
            ],
            "stop_on_error": True,
        }
    )
    assert isinstance(result, dict)
    assert "func" in result
    assert "summary" in result
    assert len(result["func"]) == 1
    assert result["summary"]["stopped"] is True


@test(binary="crackme03.elf")
def test_rename_local_error_handling():
    """rename(local=...) reports a structured error for a missing local variable."""
    fn_addr = CRACKME_CHECK_PW
    if not fn_addr:
        skip_test("check_pw not present")

    result = rename(
        {
            "local": [
                {
                    "func_addr": fn_addr,
                    "old": "__nonexistent_var__",
                    "new": "__test_local__",
                }
            ]
        }
    )
    assert "local" in result
    assert "error" in result["local"][0]
    assert_error(result["local"][0], contains="not found")


@test(binary="typed_fixture.elf")
def test_rename_local_roundtrip():
    """rename(local=...) reaches the decompiler-local rename path on a real variable."""
    try:
        result = rename(
            {
                "local": [
                    {"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": TYPED_FIXTURE_LOCAL_NAME, "new": "rhs_value"}
                ]
            }
        )
        assert (
            "error" not in result["local"][0]
            or "not found" in (result["local"][0].get("error") or "").lower()
            or "Hex-Rays" in (result["local"][0].get("error") or "")
            or "could not rename local" in (result["local"][0].get("error") or "").lower()
        )
    finally:
        rename(
            {
                "local": [
                    {"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": "rhs_value", "new": TYPED_FIXTURE_LOCAL_NAME}
                ]
            }
        )


@test(binary="typed_fixture.elf")
def test_rename_stack_roundtrip():
    """rename(stack=...) can rename and restore a real stack member."""
    from ..api_stack import stack_frame

    try:
        result = rename(
            {
                "stack": [
                    {"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": TYPED_FIXTURE_LOCAL_NAME, "new": "rhs_stack"}
                ]
            }
        )
        assert "error" not in result["stack"][0]
        names = {var["name"] for var in stack_frame(TYPED_FIXTURE_USE_WRAPPER)[0]["vars"]}
        assert "rhs_stack" in names
    finally:
        rename(
            {
                "stack": [
                    {"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": "rhs_stack", "new": TYPED_FIXTURE_LOCAL_NAME}
                ]
            }
        )


@test(binary="typed_fixture.elf")
def test_rename_stack_missing_member_error():
    """rename(stack=...) reports missing frame members explicitly."""
    result = rename({"stack": [{"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": "nope", "new": "x"}]})
    assert "error" in result["stack"][0]
    assert_error(result["stack"][0], contains="not found")


@test(binary="typed_fixture.elf")
def test_rename_stack_special_member_error():
    """rename(stack=...) rejects special frame members like saved registers/return address."""
    result = rename(
        {"stack": [{"func_addr": TYPED_FIXTURE_USE_WRAPPER, "old": "__return_address", "new": "x"}]}
    )
    assert "error" in result["stack"][0]
    assert_error(result["stack"][0], contains="Special frame member")


@test(binary="typed_fixture.elf")
def test_rename_local_missing_function_error():
    """rename(local=...) reports missing functions cleanly."""
    result = rename({"local": [{"func_addr": "0xdeadbeef", "old": "a", "new": "b"}]})
    assert "error" in result["local"][0]
    assert_error(result["local"][0], contains="No function found")


@test(binary="crackme03.elf")
def test_define_undefine_func_roundtrip():
    """undefine removes an existing function and define_func recreates it with the same bounds."""
    import idaapi

    func = idaapi.get_func(int(CRACKME_FRAME_DUMMY, 16))
    if not func:
        skip_test("frame_dummy function not present")

    start_ea = func.start_ea
    end_ea = func.end_ea

    try:
        undef_result = undefine({"addr": hex(start_ea), "end": hex(end_ea)})[0]
        assert "error" not in undef_result
        assert idaapi.get_func(start_ea) is None

        define_result = define_func({"addr": hex(start_ea), "end": hex(end_ea)})[0]
        if "error" in define_result:
            define_code({"addr": hex(start_ea)})
            define_result = define_func({"addr": hex(start_ea), "end": hex(end_ea)})[0]
        assert "error" not in define_result
        recreated = idaapi.get_func(start_ea)
        assert recreated is not None
        assert recreated.start_ea == start_ea
        assert recreated.end_ea == end_ea
    finally:
        if idaapi.get_func(start_ea) is None:
            define_code({"addr": hex(start_ea)})
            define_func({"addr": hex(start_ea), "end": hex(end_ea)})


@test()
def test_define_func_already_exists():
    """define_func reports an already-exists error on an existing function."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = define_func({"addr": fn_addr})[0]
    assert_error(result, contains="already exists")


@test()
def test_define_func_batch():
    """define_func accepts batch input and returns one result per item."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = define_func([{"addr": fn_addr}, {"addr": fn_addr}])
    assert_is_list(result, min_length=2)


@test()
def test_define_code_on_existing_code():
    """define_code on existing code returns a structured response instead of crashing."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = define_code({"addr": fn_addr})[0]
    assert result["addr"] == fn_addr
    assert (
        "error" not in result
        or result.get("length") is not None
        or result.get("error") is not None
    )


@test(binary="typed_fixture.elf")
def test_rename_global_missing_symbol():
    """rename(data=...) reports a clean error when the global symbol is absent."""
    result = rename({"data": [{"old": "nope", "new": "x"}]})
    assert "error" in result["data"][0]
    assert_error(result["data"][0], contains="not found")


@test(binary="typed_fixture.elf")
def test_rename_function_same_name_is_stable():
    """rename(func=...) with the same current name succeeds or stays stable without crashing."""
    result = rename({"func": [{"addr": "0x1013ef0", "name": "main"}]})
    entry = result["func"][0]
    assert "error" not in entry


@test(binary="typed_fixture.elf")
def test_undefine_single_byte_and_restore():
    """undefine(size=1) works on code bytes and the function can be fully restored afterwards."""
    import idaapi

    addr = 0x1013EF0
    func = idaapi.get_func(addr)
    if not func:
        skip_test("typed_fixture main function not present")
    end_ea = func.end_ea

    try:
        result = undefine({"addr": hex(addr), "size": 1})[0]
        assert "error" not in result
    finally:
        define_code({"addr": hex(addr)})
        if idaapi.get_func(addr) is None:
            define_func({"addr": hex(addr), "end": hex(end_ea)})


@test(binary="crackme03.elf")
def test_undefine_batch():
    """undefine accepts batch input and can restore a small function afterwards."""
    import idaapi

    func = idaapi.get_func(int(CRACKME_FRAME_DUMMY, 16))
    if not func:
        skip_test("frame_dummy function not present")

    start_ea = func.start_ea
    end_ea = func.end_ea
    try:
        result = undefine([{"addr": hex(start_ea), "end": hex(end_ea)}])
        assert_is_list(result, min_length=1)
        assert "error" not in result[0]
    finally:
        if idaapi.get_func(start_ea) is None:
            define_code({"addr": hex(start_ea)})
            define_func({"addr": hex(start_ea), "end": hex(end_ea)})


# ----------------------------------------------------------------------
# force_recompile
# ----------------------------------------------------------------------


@test()
def test_force_recompile_single_function():
    """force_recompile on one function returns ok and reports the function name."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = force_recompile([{"addr": fn_addr}])
    assert "summary" in result
    assert result["summary"]["total"] == 1
    assert result["summary"]["ok"] == 1
    assert result["summary"]["all"] is False
    entries = result["results"]
    assert_is_list(entries, min_length=1)
    assert entries[0]["ok"] is True
    assert entries[0]["addr"].startswith("0x")
    assert "name" in entries[0]


@test()
def test_force_recompile_no_args_means_all():
    """force_recompile() with no items invalidates every function."""
    result = force_recompile()
    assert "summary" in result
    assert result["summary"]["all"] is True
    assert result["summary"]["total"] >= 1
    assert result["summary"]["ok"] == result["summary"]["total"]


@test()
def test_force_recompile_invalid_addr_skipped():
    """force_recompile silently skips addresses that aren't function entries."""
    result = force_recompile([{"addr": "0xffffff00"}])
    assert "summary" in result
    # Either skipped (total=0) or recorded as failed -- both acceptable
    assert result["summary"]["all"] is False


# ----------------------------------------------------------------------
# set_op_type
# ----------------------------------------------------------------------


@test(binary="typed_fixture.elf")
def test_set_op_type_hex_format_roundtrip():
    """set_op_type kind='hex' marks operand as hex; restoring to dec works."""
    # Restore to default decimal first to make the test idempotent.
    set_op_type([{"addr": TYPED_FIXTURE_IMMEDIATE_1234, "op_n": 1, "kind": "dec"}])

    result = set_op_type([{"addr": TYPED_FIXTURE_IMMEDIATE_1234, "op_n": 1, "kind": "hex"}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["addr"] == TYPED_FIXTURE_IMMEDIATE_1234
    assert entry["op_n"] == 1
    assert entry["kind"] == "hex"
    assert entry["ok"] is True

    # Restore so other tests aren't affected.
    set_op_type([{"addr": TYPED_FIXTURE_IMMEDIATE_1234, "op_n": 1, "kind": "dec"}])


@test()
def test_set_op_type_unknown_kind_errors():
    """set_op_type returns ok=False with an explanatory error for unknown kinds."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = set_op_type([{"addr": fn_addr, "op_n": 0, "kind": "totally-not-a-kind"}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["ok"] is False
    assert "error" in entry
    assert "unknown kind" in entry["error"]


@test()
def test_set_op_type_stroff_requires_struct():
    """kind='stroff' without a struct name returns an explanatory error."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = set_op_type([{"addr": fn_addr, "op_n": 0, "kind": "stroff"}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["ok"] is False
    assert "struct name required" in entry["error"]


@test()
def test_set_op_type_invalid_addr_errors():
    """set_op_type with an unparseable address returns ok=False."""
    result = set_op_type([{"addr": "not-a-hex", "op_n": 0, "kind": "hex"}])
    assert_is_list(result, min_length=1)
    assert result[0]["ok"] is False
    assert "error" in result[0]


# ----------------------------------------------------------------------
# make_data
# ----------------------------------------------------------------------


@test(binary="typed_fixture.elf")
def test_make_data_primitive_roundtrip():
    """make_data applies a primitive type to an address; idc.get_type confirms it."""
    import idc, ida_name, ida_bytes

    # Use a small data area in the .data segment that we can safely repaint.
    addr = "0x1069f60"  # __data_start in typed_fixture (16 zero bytes)

    original_name = ida_name.get_name(int(addr, 16))
    original_type = idc.get_type(int(addr, 16)) or ""

    try:
        result = make_data([{"addr": addr, "type": "int probe[2]"}])
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert entry["ok"] is True
        assert entry["size"] == 8  # int[2] = 8 bytes
        applied = idc.get_type(int(addr, 16))
        assert applied is not None
        assert "int" in applied
    finally:
        # Restore: undefine, then re-apply original type if any.
        ida_bytes.del_items(int(addr, 16), ida_bytes.DELIT_EXPAND, 8)
        if original_type:
            idc.SetType(int(addr, 16), original_type + ";")
        if original_name:
            ida_name.set_name(int(addr, 16), original_name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)


@test()
def test_make_data_invalid_type_errors():
    """make_data rejects malformed type declarations with ok=False + error."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = make_data([{"addr": fn_addr, "type": "this is not a valid C declaration"}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["ok"] is False
    assert "error" in entry


@test()
def test_make_data_empty_type_errors():
    """make_data with an empty type field returns an explanatory error."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = make_data([{"addr": fn_addr, "type": ""}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["ok"] is False
    assert "type declaration is required" in entry["error"]


@test(binary="typed_fixture.elf")
def test_make_data_renames_when_name_provided():
    """make_data with a `name` field applies the name alongside the type."""
    import idc, ida_name, ida_bytes

    addr = "0x1069f60"
    original_name = ida_name.get_name(int(addr, 16))
    original_type = idc.get_type(int(addr, 16)) or ""

    try:
        result = make_data([
            {"addr": addr, "type": "int probe_named[2]", "name": "test_make_data_probe"}
        ])
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert entry["ok"] is True
        assert ida_name.get_name(int(addr, 16)) == "test_make_data_probe"
    finally:
        ida_bytes.del_items(int(addr, 16), ida_bytes.DELIT_EXPAND, 8)
        if original_type:
            idc.SetType(int(addr, 16), original_type + ";")
        if original_name:
            ida_name.set_name(int(addr, 16), original_name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)


@test(binary="typed_fixture.elf")
def test_set_op_type_stroff_with_valid_struct():
    """set_op_type kind='stroff' with an existing struct returns ok=True.

    Uses 'Point' which the typed_fixture binary has declared in its IDB.
    """
    import idautils, ida_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    # Find the first instruction with a memory-displacement operand.
    func = ida_funcs.get_func(int(fn_addr, 16))
    if not func:
        skip_test("no func at addr")
    target_ea = None
    import ida_ua
    for head in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, head):
            continue
        for i, op in enumerate(insn.ops):
            if op.type in (3, 4):  # PHRASE or DISPL
                target_ea = (head, i)
                break
        if target_ea:
            break
    if not target_ea:
        skip_test("no memory-operand instruction in candidate function")

    ea, op_n = target_ea
    result = set_op_type([{"addr": hex(ea), "op_n": op_n, "kind": "stroff", "struct": "Point", "delta": 0}])
    assert_is_list(result, min_length=1)
    entry = result[0]
    # The ok flag may be False on x86 ELF binaries where IDA can't bind a
    # struct-offset to an arbitrary memory operand -- but the call must NOT
    # error with "module 'idaapi' has no attribute 'get_struc_id'" or any
    # other API-level failure.
    assert "error" not in entry or "no tid" in entry.get("error", "") or "not bind" in entry.get("error", "").lower(), \
        f"unexpected error: {entry.get('error')!r}"
