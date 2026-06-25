"""Headless unit tests for the pure ABI / argument-resolution helpers in
``ida_pro_mcp.ida_mcp.dbg_common``.

These exercise ``detect_abi`` (pointer width + OS -> convention),
``int_arg_location`` (where integer arg N lives at callee ENTRY), and
``resolve_int_arg`` (reads a single arg through INJECTED fakes). None of these
touch IDA, so the package's conftest idaapi stub is enough; the dbg_common
module imports no IDA at top level anyway.
"""

import pytest

from ida_pro_mcp.ida_mcp.dbg_common import (
    detect_abi,
    int_arg_location,
    resolve_int_arg,
)


# --------------------------------------------------------------------------
# detect_abi
# --------------------------------------------------------------------------


def test_detect_abi_32bit_is_cdecl_regardless_of_os():
    # 32-bit collapses to the shared cdecl/stdcall/thiscall stack layout on any OS.
    assert detect_abi(4, True) == "cdecl"
    assert detect_abi(4, False) == "cdecl"


def test_detect_abi_win64():
    assert detect_abi(8, True) == "win64"


def test_detect_abi_sysv():
    assert detect_abi(8, False) == "sysv"


# --------------------------------------------------------------------------
# int_arg_location
# --------------------------------------------------------------------------


def test_int_arg_location_win64_register_args():
    assert int_arg_location(0, "win64") == {"kind": "reg", "reg": "rcx"}
    assert int_arg_location(1, "win64") == {"kind": "reg", "reg": "rdx"}
    assert int_arg_location(2, "win64") == {"kind": "reg", "reg": "r8"}
    assert int_arg_location(3, "win64") == {"kind": "reg", "reg": "r9"}


def test_int_arg_location_win64_stack_args_account_for_shadow_space():
    # arg4 = 8 retaddr + 0x20 shadow = 0x28; arg5 = 0x28 + 8 = 0x30.
    assert int_arg_location(4, "win64") == {"kind": "stack", "disp": 0x28}
    assert int_arg_location(5, "win64") == {"kind": "stack", "disp": 0x30}


def test_int_arg_location_sysv_register_args():
    assert int_arg_location(0, "sysv") == {"kind": "reg", "reg": "rdi"}
    assert int_arg_location(5, "sysv") == {"kind": "reg", "reg": "r9"}


def test_int_arg_location_sysv_first_stack_arg_no_shadow():
    # SysV: args 0..5 in regs; arg6 is first on the stack at retaddr slot only.
    assert int_arg_location(6, "sysv") == {"kind": "stack", "disp": 8}
    assert int_arg_location(7, "sysv") == {"kind": "stack", "disp": 0x10}


def test_int_arg_location_cdecl_all_stack():
    # cdecl: every arg follows the retaddr; arg0 at [esp+4], 4-byte slots.
    assert int_arg_location(0, "cdecl") == {"kind": "stack", "disp": 4}
    assert int_arg_location(1, "cdecl") == {"kind": "stack", "disp": 8}
    assert int_arg_location(2, "cdecl") == {"kind": "stack", "disp": 0xC}


def test_int_arg_location_negative_index_errors():
    loc = int_arg_location(-1, "win64")
    assert "error" in loc


def test_int_arg_location_unknown_convention_errors():
    loc = int_arg_location(0, "pascal")
    assert "error" in loc


# --------------------------------------------------------------------------
# resolve_int_arg (injected fake readers)
# --------------------------------------------------------------------------


def _fake_reg_reader(reg_values: dict):
    return lambda name: reg_values.get(name)


def _fake_stack_reader(stack_by_disp: dict):
    return lambda disp: stack_by_disp.get(disp)


def test_resolve_int_arg_win64_reg_uses_register_reader():
    read_reg = _fake_reg_reader({"rcx": 0x1111, "rdx": 0x2222, "r8": 0x3333, "r9": 0x4444})
    read_stack = _fake_stack_reader({})
    # arg0 -> rcx, arg2 -> r8: value must come from the register reader.
    assert resolve_int_arg(0, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0x1111
    assert resolve_int_arg(2, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0x3333


def test_resolve_int_arg_win64_stack_uses_stack_reader_at_correct_disp():
    read_reg = _fake_reg_reader({})
    # arg4 -> disp 0x28 on the stack.
    read_stack = _fake_stack_reader({0x28: 0xDEAD, 0x30: 0xBEEF})
    assert resolve_int_arg(4, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0xDEAD
    assert resolve_int_arg(5, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0xBEEF


def test_resolve_int_arg_sysv_stack_uses_stack_reader():
    read_reg = _fake_reg_reader({"rdi": 1, "rsi": 2, "rdx": 3, "rcx": 4, "r8": 5, "r9": 6})
    # arg6 -> disp 8 on the stack: value must come from the stack reader, not a reg.
    read_stack = _fake_stack_reader({8: 0xABCD, 0x10: 0x1234})
    assert resolve_int_arg(6, "sysv", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0xABCD
    assert resolve_int_arg(7, "sysv", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0x1234


def test_resolve_int_arg_sysv_reg_uses_register_reader():
    read_reg = _fake_reg_reader({"rdi": 0xAAAA, "r9": 0x9999})
    read_stack = _fake_stack_reader({})
    assert resolve_int_arg(0, "sysv", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0xAAAA
    assert resolve_int_arg(5, "sysv", read_reg=read_reg, read_stack_at_sp_disp=read_stack) == 0x9999


def test_resolve_int_arg_unknown_location_returns_none():
    read_reg = _fake_reg_reader({"rcx": 1})
    read_stack = _fake_stack_reader({0x28: 2})
    assert resolve_int_arg(-1, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) is None


def test_resolve_int_arg_propagates_none_from_reader():
    # Reader has no value for the resolved location -> None bubbles up.
    read_reg = _fake_reg_reader({})
    read_stack = _fake_stack_reader({})
    assert resolve_int_arg(0, "win64", read_reg=read_reg, read_stack_at_sp_disp=read_stack) is None
