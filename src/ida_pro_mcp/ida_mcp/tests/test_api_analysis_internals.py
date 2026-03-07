"""Targeted tests for deeper internal helpers in api_analysis.py."""

from ..framework import test, assert_non_empty
from ..api_analysis import (
    _resolve_insn_scan_ranges,
    _scan_insn_ranges,
    _value_to_le_bytes,
    _value_candidates_for_immediate,
)


@test(binary="typed_fixture.elf")
def test_internal_resolve_insn_scan_ranges_variants():
    """Instruction scan range resolver handles function, segment, start/end and broad-scan modes."""
    ranges, err = _resolve_insn_scan_ranges({"func": "0x1013dc0"}, False)
    assert err is None
    assert ranges == [(0x1013DC0, 0x1013EE4)]

    ranges, err = _resolve_insn_scan_ranges({"segment": ".text"}, False)
    assert err is None
    assert len(ranges) >= 1

    ranges, err = _resolve_insn_scan_ranges(
        {"start": "0x1013ef0", "end": "0x1013f3f"}, False
    )
    assert err is None
    assert ranges == [(0x1013EF0, 0x1013F3F)]

    ranges, err = _resolve_insn_scan_ranges({}, True)
    assert err is None
    assert len(ranges) >= 1


@test(binary="typed_fixture.elf")
def test_internal_resolve_insn_scan_ranges_errors():
    """Instruction scan range resolver returns deterministic validation errors."""
    assert (
        _resolve_insn_scan_ranges({"func": "0xdeadbeef"}, False)[1]
        == "Function not found at 0xdeadbeef"
    )
    assert (
        "Executable segment not found"
        in _resolve_insn_scan_ranges({"segment": "nope"}, False)[1]
    )
    assert (
        _resolve_insn_scan_ranges({"end": "0x1013f3f"}, False)[1]
        == "start is required when end is set"
    )
    assert (
        _resolve_insn_scan_ranges({"start": "0x1000c00"}, False)[1]
        == "start address not in executable segment"
    )
    assert (
        _resolve_insn_scan_ranges({"start": "0x1013f3f", "end": "0x1013ef0"}, False)[1]
        == "end must be greater than start"
    )
    assert "Scope required" in _resolve_insn_scan_ranges({}, False)[1]


@test(binary="typed_fixture.elf")
def test_internal_scan_insn_ranges_match_offset_and_truncation():
    """Instruction scan core handles limits, offsets, operand-any and truncation branches."""
    ranges = [(0x1013EF0, 0x1013F3F)]

    matches, more, scanned, truncated, next_start = _scan_insn_ranges(
        ranges, "call", None, None, None, None, 1, 0, 100
    )
    assert matches == ["0x1013f16"]
    assert more is True
    assert truncated is False
    assert scanned > 0
    assert next_start is None

    matches, more, scanned, truncated, next_start = _scan_insn_ranges(
        ranges, "call", None, None, None, None, 1, 1, 100
    )
    assert matches == ["0x1013f1b"]
    assert more is True
    assert truncated is False

    matches, more, scanned, truncated, next_start = _scan_insn_ranges(
        ranges, "", None, None, None, 0x1013DC0, 10, 0, 100
    )
    assert matches == ["0x1013f1b"]
    assert more is False
    assert truncated is False

    matches, more, scanned, truncated, next_start = _scan_insn_ranges(
        ranges, "", None, None, None, None, 10, 0, 2
    )
    assert truncated is True
    assert scanned == 2
    assert next_start is not None


@test(binary="typed_fixture.elf")
def test_internal_immediate_encoding_helpers():
    """Immediate-value helper paths encode positive/negative values and reject oversize inputs."""
    data, size, normalized = _value_to_le_bytes(1234)
    assert data == b"\xd2\x04\x00\x00"
    assert size == 4
    assert normalized == 1234

    data, size, normalized = _value_to_le_bytes(-2)
    assert data == b"\xfe\xff\xff\xff"
    assert size == 4
    assert normalized == 0xFFFFFFFE

    assert _value_to_le_bytes(1 << 80) is None

    candidates = _value_candidates_for_immediate(1234)
    assert_non_empty(candidates)
    assert any(item[0] == 1234 and item[1] == 4 for item in candidates)
    assert any(item[0] == 1234 and item[1] == 8 for item in candidates)
