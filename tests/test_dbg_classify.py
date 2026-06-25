"""Headless unit tests for ``classify_pointer`` in
``ida_pro_mcp.ida_mcp.dbg_common``.

``classify_pointer`` maps a raw pointer value against a synthetic region list
(each {start,end,perm,module,kind}) to {region, module, perm, offset_in_region,
kind}. Pure -- the region list is hand-built, no live process.
"""

import pytest

from ida_pro_mcp.ida_mcp._kernel.dbg_common import classify_pointer


# A synthetic, ordered, non-overlapping region map standing in for what
# enumerate_memory_regions() would return for a live debuggee.
REGIONS = [
    # An image (module-backed) code region.
    {"start": 0x140000000, "end": 0x140010000, "perm": "r-x", "module": "target.exe", "kind": "image"},
    # A heap region tagged by kind.
    {"start": 0x200000, "end": 0x300000, "perm": "rw-", "module": None, "kind": "heap"},
    # A stack region tagged by kind.
    {"start": 0x7FFF0000, "end": 0x80000000, "perm": "rw-", "module": None, "kind": "stack"},
    # A plain mapped region with no module and no explicit kind -> inferred "mapped".
    {"start": 0x10000, "end": 0x20000, "perm": "r--", "module": None},
]


def test_classify_image_address_reports_module_and_offset():
    res = classify_pointer(0x140001234, REGIONS)
    assert res["kind"] == "image"
    assert res["module"] == "target.exe"
    assert res["perm"] == "r-x"
    assert res["region"] == [0x140000000, 0x140010000]
    assert res["offset_in_region"] == 0x1234


def test_classify_stack_address():
    res = classify_pointer(0x7FFF1000, REGIONS)
    assert res["kind"] == "stack"
    assert res["region"] == [0x7FFF0000, 0x80000000]
    assert res["offset_in_region"] == 0x1000
    assert res["module"] is None


def test_classify_heap_address():
    res = classify_pointer(0x200040, REGIONS)
    assert res["kind"] == "heap"
    assert res["offset_in_region"] == 0x40


def test_classify_unmapped_address():
    res = classify_pointer(0xDEADBEEF00, REGIONS)
    assert res["kind"] == "unmapped"
    assert res["region"] is None
    assert res["module"] is None
    assert res["perm"] is None
    assert res["offset_in_region"] is None


def test_classify_end_is_exclusive():
    # end_ea is exclusive: an address exactly at end belongs to no region here.
    res = classify_pointer(0x140010000, REGIONS)
    assert res["kind"] == "unmapped"


def test_classify_start_is_inclusive():
    res = classify_pointer(0x140000000, REGIONS)
    assert res["kind"] == "image"
    assert res["offset_in_region"] == 0


def test_classify_infers_mapped_for_untagged_module_less_region():
    res = classify_pointer(0x18000, REGIONS)
    assert res["kind"] == "mapped"
    assert res["module"] is None
    assert res["offset_in_region"] == 0x8000


def test_classify_infers_image_kind_when_module_present_but_kind_absent():
    regions = [{"start": 0x400000, "end": 0x410000, "perm": "r-x", "module": "lib.so"}]
    res = classify_pointer(0x400100, regions)
    assert res["kind"] == "image"
    assert res["module"] == "lib.so"


def test_classify_first_containing_region_wins_on_overlap():
    overlapping = [
        {"start": 0x1000, "end": 0x3000, "perm": "r--", "module": "first.bin", "kind": "image"},
        {"start": 0x2000, "end": 0x4000, "perm": "rw-", "module": "second.bin", "kind": "image"},
    ]
    res = classify_pointer(0x2500, overlapping)
    assert res["module"] == "first.bin"


def test_classify_empty_region_list_is_unmapped():
    assert classify_pointer(0x1000, [])["kind"] == "unmapped"
