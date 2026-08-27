"""Host-side tests for the IDA 9.4 compatibility adapters.

`ida_pro_mcp.ida_mcp.compat` can only be imported inside IDA, so these tests
install fake `ida_*` modules in `sys.modules` and load `compat.py` directly from
disk as a standalone module (it has no intra-package imports).

Two IDA generations are simulated:

* "modern"  - IDA 9.4: exposes `func_entry_info_t` / `get_func_entry_info`,
  `get_segment_info` / `segment_info_t`, `qflow_chart_ea_t`, and the `*_ea`
  ida_frame entry points. The deprecated APIs are present but raise if called.
* "legacy"  - pre-9.4: only the deprecated APIs exist.

The point of the fakes is to pin the *shape* of the adapters (which IDA entry
point is chosen, argument order, BADADDR handling, tail-chunk skipping,
JSON-visible return types) - not to emulate IDA's analysis.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest


COMPAT_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "compat.py"
)

BADADDR = 0xFFFFFFFFFFFFFFFF

GFI_NAME = 0x0001
GFI_CMT = 0x0002
GFI_CMT_RPT = 0x0004

SEGPERM_EXEC = 1
SEGPERM_WRITE = 2
SEGPERM_READ = 4

FUNC_TAIL = 0x00008000
FUNC_LIB = 0x00000004


# ============================================================================
# Fake IDA object model
# ============================================================================


class FakeRange:
    def __init__(self, start_ea=0, end_ea=0):
        self.start_ea = start_ea
        self.end_ea = end_ea

    def empty(self):
        return self.start_ea >= self.end_ea


class FakeFchunkInfo(FakeRange):
    """Stand-in for ida_funcs.fchunk_info_t."""

    def __init__(self, start_ea=0, end_ea=0):
        super().__init__(start_ea, end_ea)
        self._flags = 0

    def get_flags(self):
        return self._flags

    def is_tail(self):
        return (self._flags & FUNC_TAIL) != 0


class FakeFuncEntryInfo(FakeFchunkInfo):
    """Stand-in for ida_funcs.func_entry_info_t.

    Mirrors the SDK contract: the name/comment fields are only populated when
    the matching GFI_ flag was requested, and `get_name()` returns a plain
    string (never None, never a generated `sub_...` name).
    """

    def __init__(self, start_ea=0, end_ea=0):
        super().__init__(start_ea, end_ea)
        self._filled = 0
        self._frame_id = BADADDR
        self._name = ""
        self._cmt = ""
        self._cmt_rpt = ""

    def has(self, gfi_flags):
        return (self._filled & gfi_flags) == gfi_flags

    def get_frame_id(self):
        return self._frame_id

    def get_name(self):
        return self._name

    def get_cmt(self):
        return self._cmt

    def get_cmt_rpt(self):
        return self._cmt_rpt


class FakeSegmentInfo(FakeRange):
    def __init__(self):
        super().__init__(0, 0)
        self._perm = 0
        self._type = 0
        self._name = ""

    def get_perm(self):
        return self._perm

    def get_type(self):
        return self._type

    def get_name(self):
        return self._name


class FakeFuncT(FakeRange):
    """Stand-in for the deprecated ida_funcs.func_t."""

    def __init__(self, start_ea=0, end_ea=0, flags=0, frame=BADADDR):
        super().__init__(start_ea, end_ea)
        self.flags = flags
        self.frame = frame


class FakeQflowChartEa:
    """Stand-in for ida_gdl.qflow_chart_ea_t."""

    # (start, end, succ indices)
    LAYOUT = [
        (0x1000, 0x1010, [1, 2]),
        (0x1010, 0x1018, [3]),
        (0x1018, 0x1020, [3]),
        (0x1020, 0x1028, []),
    ]

    created_with: list[tuple] = []

    def __init__(self, title, func_ea, ea1, ea2, flags):
        FakeQflowChartEa.created_with.append((title, func_ea, ea1, ea2, flags))
        self.func_ea = func_ea
        self._blocks = [FakeRange(s, e) for s, e, _ in self.LAYOUT]
        self._succ = [list(s) for _, _, s in self.LAYOUT]
        self._pred: list[list[int]] = [[] for _ in self.LAYOUT]
        for i, succs in enumerate(self._succ):
            for j in succs:
                self._pred[j].append(i)

    def size(self):
        return len(self._blocks)

    def __getitem__(self, n):
        return self._blocks[n]

    def calc_block_type(self, n):
        return 100 + n

    def nsucc(self, n):
        return len(self._succ[n])

    def npred(self, n):
        return len(self._pred[n])

    def succ(self, n, i):
        return self._succ[n][i]

    def pred(self, n, i):
        return self._pred[n][i]


class FakeItemIterator:
    """Stand-in for ida_funcs.function_item_iterator_t.

    Records which advance method the adapter drives, and models the difference
    that matters: `next_code()` walks item heads, `next_addr()` walks every
    address.
    """

    HEADS = {0x1000: [0x1000, 0x1004, 0x100A]}
    calls: list[str] = []

    def __init__(self, func_ea, ea=BADADDR):
        self.func_ea = func_ea
        self._heads = list(self.HEADS.get(func_ea, []))
        self._addrs = list(range(0x1000, 0x100C)) if self._heads else []
        self._mode: str | None = None
        self._i = -1

    def first(self):
        if not self._heads:
            return False
        self._i = 0
        return True

    def current(self):
        seq = self._addrs if self._mode == "addr" else self._heads
        return seq[self._i] if 0 <= self._i < len(seq) else BADADDR

    def next_code(self):
        FakeItemIterator.calls.append("next_code")
        self._mode = "code"
        self._i += 1
        return self._i < len(self._heads)

    def next_addr(self):
        FakeItemIterator.calls.append("next_addr")
        self._mode = "addr"
        self._i += 1
        return self._i < len(self._addrs)


class FakeRangeVec(list):
    """qvector-like: IDA's rangevec_t is appended to with push_back()."""

    def push_back(self, item):
        self.append(item)


class FakeDecompRanges:
    """Stand-in for ida_hexrays.decomp_ranges_t."""

    def __init__(self):
        self.ranges = FakeRangeVec()

    def empty(self):
        return not self.ranges

    def start(self):
        return self.ranges[0].start_ea if self.ranges else BADADDR


class FakeHexraysFailure:
    def __init__(self):
        self.code = 0
        self.str = ""
        self.errea = BADADDR

    def desc(self):
        return self.str


class FakeMba:
    def __init__(self, ranges):
        self._dr = FakeDecompRanges()
        # the kernel reports the *merged* submitted set
        for start, end in ranges:
            self._dr.ranges.push_back(FakeRange(start, end))

    def get_decomp_ranges(self):
        return self._dr


class FakeCfunc:
    def __init__(self, ranges):
        self.mba = FakeMba(ranges)
        self.entry_ea = ranges[0][0] if ranges else BADADDR
        self._ranges = list(ranges)

    def __str__(self):
        return "// snippet %s" % (self._ranges,)


def _deprecated(name):
    def _raise(*_args, **_kwargs):
        raise AssertionError(f"deprecated IDA API {name}() must not be called")

    return _raise


# ============================================================================
# Fake module construction
# ============================================================================


class World:
    """Mutable database the fake modules read from."""

    def __init__(self):
        # ea -> (start, end, flags, frame_id, name, cmt, cmt_rpt)
        self.funcs: dict[int, dict] = {}
        self.chunks: list[dict] = []  # ordered by start_ea
        self.segments: list[dict] = []
        self.min_ea = 0x1000
        self.max_ea = 0x9000
        self.frame_calls: list[tuple] = []
        # [(start, end)] of defined code items, plus mapped/loaded spans
        self.code_items: list[tuple[int, int]] = []
        self.loaded: list[tuple[int, int]] = []
        self.decomp_calls: list[tuple] = []
        self.decomp_result = "ok"  # 'ok' | 'fail' | 'license' | 'raise'


def _build_modules(world: World, *, modern: bool):
    mods: dict[str, types.ModuleType] = {}

    def mod(name):
        m = types.ModuleType(name)
        mods[name] = m
        return m

    idaapi = mod("idaapi")
    idaapi.BADADDR = BADADDR
    idaapi.SEGPERM_EXEC = SEGPERM_EXEC
    idaapi.SEGPERM_WRITE = SEGPERM_WRITE
    idaapi.SEGPERM_READ = SEGPERM_READ
    idaapi.get_kernel_version = lambda: "9.4" if modern else "9.1"
    idaapi.getseg = _deprecated("getseg")
    idaapi.get_segm_name = _deprecated("get_segm_name")
    idaapi.FlowChart = _deprecated("FlowChart")
    idaapi.demangle_name = lambda *a, **k: None
    idaapi.MNG_NODEFINIT = 0

    ida_bytes = mod("ida_bytes")
    ida_bytes.FF_CODE = 0x600
    ida_bytes.is_loaded = lambda ea: _is_loaded(world, ea)
    ida_bytes.get_flags = lambda ea: _get_flags(world, ea)
    ida_bytes.is_code = lambda flags: (flags & 0x600) == 0x600
    ida_bytes.get_item_head = lambda ea: _item_head(world, ea)
    ida_bytes.get_item_end = lambda ea: _item_end(world, ea)
    ida_bytes.find_bytes = lambda *a, **k: BADADDR
    ida_bytes.bin_search = lambda *a, **k: BADADDR
    ida_bytes.BIN_SEARCH_FORWARD = 0
    ida_bytes.BIN_SEARCH_NOSHOW = 0

    ida_funcs = mod("ida_funcs")

    class _FuncT(FakeFuncT):
        pass

    ida_funcs.func_t = _FuncT
    ida_funcs.FUNC_TAIL = FUNC_TAIL
    ida_funcs.FUNC_LIB = FUNC_LIB
    ida_funcs.get_func = _deprecated("get_func") if modern else (
        lambda ea: _legacy_get_func(world, ea)
    )
    ida_funcs.get_next_func = _deprecated("get_next_func")
    ida_funcs.get_fchunk = _deprecated("get_fchunk")
    ida_funcs.get_next_fchunk = _deprecated("get_next_fchunk")
    ida_funcs.get_func_cmt = _deprecated("get_func_cmt")
    ida_funcs.set_func_cmt = _deprecated("set_func_cmt")
    ida_funcs.get_func_name = lambda ea: _get_func_name(world, ea)

    if modern:
        ida_funcs.GFI_NAME = GFI_NAME
        ida_funcs.GFI_CMT = GFI_CMT
        ida_funcs.GFI_CMT_RPT = GFI_CMT_RPT
        ida_funcs.fchunk_info_t = FakeFchunkInfo
        ida_funcs.func_entry_info_t = FakeFuncEntryInfo
        ida_funcs.get_func_entry_info = lambda out, ea, flags=0: _get_func_entry_info(
            world, out, ea, flags
        )
        ida_funcs.get_func_start = lambda ea: _func_start(world, ea)
        ida_funcs.get_next_func_ea = lambda ea: _next_func_ea(world, ea)
        ida_funcs.get_fchunk_start = lambda ea: _fchunk_start(world, ea)
        ida_funcs.get_next_fchunk_ea = lambda ea: _next_fchunk_ea(world, ea)
        ida_funcs.is_function_tail = lambda ea: _is_tail(world, ea)
        ida_funcs.get_func_flags = lambda ea: _chunk_flags(world, ea)
        ida_funcs.get_func_cmt_ea = lambda ea, rpt: _get_cmt(world, ea, rpt)
        ida_funcs.set_func_cmt_ea = lambda ea, cmt, rpt: _set_cmt(world, ea, cmt, rpt)
        ida_funcs.function_item_iterator_t = FakeItemIterator

    ida_frame = mod("ida_frame")
    if modern:
        ida_frame.get_func_frame_ea = lambda tif, ea: _rec(
            world, "get_func_frame_ea", tif, ea
        )
        ida_frame.soff_to_fpoff_ea = lambda ea, soff: _rec(
            world, "soff_to_fpoff_ea", ea, soff
        )
        ida_frame.define_stkvar_ea = lambda ea, name, off, tif: _rec(
            world, "define_stkvar_ea", ea, name, off, tif
        )
        ida_frame.is_funcarg_off_ea = lambda ea, off: _rec(
            world, "is_funcarg_off_ea", ea, off
        )
        ida_frame.delete_frame_members_ea = lambda ea, s, e: _rec(
            world, "delete_frame_members_ea", ea, s, e
        )
        ida_frame.set_frame_member_type_ea = lambda ea, off, tif: _rec(
            world, "set_frame_member_type_ea", ea, off, tif
        )
        for legacy in (
            "get_func_frame",
            "soff_to_fpoff",
            "define_stkvar",
            "is_funcarg_off",
            "delete_frame_members",
            "set_frame_member_type",
        ):
            setattr(ida_frame, legacy, _deprecated(legacy))
    else:
        ida_frame.get_func_frame = lambda tif, fn: _rec(
            world, "get_func_frame", tif, fn
        )
        ida_frame.soff_to_fpoff = lambda fn, soff: _rec(world, "soff_to_fpoff", fn, soff)
        ida_frame.define_stkvar = lambda fn, name, off, tif: _rec(
            world, "define_stkvar", fn, name, off, tif
        )
        ida_frame.is_funcarg_off = lambda fn, off: _rec(world, "is_funcarg_off", fn, off)
        ida_frame.delete_frame_members = lambda fn, s, e: _rec(
            world, "delete_frame_members", fn, s, e
        )
        ida_frame.set_frame_member_type = lambda fn, off, tif: _rec(
            world, "set_frame_member_type", fn, off, tif
        )

    ida_nalt = mod("ida_nalt")
    ida_nalt.get_tinfo = lambda tif, ea: False
    ida_nalt.get_entry_qty = lambda: 0
    ida_nalt.get_entry_ordinal = lambda i: 0
    ida_nalt.get_entry = lambda o: 0
    ida_nalt.get_entry_name = lambda o: None

    ida_segment = mod("ida_segment")
    ida_segment.get_segm_name = _deprecated("get_segm_name")
    ida_segment.get_first_seg = _deprecated("get_first_seg")
    ida_segment.get_next_seg = _deprecated("get_next_seg")
    if modern:
        ida_segment.segment_info_t = FakeSegmentInfo
        ida_segment.get_segment_info = lambda out, ea, flags=0: _get_segment_info(
            world, out, ea, flags
        )
        ida_segment.get_segment_name = lambda ea, flags=0: _segment_name(world, ea)
        ida_segment.get_first_segment_ea = lambda: (
            world.segments[0]["start"] if world.segments else BADADDR
        )
        ida_segment.get_next_segment_ea = lambda ea: _next_segment_ea(world, ea)

    ida_typeinf = mod("ida_typeinf")

    class _Tinfo:
        def is_func(self):
            return False

    ida_typeinf.tinfo_t = _Tinfo
    ida_typeinf.til_t = object
    ida_typeinf.udm_t = object
    ida_typeinf.get_ordinal_limit = lambda *a: 0
    ida_typeinf.get_ordinal_qty = lambda *a: 0
    ida_typeinf.guess_tinfo = lambda tif, ea: False

    idc = mod("idc")
    idc.get_func_cmt = _deprecated("idc.get_func_cmt")
    idc.set_func_cmt = _deprecated("idc.set_func_cmt")
    idc.get_name = lambda *a, **k: ""

    ida_ida = mod("ida_ida")
    ida_ida.inf_get_min_ea = lambda: world.min_ea
    ida_ida.inf_get_max_ea = lambda: world.max_ea
    ida_ida.inf_get_omin_ea = lambda: world.min_ea
    ida_ida.inf_get_omax_ea = lambda: world.max_ea
    ida_ida.inf_is_64bit = lambda: True

    ida_entry = mod("ida_entry")
    ida_entry.get_entry_qty = lambda: 0
    ida_entry.get_entry_ordinal = lambda i: 0
    ida_entry.get_entry = lambda o: 0
    ida_entry.get_entry_name = lambda o: None

    ida_gdl = mod("ida_gdl")
    if modern:
        ida_gdl.qflow_chart_ea_t = FakeQflowChartEa

    idautils = mod("idautils")
    idautils.Functions = _deprecated("idautils.Functions")
    idautils.FuncItems = _deprecated("idautils.FuncItems")
    idautils.Segments = lambda: iter([s["start"] for s in world.segments])

    ida_range = mod("ida_range")
    ida_range.range_t = FakeRange
    ida_range.rangevec_t = FakeRangeVec

    ida_hexrays = mod("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: True
    ida_hexrays.guess_tinfo = lambda tif, ea: False
    ida_hexrays.MERR_LICENSE = 42
    ida_hexrays.hexrays_failure_t = FakeHexraysFailure
    if modern:
        ida_hexrays.decomp_ranges_t = FakeDecompRanges
        priv = mod("_ida_hexrays")
        priv.decompile = lambda dcr, hf, flags: _fake_decompile(world, dcr, hf, flags)

    return mods


# --- fake kernel implementations ------------------------------------------


def _rec(world, name, *args):
    world.frame_calls.append((name, *args))
    return True


def _func_record(world, ea):
    """The function entry whose [start, end) or tail range contains ea."""
    for rec in world.funcs.values():
        if rec["start"] <= ea < rec["end"]:
            return rec
        for t_start, t_end in rec.get("tails", ()):
            if t_start <= ea < t_end:
                return rec
    return None


def _func_start(world, ea):
    rec = _func_record(world, ea)
    return rec["start"] if rec else BADADDR


def _next_func_ea(world, ea):
    for start in sorted(world.funcs):
        if start > ea:
            return start
    return BADADDR


def _chunk_at(world, ea):
    for c in world.chunks:
        if c["start"] <= ea < c["end"]:
            return c
    return None


def _fchunk_start(world, ea):
    c = _chunk_at(world, ea)
    return c["start"] if c else BADADDR


def _next_fchunk_ea(world, ea):
    for c in world.chunks:
        if c["start"] > ea:
            return c["start"]
    return BADADDR


def _is_tail(world, ea):
    c = _chunk_at(world, ea)
    return bool(c and c["tail"])


def _chunk_flags(world, ea):
    c = _chunk_at(world, ea)
    return c["flags"] if c else 0


def _get_func_entry_info(world, out, ea, flags):
    rec = _func_record(world, ea)
    if rec is None:
        return False
    out.start_ea = rec["start"]
    out.end_ea = rec["end"]
    out._flags = rec["flags"]
    out._frame_id = rec["frame_id"]
    out._filled = flags
    if flags & GFI_NAME:
        out._name = rec["name"]
    if flags & GFI_CMT:
        out._cmt = rec["cmt"]
    if flags & GFI_CMT_RPT:
        out._cmt_rpt = rec["cmt_rpt"]
    return True


def _legacy_get_func(world, ea):
    rec = _func_record(world, ea)
    if rec is None:
        return None
    return FakeFuncT(rec["start"], rec["end"], rec["flags"], rec["frame_id"])


def _get_func_name(world, ea):
    rec = _func_record(world, ea)
    if rec is None:
        return None
    return rec["display_name"]


def _get_cmt(world, ea, repeatable):
    rec = _func_record(world, ea)
    if rec is None:
        return None
    return rec["cmt_rpt"] if repeatable else rec["cmt"]


def _set_cmt(world, ea, cmt, repeatable):
    rec = _func_record(world, ea)
    if rec is None:
        return False
    rec["cmt_rpt" if repeatable else "cmt"] = cmt
    return True


def _is_loaded(world, ea):
    return any(lo <= ea < hi for lo, hi in world.loaded)


def _get_flags(world, ea):
    if not _is_loaded(world, ea):
        return 0
    if any(lo <= ea < hi for lo, hi in world.code_items):
        return 0x600  # FF_CODE
    return 0x400  # data-ish


def _item_head(world, ea):
    for lo, hi in world.code_items:
        if lo <= ea < hi:
            return lo
    return ea


def _item_end(world, ea):
    for lo, hi in world.code_items:
        if lo <= ea < hi:
            return hi
    return ea


def _fake_decompile(world, dcr, hf, flags):
    world.decomp_calls.append(
        (tuple((r.start_ea, r.end_ea) for r in dcr.ranges), flags)
    )
    if world.decomp_result == "raise":
        raise RuntimeError("boom")
    if world.decomp_result == "license":
        hf.code = 42
        return None
    if world.decomp_result == "fail":
        hf.str = "bad ranges"
        hf.errea = 0x1004
        return None
    return FakeCfunc([(r.start_ea, r.end_ea) for r in dcr.ranges])


def _segment_for(world, ea):
    for s in world.segments:
        if s["start"] <= ea < s["end"]:
            return s
    return None


def _get_segment_info(world, out, ea, flags):
    s = _segment_for(world, ea)
    if s is None:
        return False
    out.start_ea = s["start"]
    out.end_ea = s["end"]
    out._perm = s["perm"]
    out._type = s["type"]
    if flags & 0x0001:
        out._name = s["name"]
    return True


def _segment_name(world, ea):
    s = _segment_for(world, ea)
    return s["name"] if s else ""


def _next_segment_ea(world, ea):
    for s in world.segments:
        if s["start"] > ea:
            return s["start"]
    return BADADDR


# ============================================================================
# Loader
# ============================================================================


def load_compat(tc: unittest.TestCase, *, modern=True, world=None):
    """Load compat.py against fake IDA modules.

    The fakes stay installed in sys.modules for the duration of the test: some
    adapters import ida_gdl / idautils lazily inside the call.
    """
    world = world or default_world()
    mods = _build_modules(world, modern=modern)
    saved = {name: sys.modules.get(name) for name in mods}
    sys.modules.update(mods)

    def restore():
        for name, prev in saved.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev

    tc.addCleanup(restore)
    spec = importlib.util.spec_from_file_location(
        f"_compat_under_test_{'modern' if modern else 'legacy'}", COMPAT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, world


def default_world():
    world = World()
    # 0x1000 main entry chunk + a tail at 0x2000; 0x1200 is a second function.
    world.funcs = {
        0x1000: {
            "start": 0x1000,
            "end": 0x100C,
            "flags": FUNC_LIB,
            "frame_id": 0x4242,
            "name": "real_name",
            "display_name": "real_name",
            "cmt": "regular cmt",
            "cmt_rpt": "repeatable cmt",
            "tails": ((0x2000, 0x2004),),
        },
        0x1200: {
            "start": 0x1200,
            "end": 0x1210,
            "flags": 0,
            "frame_id": BADADDR,
            # An unnamed function: nothing stored in the DB, but IDA still
            # generates sub_1200 for get_func_name().
            "name": "",
            "display_name": "sub_1200",
            "cmt": "",
            "cmt_rpt": "",
        },
    }
    world.chunks = [
        {"start": 0x0F00, "end": 0x0F08, "tail": True, "flags": FUNC_TAIL},
        {"start": 0x1000, "end": 0x100C, "tail": False, "flags": FUNC_LIB},
        {"start": 0x1200, "end": 0x1210, "tail": False, "flags": 0},
        {"start": 0x2000, "end": 0x2004, "tail": True, "flags": FUNC_TAIL},
    ]
    world.segments = [
        {
            "start": 0x1000,
            "end": 0x3000,
            "perm": SEGPERM_READ | SEGPERM_EXEC,
            "type": 2,
            "name": ".text",
        },
        {
            "start": 0x3000,
            "end": 0x4000,
            "perm": SEGPERM_READ | SEGPERM_WRITE,
            "type": 3,
            "name": ".data",
        },
    ]
    world.min_ea = 0x0F00
    world.max_ea = 0x9000
    # 4-byte code items across 0x1000..0x1400, data at 0x3000..0x3100
    world.code_items = [(ea, ea + 4) for ea in range(0x1000, 0x1400, 4)]
    world.loaded = [(0x1000, 0x1400), (0x3000, 0x3100)]
    return world


# ============================================================================
# Tests
# ============================================================================


class FunctionInfoTests(unittest.TestCase):
    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def test_uses_entry_info_api(self):
        self.assertTrue(self.compat.HAS_FUNC_ENTRY_INFO)
        fn = self.compat.get_func_info(0x1004)
        self.assertIsNotNone(fn)
        self.assertEqual(fn.start_ea, 0x1000)
        self.assertEqual(fn.end_ea, 0x100C)

    def test_interior_and_tail_addresses_resolve_to_the_entry(self):
        for ea in (0x1000, 0x1004, 0x2002):
            with self.subTest(ea=hex(ea)):
                self.assertEqual(self.compat.get_func_info(ea).start_ea, 0x1000)
                self.assertEqual(self.compat.func_start_ea(ea), 0x1000)

    def test_missing_function_returns_none_and_badaddr(self):
        self.assertIsNone(self.compat.get_func_info(0x8000))
        self.assertEqual(self.compat.func_start_ea(0x8000), BADADDR)
        self.assertFalse(self.compat.in_function(0x8000))
        self.assertTrue(self.compat.in_function(0x1004))

    def test_default_flags_do_not_request_optional_strings(self):
        """get_func_info() must not pay for GFI_NAME on every call."""
        fn = self.compat.get_func_info(0x1000)
        self.assertFalse(fn.has(GFI_NAME))
        self.assertFalse(fn.has(GFI_CMT))
        # Explicit flags still work for callers that want them.
        fn = self.compat.get_func_info(0x1000, GFI_NAME)
        self.assertTrue(fn.has(GFI_NAME))
        self.assertEqual(fn.get_name(), "real_name")

    def test_get_func_name_resolves_generated_names(self):
        """The name must come from get_func_name(), not from entry_info.name_.

        func_entry_info_t.get_name() is empty for a function with no stored
        name; routing through it would replace "sub_1200" with "".
        """
        fn = self.compat.get_func_info(0x1200)
        self.assertEqual(fn.get_name(), "")
        self.assertEqual(self.compat.get_func_name(fn), "sub_1200")

    def test_get_func_name_is_none_outside_a_function(self):
        fake = FakeFuncEntryInfo(0x8000, 0x8001)
        self.assertIsNone(self.compat.get_func_name(fake))

    def test_flags_and_frame_id_read_through_accessors(self):
        fn = self.compat.get_func_info(0x1000)
        self.assertEqual(self.compat.get_func_flags(fn), FUNC_LIB)
        self.assertEqual(self.compat.get_func_frame_id(fn), 0x4242)

    def test_func_flags_at_uses_ea_api(self):
        self.assertEqual(self.compat.func_flags_at(0x1000), FUNC_LIB)
        self.assertEqual(self.compat.func_flags_at(0x1200), 0)
        self.assertEqual(self.compat.func_flags_at(0x8000), 0)

    def test_comments_round_trip_through_ea_api(self):
        self.assertEqual(self.compat.get_func_comment(0x1000, False), "regular cmt")
        self.assertEqual(self.compat.get_func_comment(0x1000, True), "repeatable cmt")
        # Never None: callers concatenate the result.
        self.assertEqual(self.compat.get_func_comment(0x8000, False), "")
        self.assertEqual(self.compat.get_func_comment(0x1200, False), "")

        self.assertTrue(self.compat.set_func_comment(0x1000, "new", False))
        self.assertEqual(self.compat.get_func_comment(0x1000, False), "new")
        self.assertEqual(self.compat.get_func_comment(0x1000, True), "repeatable cmt")


class FunctionEnumerationTests(unittest.TestCase):
    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def test_skips_leading_tail_chunk(self):
        """A tail chunk at the start of the range is not a function entry."""
        self.assertEqual(list(self.compat.function_eas()), [0x1000, 0x1200])

    def test_explicit_range_is_half_open_on_the_entry_ea(self):
        self.assertEqual(list(self.compat.function_eas(0x1000, 0x1200)), [0x1000])
        self.assertEqual(
            list(self.compat.function_eas(0x1000, 0x1201)), [0x1000, 0x1200]
        )

    def test_start_inside_a_function_yields_that_function(self):
        # Matches idautils.Functions(): the containing chunk is reported even
        # though its start is below `start`.
        self.assertEqual(
            list(self.compat.function_eas(0x1004, 0x9000)), [0x1000, 0x1200]
        )

    def test_start_past_every_function_yields_nothing(self):
        self.assertEqual(list(self.compat.function_eas(0x5000, 0x9000)), [])

    def test_start_in_a_tail_chunk_skips_to_the_next_entry(self):
        self.assertEqual(list(self.compat.function_eas(0x2000, 0x9000)), [])


class FunctionItemTests(unittest.TestCase):
    def setUp(self):
        FakeItemIterator.calls = []
        self.compat, self.world = load_compat(self, modern=True)

    def test_iterates_code_items_not_every_address(self):
        """idautils.FuncItems() is first()/next_code(); next_addr() is not it."""
        items = list(self.compat.function_items(0x1000))
        self.assertEqual(items, [0x1000, 0x1004, 0x100A])
        self.assertIn("next_code", FakeItemIterator.calls)
        self.assertNotIn("next_addr", FakeItemIterator.calls)

    def test_no_items_when_first_fails(self):
        self.assertEqual(list(self.compat.function_items(0x8000)), [])


class SegmentTests(unittest.TestCase):
    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def test_segment_info_and_accessors(self):
        seg = self.compat.get_segment_info(0x1100)
        self.assertIsNotNone(seg)
        self.assertEqual((seg.start_ea, seg.end_ea), (0x1000, 0x3000))
        self.assertEqual(
            self.compat.get_segment_perm(seg), SEGPERM_READ | SEGPERM_EXEC
        )
        self.assertEqual(self.compat.get_segment_type(seg), 2)
        self.assertEqual(self.compat.get_segment_size(seg), 0x2000)

    def test_missing_segment_returns_none(self):
        self.assertIsNone(self.compat.get_segment_info(0x8000))
        self.assertIsNone(self.compat.get_segment_name(0x8000))

    def test_segment_name_uses_address_lookup(self):
        self.assertEqual(self.compat.get_segment_name(0x1100), ".text")
        self.assertEqual(self.compat.get_segment_name(0x3100), ".data")

    def test_segment_eas_walks_every_segment(self):
        self.assertEqual(list(self.compat.segment_eas()), [0x1000, 0x3000])

    def test_segment_eas_stops_at_badaddr(self):
        self.world.segments = []
        self.assertEqual(list(self.compat.segment_eas()), [])


class FlowChartTests(unittest.TestCase):
    def setUp(self):
        FakeQflowChartEa.created_with = []
        self.compat, self.world = load_compat(self, modern=True)

    def test_uses_badaddr_sentinel_bounds_like_ida_gdl_flowchart(self):
        self.compat.function_flow_blocks(0x1004)
        self.assertEqual(
            FakeQflowChartEa.created_with,
            [("", 0x1000, BADADDR, BADADDR, 0)],
        )

    def test_block_adapter_matches_basicblock_shape(self):
        blocks = self.compat.function_flow_blocks(0x1000)
        self.assertEqual(len(blocks), 4)
        self.assertEqual([b.id for b in blocks], [0, 1, 2, 3])
        self.assertEqual([b.start_ea for b in blocks], [0x1000, 0x1010, 0x1018, 0x1020])
        self.assertEqual([b.end_ea for b in blocks], [0x1010, 0x1018, 0x1020, 0x1028])
        self.assertEqual([b.type for b in blocks], [100, 101, 102, 103])

    def test_successors_and_predecessors(self):
        blocks = self.compat.function_flow_blocks(0x1000)
        self.assertEqual(
            [s.start_ea for s in blocks[0].succs()], [0x1010, 0x1018]
        )
        self.assertEqual([p.start_ea for p in blocks[0].preds()], [])
        self.assertEqual(
            [p.start_ea for p in blocks[3].preds()], [0x1010, 0x1018]
        )
        self.assertEqual([s.start_ea for s in blocks[3].succs()], [])

    def test_edge_count_matches_cyclomatic_complexity_input(self):
        blocks = self.compat.function_flow_blocks(0x1000)
        edges = sum(1 for b in blocks for _ in b.succs())
        self.assertEqual(edges, 4)
        self.assertEqual(edges - len(blocks) + 2, 2)

    def test_no_function_returns_empty_list(self):
        self.assertEqual(self.compat.function_flow_blocks(0x8000), [])
        self.assertEqual(FakeQflowChartEa.created_with, [])


class FrameAdapterTests(unittest.TestCase):
    def test_modern_frame_calls_forward_the_start_ea(self):
        compat, world = load_compat(self, modern=True)
        fn = compat.get_func_info(0x1004)
        tif = object()
        self.assertTrue(compat.get_func_frame(tif, fn))
        self.assertTrue(compat.soff_to_fpoff(fn, -8))
        self.assertTrue(compat.define_stkvar(fn, "v", -8, tif))
        self.assertTrue(compat.is_funcarg_off(fn, 0x10))
        self.assertTrue(compat.delete_frame_members(fn, -8, 0))
        self.assertTrue(compat.set_frame_member_type(fn, -8, tif))
        self.assertEqual(
            world.frame_calls,
            [
                ("get_func_frame_ea", tif, 0x1000),
                ("soff_to_fpoff_ea", 0x1000, -8),
                ("define_stkvar_ea", 0x1000, "v", -8, tif),
                ("is_funcarg_off_ea", 0x1000, 0x10),
                ("delete_frame_members_ea", 0x1000, -8, 0),
                ("set_frame_member_type_ea", 0x1000, -8, tif),
            ],
        )

    def test_legacy_frame_calls_forward_the_function_object(self):
        compat, world = load_compat(self, modern=False)
        self.assertFalse(compat.HAS_FUNC_ENTRY_INFO)
        fn = compat.get_func_info(0x1004)
        self.assertIsInstance(fn, FakeFuncT)
        tif = object()
        compat.get_func_frame(tif, fn)
        compat.soff_to_fpoff(fn, -8)
        compat.define_stkvar(fn, "v", -8, tif)
        compat.is_funcarg_off(fn, 0x10)
        compat.delete_frame_members(fn, -8, 0)
        compat.set_frame_member_type(fn, -8, tif)
        self.assertEqual(
            [c[0] for c in world.frame_calls],
            [
                "get_func_frame",
                "soff_to_fpoff",
                "define_stkvar",
                "is_funcarg_off",
                "delete_frame_members",
                "set_frame_member_type",
            ],
        )
        for call in world.frame_calls:
            self.assertIn(fn, call[1:])


class LegacyFallbackTests(unittest.TestCase):
    """On pre-9.4 builds the adapters must fall back, not raise."""

    def setUp(self):
        self.compat, self.world = load_compat(self, modern=False)

    def test_func_info_falls_back_to_func_t(self):
        fn = self.compat.get_func_info(0x1004)
        self.assertEqual((fn.start_ea, fn.end_ea), (0x1000, 0x100C))
        self.assertEqual(self.compat.get_func_flags(fn), FUNC_LIB)
        self.assertEqual(self.compat.get_func_frame_id(fn), 0x4242)
        self.assertEqual(self.compat.get_func_name(fn), "real_name")

    def test_func_start_ea_falls_back_without_get_func_start(self):
        self.assertEqual(self.compat.func_start_ea(0x1004), 0x1000)
        self.assertEqual(self.compat.func_start_ea(0x8000), BADADDR)

    def test_func_flags_at_falls_back(self):
        self.assertEqual(self.compat.func_flags_at(0x1000), FUNC_LIB)
        self.assertEqual(self.compat.func_flags_at(0x8000), 0)

    def test_segment_eas_falls_back_to_idautils(self):
        self.assertEqual(list(self.compat.segment_eas()), [0x1000, 0x3000])


class JsonShapeTests(unittest.TestCase):
    """Pin the value types that reach MCP JSON payloads."""

    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def test_scalar_types(self):
        fn = self.compat.get_func_info(0x1000)
        seg = self.compat.get_segment_info(0x1000)
        self.assertIsInstance(fn.start_ea, int)
        self.assertIsInstance(fn.end_ea, int)
        self.assertIsInstance(self.compat.get_func_flags(fn), int)
        self.assertIsInstance(self.compat.func_start_ea(0x1000), int)
        self.assertIsInstance(self.compat.func_flags_at(0x1000), int)
        self.assertIsInstance(self.compat.get_segment_perm(seg), int)
        self.assertIsInstance(self.compat.get_segment_type(seg), int)
        self.assertIsInstance(self.compat.get_segment_size(seg), int)
        self.assertIsInstance(self.compat.get_segment_name(0x1000), str)
        self.assertIsInstance(self.compat.get_func_comment(0x1000, False), str)
        self.assertIsInstance(self.compat.get_func_name(fn), str)

    def test_function_size_uses_entry_chunk_range(self):
        """`size` in the Function payload is end_ea - start_ea of the entry
        chunk, i.e. it excludes tail chunks - same as func_t.size() did."""
        fn = self.compat.get_func_info(0x1000)
        self.assertEqual(fn.end_ea - fn.start_ea, 0x0C)



class NormalizeCodeRangesTests(unittest.TestCase):
    """Garbage must never reach Hex-Rays: it is all rejected here."""

    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def _ok(self, ranges):
        got, err = self.compat.normalize_code_ranges(ranges)
        self.assertIsNone(err, err)
        return got

    def _err(self, ranges):
        got, err = self.compat.normalize_code_ranges(ranges)
        self.assertEqual(got, [])
        self.assertIsInstance(err, str)
        return err

    def test_valid_range_passes_through(self):
        self.assertEqual(self._ok([(0x1000, 0x1010)]), [(0x1000, 0x1010)])

    def test_start_snaps_back_to_the_item_head(self):
        # mid-instruction start is the most likely caller mistake
        self.assertEqual(self._ok([(0x1002, 0x1010)]), [(0x1000, 0x1010)])

    def test_end_snaps_forward_to_the_item_end(self):
        self.assertEqual(self._ok([(0x1000, 0x100E)]), [(0x1000, 0x1010)])

    def test_ranges_are_sorted(self):
        self.assertEqual(
            self._ok([(0x1100, 0x1110), (0x1000, 0x1010)]),
            [(0x1000, 0x1010), (0x1100, 0x1110)],
        )

    def test_overlapping_ranges_merge(self):
        self.assertEqual(self._ok([(0x1000, 0x1020), (0x1010, 0x1040)]), [(0x1000, 0x1040)])

    def test_adjacent_ranges_merge(self):
        self.assertEqual(self._ok([(0x1000, 0x1010), (0x1010, 0x1020)]), [(0x1000, 0x1020)])

    def test_disjoint_ranges_are_kept_apart(self):
        self.assertEqual(
            self._ok([(0x1000, 0x1010), (0x1100, 0x1110)]),
            [(0x1000, 0x1010), (0x1100, 0x1110)],
        )

    def test_rejections(self):
        cases = {
            "reversed": [(0x1010, 0x1000)],
            "empty": [(0x1000, 0x1000)],
            "badaddr_start": [(BADADDR, 0x1010)],
            "badaddr_end": [(0x1000, BADADDR)],
            "unmapped": [(0x7000, 0x7010)],
            "not_code": [(0x3000, 0x3010)],
            "no_ranges": [],
            "garbage": ["nonsense"],
            "none_bound": [(None, 0x1010)],
            "short_tuple": [(0x1000,)],
        }
        for label, ranges in cases.items():
            with self.subTest(label):
                self._err(ranges)

    def test_range_count_cap(self):
        many = [(0x1000 + i * 8, 0x1000 + i * 8 + 4) for i in range(self.compat.MAX_DECOMP_RANGES + 1)]
        self.assertIn("Too many ranges", self._err(many))

    def test_total_size_cap(self):
        got, err = self.compat.normalize_code_ranges(
            [(0x1000, 0x1010)], max_bytes=8
        )
        self.assertEqual(got, [])
        self.assertIn("bytes", err)


class DecompileRangesTests(unittest.TestCase):
    def setUp(self):
        self.compat, self.world = load_compat(self, modern=True)

    def test_available_on_modern_build(self):
        self.assertTrue(self.compat.can_decompile_ranges())

    def test_forwards_ranges_in_order(self):
        cfunc, err = self.compat.decompile_ranges([(0x1000, 0x1010), (0x1100, 0x1110)])
        self.assertIsNone(err)
        self.assertIsNotNone(cfunc)
        self.assertEqual(
            self.world.decomp_calls,
            [(((0x1000, 0x1010), (0x1100, 0x1110)), 0)],
        )

    def test_lowest_address_becomes_the_entry(self):
        cfunc, _ = self.compat.decompile_ranges([(0x1000, 0x1010), (0x1100, 0x1110)])
        self.assertEqual(cfunc.entry_ea, 0x1000)

    def test_flags_are_passed_through(self):
        self.compat.decompile_ranges([(0x1000, 0x1010)], flags=7)
        self.assertEqual(self.world.decomp_calls[0][1], 7)

    def test_empty_ranges_rejected_before_the_call(self):
        cfunc, err = self.compat.decompile_ranges([])
        self.assertIsNone(cfunc)
        self.assertEqual(err, "No ranges given")
        self.assertEqual(self.world.decomp_calls, [])

    def test_decompiler_failure_is_reported_with_address(self):
        self.world.decomp_result = "fail"
        cfunc, err = self.compat.decompile_ranges([(0x1000, 0x1010)])
        self.assertIsNone(cfunc)
        self.assertIn("bad ranges", err)
        self.assertIn("0x1004", err)

    def test_license_failure_has_its_own_message(self):
        self.world.decomp_result = "license"
        cfunc, err = self.compat.decompile_ranges([(0x1000, 0x1010)])
        self.assertIsNone(cfunc)
        self.assertIn("license", err.lower())

    def test_exception_from_the_private_entry_point_is_contained(self):
        # _ida_hexrays.decompile is not contract-bound; it must not escape
        self.world.decomp_result = "raise"
        cfunc, err = self.compat.decompile_ranges([(0x1000, 0x1010)])
        self.assertIsNone(cfunc)
        self.assertIn("boom", err)

    def test_unavailable_on_legacy_build(self):
        compat, _world = load_compat(self, modern=False)
        self.assertFalse(compat.can_decompile_ranges())
        cfunc, err = compat.decompile_ranges([(0x1000, 0x1010)])
        self.assertIsNone(cfunc)
        self.assertIn("not available", err)

    def test_submitted_ranges_come_from_the_mba(self):
        cfunc, _ = self.compat.decompile_ranges([(0x1000, 0x1010)])
        self.assertEqual(
            self.compat.submitted_decomp_ranges(cfunc, [(0, 0)]), [(0x1000, 0x1010)]
        )

    def test_submitted_ranges_fall_back_when_the_mba_is_unhelpful(self):
        class _NoMba:
            mba = None

        self.assertEqual(
            self.compat.submitted_decomp_ranges(_NoMba(), [(0x1000, 0x1010)]),
            [(0x1000, 0x1010)],
        )

if __name__ == "__main__":
    unittest.main()
