"""Call-edge semantics independent of processor-specific instruction enums."""
from types import SimpleNamespace
from unittest.mock import patch

import ida_ua
import ida_xref

from ..framework import test
from .. import api_analysis, utils


def _instruction(operand_type=ida_ua.o_reg, address=0):
    return SimpleNamespace(itype=0x7FFF, ops=[SimpleNamespace(type=operand_type, addr=address)])


@test()
def test_call_targets_use_processor_predicate_and_call_xrefs():
    """Non-x86 instructions use IDA's call predicate; jumps and data refs do not count."""
    refs = [
        SimpleNamespace(to=0x2000, iscode=True, type=ida_xref.fl_CN),
        SimpleNamespace(to=0x2000, iscode=True, type=ida_xref.fl_CF),
        SimpleNamespace(to=0x3000, iscode=True, type=ida_xref.fl_JN),
        SimpleNamespace(to=0x4000, iscode=True, type=ida_xref.fl_F),
        SimpleNamespace(to=0x5000, iscode=False, type=ida_xref.dr_R),
    ]
    instruction = _instruction()
    with patch.object(utils.ida_idp, "is_call_insn", return_value=True) as predicate:
        with patch.object(utils.idautils, "XrefsFrom", return_value=refs):
            assert utils.resolved_call_targets(0x1000, instruction) == [0x2000]
    predicate.assert_called_once_with(instruction)


@test()
def test_call_targets_exclude_non_call_instructions():
    """A near operand on an ordinary branch does not establish a callee."""
    with patch.object(utils.ida_idp, "is_call_insn", return_value=False):
        with patch.object(utils.idautils, "XrefsFrom") as references:
            assert utils.resolved_call_targets(0x1000, _instruction(ida_ua.o_near, 0x2000)) == []
    references.assert_not_called()


@test()
def test_call_targets_fall_back_to_direct_near_and_far_operands():
    """A decoded direct call can resolve before IDA emits its code xref."""
    with patch.object(utils.ida_idp, "is_call_insn", return_value=True):
        with patch.object(utils.idautils, "XrefsFrom", return_value=[]):
            for kind in (ida_ua.o_near, ida_ua.o_far):
                assert utils.resolved_call_targets(0x1000, _instruction(kind, 0x2000)) == [0x2000]


@test()
def test_call_targets_do_not_invent_unresolved_indirect_calls():
    """Register and memory operands without resolved call xrefs remain unknown."""
    with patch.object(utils.ida_idp, "is_call_insn", return_value=True):
        with patch.object(utils.idautils, "XrefsFrom", return_value=[]):
            for kind in (ida_ua.o_reg, ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
                assert utils.resolved_call_targets(0x1000, _instruction(kind, 0x2000)) == []


@test()
def test_call_targets_sort_and_deduplicate_resolved_calls():
    """Repeated references do not create duplicate direct targets."""
    refs = [SimpleNamespace(to=target, iscode=True, type=ida_xref.fl_CN) for target in (0x3000, 0x2000, 0x3000)]
    with patch.object(utils.ida_idp, "is_call_insn", return_value=True):
        with patch.object(utils.idautils, "XrefsFrom", return_value=refs):
            assert utils.resolved_call_targets(0x1000, _instruction()) == [0x2000, 0x3000]


@test()
def test_call_targets_retain_reference_collection_failure():
    """Collection failure must not be reported as a function with zero calls."""
    with patch.object(utils.ida_idp, "is_call_insn", return_value=True):
        with patch.object(utils.idautils, "XrefsFrom", side_effect=RuntimeError("controlled reference failure")):
            try:
                utils.resolved_call_targets(0x1000, _instruction())
            except RuntimeError as error:
                assert str(error) == "controlled reference failure"
            else:
                raise AssertionError("reference collection failure was lost")


def _limited_callees(targets, limit):
    function = SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
    with patch.object(api_analysis, "parse_address", return_value=function.start_ea):
        with patch.object(api_analysis.idaapi, "get_func", return_value=function):
            with patch.object(api_analysis.idautils, "FuncItems", return_value=[0x1000 + index * 4 for index in range(len(targets))]):
                with patch.object(api_analysis, "_decode_insn_at", return_value=_instruction()):
                    with patch.object(api_analysis, "resolved_call_targets", side_effect=targets):
                        with patch.object(api_analysis.ida_name, "get_name", side_effect=lambda address: f"callee_{address:x}"):
                            return api_analysis.callees("0x1000", limit)[0]


@test()
def test_call_targets_limit_requires_an_extra_distinct_target():
    """Duplicates at the exact unique limit do not establish omitted callees."""
    result = _limited_callees([[0x2000], [0x2000]], 1)
    assert [item["addr"] for item in result["callees"]] == ["0x2000"]
    assert result["more"] is False


@test()
def test_call_targets_limit_reports_an_extra_distinct_target():
    """The first distinct target beyond the cap proves there is more data."""
    result = _limited_callees([[0x2000], [0x2000], [0x3000]], 1)
    assert [item["addr"] for item in result["callees"]] == ["0x2000"]
    assert result["more"] is True
