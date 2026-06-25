"""Unit tests for the side-effect-free probe-predicate evaluator.

``safe_eval`` evaluates a *whitelisted* AST directly: no ``eval``/``exec``, no
attribute access, no calls, no comprehensions. These tests assert that valid
predicates evaluate correctly AND that every known sandbox-escape construct
raises :class:`UnsafeExpressionError` instead of running.
"""

import sys

import pytest

from ida_pro_mcp.ida_mcp.safe_eval import safe_eval, UnsafeExpressionError


# ---------------------------------------------------------------------------
# Valid predicates evaluate correctly
# ---------------------------------------------------------------------------


def test_evaluates_dict_index_compare():
    assert safe_eval("c['len'] > 0x10", {"c": {"len": 0x20}}) is True
    assert safe_eval("c['len'] > 0x10", {"c": {"len": 0x08}}) is False


def test_evaluates_new_not_equal_old():
    assert safe_eval("new != old", {"new": 5, "old": 4}) is True
    assert safe_eval("new != old", {"new": 4, "old": 4}) is False


def test_evaluates_chained_compare():
    assert safe_eval("0 < x < 10", {"x": 5}) is True
    assert safe_eval("0 < x < 10", {"x": 10}) is False
    assert safe_eval("0 < x < 10", {"x": -1}) is False


def test_boolean_and_or_short_circuit():
    assert safe_eval("a and b", {"a": True, "b": False}) is False
    assert safe_eval("a or b", {"a": False, "b": True}) is True
    # short-circuit: 'a' is falsy so 'b' (missing name) must never be evaluated
    assert safe_eval("a and b", {"a": False}) is False
    # short-circuit: 'a' is truthy so the missing 'b' on the or-path is reached
    assert safe_eval("a or b", {"a": True}) is True


def test_arithmetic_and_bitwise():
    assert safe_eval("(a & 0xff) == 0", {"a": 0x100}) is True
    assert safe_eval("(a & 0xff) == 0", {"a": 0x101}) is False
    assert safe_eval("(a | 0x0f) == 0x1f", {"a": 0x10}) is True
    assert safe_eval("(a ^ b) == 0", {"a": 7, "b": 7}) is True
    assert safe_eval("a + b * 2 - 1", {"a": 3, "b": 4}) == 10


def test_membership():
    assert safe_eval("x in (1, 2, 3)", {"x": 2}) is True
    assert safe_eval("x in (1, 2, 3)", {"x": 9}) is False
    assert safe_eval("x not in (1, 2, 3)", {"x": 9}) is True


def test_unary_and_conditional():
    assert safe_eval("not flag", {"flag": False}) is True
    assert safe_eval("-x == 0 - x", {"x": 7}) is True
    assert safe_eval("a if cond else b", {"a": 1, "b": 2, "cond": True}) == 1
    assert safe_eval("a if cond else b", {"a": 1, "b": 2, "cond": False}) == 2


# ---------------------------------------------------------------------------
# Escapes / abuse are rejected
# ---------------------------------------------------------------------------


def test_rejects_attribute_access():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("().__class__", {})


def test_rejects_subclass_traversal_escape():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("().__class__.__bases__[0].__subclasses__()", {})


def test_rejects_call():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("len(c)", {"c": [1, 2, 3]})


def test_rejects_lambda():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("lambda: 1", {})


def test_rejects_list_comprehension():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("[i for i in range(3)]", {})


def test_rejects_walrus():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("(x := 5)", {})


def test_rejects_unknown_name():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("os", {})


def test_rejects_unknown_name_even_with_other_env():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("os.system", {"c": {"len": 1}})


def test_builtins_are_not_reachable():
    # A name that resolves to a builtin in ordinary eval must NOT be reachable:
    # the evaluator only consults the supplied env, never builtins.
    for name in ("len", "open", "__import__", "eval", "True"):
        if name == "True":
            # True is an ast.Constant, not a Name -> it is a literal, fine.
            assert safe_eval("True", {}) is True
            continue
        with pytest.raises(UnsafeExpressionError):
            safe_eval(name, {})


def test_rejects_syntax_error():
    with pytest.raises(UnsafeExpressionError):
        safe_eval("1 +", {})


# ---------------------------------------------------------------------------
# No side effects / no dangerous imports pulled in by evaluation
# ---------------------------------------------------------------------------


def test_no_side_effects_no_subprocess_import():
    before = set(sys.modules)
    # A predicate referencing names that look like modules must not import them.
    with pytest.raises(UnsafeExpressionError):
        safe_eval("subprocess", {})
    safe_eval("c['len'] > 0", {"c": {"len": 3}})
    after = set(sys.modules)
    assert "subprocess" not in (after - before)


def test_evaluation_does_not_mutate_env():
    env = {"x": 1, "y": 2}
    snapshot = dict(env)
    safe_eval("x + y == 3", env)
    assert env == snapshot
