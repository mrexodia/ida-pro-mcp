"""Headless unit tests for the structured error taxonomy in errors.py.

The Batch-2 error module layers a small set of structured exception classes on
top of the existing ``McpToolError`` base that ``sync.IDAError`` already uses.
Each class:

  * subclasses the shared ``McpToolError`` base (so existing
    ``except IDAError`` / ``except McpToolError`` handlers and
    ``McpRpcRegistry.map_exception`` keep working), and
  * carries a distinct integer ``code`` plus a ``.message`` property, so callers
    can branch on *why* a tool failed without string-matching the message.

These run headless under the conftest idaapi stub (errors.py only imports from
``rpc`` and re-exports ``sync.IDAError``).
"""

from ida_pro_mcp.ida_mcp import errors
from ida_pro_mcp.ida_mcp.errors import (
    StructuredError,
    NotFoundError,
    InvalidArgumentError,
    VersionUnsupportedError,
    FeatureUnavailableError,
    IDAError,
)
from ida_pro_mcp.ida_mcp.rpc import McpToolError


# Every structured subclass, with the code the module documents for it.
_STRUCTURED = [
    (NotFoundError, -32004),
    (InvalidArgumentError, -32602),
    (VersionUnsupportedError, -32010),
    (FeatureUnavailableError, -32011),
]


def test_message_and_args_carry_text():
    for cls, _code in _STRUCTURED:
        err = cls("boom in " + cls.__name__)
        assert err.message == "boom in " + cls.__name__
        assert err.args[0] == err.message
        assert str(err) == err.message


def test_each_subclass_has_documented_code():
    for cls, code in _STRUCTURED:
        # Class attribute and instance attribute agree.
        assert cls.code == code
        assert cls("x").code == code


def test_codes_are_distinct():
    codes = [code for _cls, code in _STRUCTURED]
    assert len(set(codes)) == len(codes), f"codes collide: {codes}"
    # And none of them aliases the generic base code.
    assert StructuredError.code not in codes
    assert StructuredError.code == -32000


def test_subclass_the_shared_base():
    # All structured errors are McpToolError so the RPC registry maps them, and
    # StructuredError sits between them and the base.
    for cls, _code in _STRUCTURED:
        assert issubclass(cls, StructuredError)
        assert issubclass(cls, McpToolError)
        err = cls("x")
        assert isinstance(err, McpToolError)
        assert isinstance(err, StructuredError)


def test_structured_error_is_base_not_one_of_subclasses():
    err = StructuredError("generic")
    assert err.code == -32000
    assert err.message == "generic"
    assert isinstance(err, McpToolError)
    # The generic base must not be an instance of any specialised subclass.
    for cls, _code in _STRUCTURED:
        assert not isinstance(err, cls)


def test_idaerror_reexported_and_shares_base():
    # errors.py re-exports sync.IDAError so a single import covers the whole
    # taxonomy; it shares the McpToolError base but is NOT a StructuredError.
    assert IDAError is errors.IDAError
    err = IDAError("nope")
    assert isinstance(err, McpToolError)
    assert not isinstance(err, StructuredError)
    assert err.message == "nope"


def test_can_discriminate_cause_by_code_without_string_match():
    # The whole point of the taxonomy: branch on .code, not on message text.
    raised = [
        NotFoundError("no such function"),
        InvalidArgumentError("offset out of range"),
        VersionUnsupportedError("decompiler too old"),
        FeatureUnavailableError("no hexrays license"),
    ]
    by_code = {e.code: e for e in raised}
    assert by_code[-32004].message == "no such function"
    assert by_code[-32602].message == "offset out of range"
    assert by_code[-32010].message == "decompiler too old"
    assert by_code[-32011].message == "no hexrays license"


def test_module_all_exports_taxonomy():
    expected = {
        "IDAError",
        "StructuredError",
        "NotFoundError",
        "InvalidArgumentError",
        "VersionUnsupportedError",
        "FeatureUnavailableError",
    }
    assert expected.issubset(set(errors.__all__))
    for name in expected:
        assert hasattr(errors, name)
