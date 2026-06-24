"""Unit tests for api_domain's pure logic.

The api_domain module wraps the ida-domain SDK, but several pieces are pure and
testable without IDA or a live database:

  * the address parser ``_parse_ea`` (decimal / 0x-hex / bare-hex),
  * the uniform error builders ``_sdk_unavailable`` / ``_exc_error``,
  * the xref-type namer ``_xref_type_name`` (best-effort, never raises),
  * the SDK-absent guard every tool runs first: with ``ida_domain`` forced to
    None each tool returns the structured ``ida_domain_unavailable`` error
    dict rather than raising,
  * the ``domain_xrefs`` direction validation (rejects anything but to/from
    before it ever touches the SDK).

The package imports cleanly under the conftest idaapi stub; ``ida_domain`` is a
real installed package, so the SDK-absent path is exercised by monkeypatching
the module-level ``ida_domain`` attribute to None.
"""

import pytest

from ida_pro_mcp.ida_mcp import api_domain


# --------------------------------------------------------------------------
# _parse_ea
# --------------------------------------------------------------------------


def test_parse_ea_decimal():
    assert api_domain._parse_ea("4198400") == 4198400


def test_parse_ea_hex_prefixed():
    assert api_domain._parse_ea("0x401000") == 0x401000


def test_parse_ea_hex_prefixed_uppercase():
    assert api_domain._parse_ea("0X401000") == 0x401000


def test_parse_ea_strips_whitespace():
    assert api_domain._parse_ea("  0x10  ") == 0x10


def test_parse_ea_bare_hex_fallback():
    # No 0x prefix and not valid decimal -> fall back to base-16.
    assert api_domain._parse_ea("deadbeef") == 0xDEADBEEF


def test_parse_ea_zero():
    assert api_domain._parse_ea("0") == 0


def test_parse_ea_invalid_raises():
    with pytest.raises(ValueError):
        api_domain._parse_ea("not_an_address")


# --------------------------------------------------------------------------
# error builders
# --------------------------------------------------------------------------


def test_sdk_unavailable_shape():
    err = api_domain._sdk_unavailable()
    assert err["error"] == "ida_domain_unavailable"
    assert "ida-domain" in err["detail"]
    assert set(err.keys()) == {"error", "detail"}


def test_exc_error_shape():
    err = api_domain._exc_error("some_kind", ValueError("boom"))
    assert err["error"] == "some_kind"
    assert err["detail"] == "ValueError: boom"
    assert set(err.keys()) == {"error", "detail"}


# --------------------------------------------------------------------------
# _xref_type_name (best-effort, never raises)
# --------------------------------------------------------------------------


class _XrefWithNamedType:
    class _T:
        name = "Code_Near_Call"

    type = _T()


class _XrefWithStrType:
    type = "Data_Read"


class _XrefRaisingType:
    @property
    def type(self):
        raise RuntimeError("no type here")


def test_xref_type_name_named():
    assert api_domain._xref_type_name(_XrefWithNamedType()) == "Code_Near_Call"


def test_xref_type_name_stringifies_when_no_name():
    assert api_domain._xref_type_name(_XrefWithStrType()) == "Data_Read"


def test_xref_type_name_swallows_exception():
    assert api_domain._xref_type_name(_XrefRaisingType()) == "unknown"


# --------------------------------------------------------------------------
# SDK-absent guard: every tool returns the structured error, never raises
# --------------------------------------------------------------------------


@pytest.fixture
def no_sdk(monkeypatch):
    """Force the module to behave as if the ida-domain SDK were not installed."""
    monkeypatch.setattr(api_domain, "ida_domain", None, raising=False)
    monkeypatch.setattr(api_domain, "Database", None, raising=False)


def _expect_unavailable(result):
    assert isinstance(result, dict)
    assert result["error"] == "ida_domain_unavailable"
    assert "detail" in result


def test_domain_functions_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_functions())


def test_domain_functions_with_filter_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_functions("recv"))


def test_domain_function_pseudocode_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_function_pseudocode("0x401000"))


def test_domain_xrefs_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_xrefs("0x401000"))


def test_domain_strings_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_strings())


def test_domain_segments_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_segments())


def test_domain_types_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_types())


def test_domain_entry_points_without_sdk(no_sdk):
    _expect_unavailable(api_domain.domain_entry_points())


# --------------------------------------------------------------------------
# domain_xrefs direction validation
#
# The SDK-absent guard runs FIRST, so to exercise direction validation we must
# keep ida_domain truthy (a sentinel) while ensuring the bad-direction branch
# returns before any real SDK call is made.
# --------------------------------------------------------------------------


@pytest.fixture
def sdk_present_sentinel(monkeypatch):
    monkeypatch.setattr(api_domain, "ida_domain", object(), raising=False)


def test_domain_xrefs_rejects_bad_direction(sdk_present_sentinel):
    result = api_domain.domain_xrefs("0x401000", "sideways")
    assert result["error"] == "invalid_direction"
    assert "to" in result["detail"] and "from" in result["detail"]


def test_domain_xrefs_accepts_to_direction_case_insensitive(sdk_present_sentinel):
    # 'TO' normalizes past the direction guard; it then fails at the (absent)
    # real SDK call and is caught into a structured error -- never raises and
    # never reports invalid_direction.
    result = api_domain.domain_xrefs("0x401000", "TO")
    assert result["error"] != "invalid_direction"


def test_domain_xrefs_invalid_address_after_valid_direction(sdk_present_sentinel):
    result = api_domain.domain_xrefs("not_an_address", "to")
    assert result["error"] == "invalid_address"


# --------------------------------------------------------------------------
# _ensure_sdk lazy loader
#
# The SDK is imported lazily so the module is importable without a live IDA.
# _ensure_sdk is idempotent and must never clobber a pinned ida_domain global.
# --------------------------------------------------------------------------


def test_ensure_sdk_is_noop_when_pinned_none(monkeypatch):
    monkeypatch.setattr(api_domain, "ida_domain", None, raising=False)
    monkeypatch.setattr(api_domain, "Database", None, raising=False)
    api_domain._ensure_sdk()
    # Pinned None is left untouched -- the loader does not re-import over it.
    assert api_domain.ida_domain is None
    assert api_domain.Database is None


def test_ensure_sdk_is_noop_when_pinned_sentinel(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(api_domain, "ida_domain", sentinel, raising=False)
    api_domain._ensure_sdk()
    assert api_domain.ida_domain is sentinel


def test_ensure_sdk_resolves_from_unloaded(monkeypatch):
    # Force the pre-load sentinel state and stub the import to a fake SDK so the
    # loader's resolve path runs without touching the real native SDK.
    monkeypatch.setattr(api_domain, "ida_domain", api_domain._UNLOADED, raising=False)
    monkeypatch.setattr(api_domain, "Database", api_domain._UNLOADED, raising=False)

    import sys
    import types

    fake = types.ModuleType("ida_domain")
    fake.Database = object
    monkeypatch.setitem(sys.modules, "ida_domain", fake)

    api_domain._ensure_sdk()
    assert api_domain.ida_domain is fake
    assert api_domain.Database is fake.Database


def test_unloaded_sentinel_is_distinct_from_none():
    assert api_domain._UNLOADED is not None


# --------------------------------------------------------------------------
# module surface
# --------------------------------------------------------------------------


def test_module_exports_all_tools():
    expected = {
        "domain_functions",
        "domain_function_pseudocode",
        "domain_xrefs",
        "domain_strings",
        "domain_segments",
        "domain_types",
        "domain_entry_points",
    }
    assert expected.issubset(set(api_domain.__all__))
    for name in expected:
        assert hasattr(api_domain, name)
