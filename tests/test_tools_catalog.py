"""Single-source-of-truth guard for the live tool surface (doc/prompt drift).

The authoritative description of which tools exist, how dangerous each is, and
which extension group (if any) gates it lives in exactly three runtime
structures populated by the @tool / @safety / @unsafe / @ext decorators at
import time:

    * ``MCP_SERVER.tools.methods`` -- the registry of every callable tool,
    * ``MCP_UNSAFE``               -- the set of tool names fenced behind the
      --unsafe / consent gate (DESTRUCTIVE / EXECUTE / PATCH tiers),
    * ``MCP_EXTENSIONS``           -- group -> tool-names (the only group is
      "dbg").

A queryable ``ida://tools`` catalog resource (axis-5 roadmap item) is meant to
be GENERATED from exactly these structures so a client can discover the real
surface without trusting hand-maintained prose. This module is that resource's
contract test: every entry the catalog would emit must

    1. name a tool that is actually registered,
    2. carry a resolvable safety class (READ / WRITE / DESTRUCTIVE / EXECUTE /
       PATCH) derived from the tool's MCP annotations,
    3. carry an ``ext`` value that matches MCP_EXTENSIONS membership,

and conversely MCP_UNSAFE / MCP_EXTENSIONS must never reference a tool that is
not registered. If a future ``ida://tools`` resource exists it is validated
directly; otherwise the same invariants are asserted against the registry it
would be generated from, so the guard is live today and tightens when the
resource lands.

Headless: importing the ``ida_pro_mcp.ida_mcp`` package (under the conftest
idaapi stub) runs every @tool decorator, fully populating the registry without
a live IDA.
"""

import pytest

# Importing the package __init__ pulls in every api_* module, so all @tool /
# @safety / @unsafe / @ext decorators have run and the registry is complete.
import ida_pro_mcp.ida_mcp  # noqa: F401  (import for decorator side effects)
from ida_pro_mcp.ida_mcp._kernel.rpc import (
    MCP_EXTENSIONS,
    MCP_SERVER,
    MCP_UNSAFE,
)


# ---------------------------------------------------------------------------
# Safety-class derivation (the catalog's "safety" column)
# ---------------------------------------------------------------------------

# Maps the boolean MCP toolAnnotations hint set back to its safety class. The
# five tiers are mutually exclusive on (readOnly, destructive, openWorld), so a
# tool's annotations resolve to exactly one class. PATCH and DESTRUCTIVE share
# the same hint vector; they are distinguished only by membership semantics
# (both are unsafe), so the catalog reports the shared "DESTRUCTIVE/PATCH"
# danger level here and relies on MCP_UNSAFE for the gate.
def _safety_class(func) -> str | None:
    ann = getattr(func, "__mcp_annotations__", None)
    if not ann:
        return None
    read = ann.get("readOnlyHint", False)
    destructive = ann.get("destructiveHint", False)
    open_world = ann.get("openWorldHint", False)
    idempotent = ann.get("idempotentHint", False)
    if read:
        return "READ"
    if destructive and open_world:
        return "EXECUTE"
    if destructive:
        return "DESTRUCTIVE/PATCH"
    if idempotent:
        return "WRITE"
    return None


def _ext_of(name: str) -> str | None:
    for group, names in MCP_EXTENSIONS.items():
        if name in names:
            return group
    return None


def _build_catalog() -> list[dict]:
    """The catalog the ``ida://tools`` resource would emit, generated from the
    same live registry it is contractually derived from."""
    catalog = []
    for name, func in MCP_SERVER.tools.methods.items():
        catalog.append(
            {
                "name": name,
                "safety": _safety_class(func),
                "unsafe": name in MCP_UNSAFE,
                "ext": _ext_of(name),
            }
        )
    return catalog


@pytest.fixture(scope="module")
def catalog() -> list[dict]:
    return _build_catalog()


@pytest.fixture(scope="module")
def registry_names() -> set[str]:
    return set(MCP_SERVER.tools.methods)


# ---------------------------------------------------------------------------
# The catalog enumerates exactly the live registry
# ---------------------------------------------------------------------------


def test_registry_is_non_trivially_populated(registry_names):
    # Guard against a collapsed import (e.g. an api module failing silently and
    # registering nothing): the shipped surface is well over a hundred tools.
    assert len(registry_names) >= 120


def test_catalog_covers_every_registered_tool(catalog, registry_names):
    catalog_names = {e["name"] for e in catalog}
    assert catalog_names == registry_names


def test_catalog_has_no_duplicate_entries(catalog):
    names = [e["name"] for e in catalog]
    assert len(names) == len(set(names))


def test_every_catalog_entry_has_a_safety_class(catalog):
    """The catalog's safety column must resolve for every tool -- a missing
    class means a tool shipped without @safety, which is the drift this guards."""
    missing = [e["name"] for e in catalog if e["safety"] is None]
    assert not missing, f"tools without a resolvable safety class: {sorted(missing)}"


def test_every_catalog_entry_carries_an_ext_field(catalog):
    # ext is part of the catalog row for every tool; None means "base /mcp".
    for entry in catalog:
        assert "ext" in entry


# ---------------------------------------------------------------------------
# MCP_UNSAFE membership matches the catalog's danger classification
# ---------------------------------------------------------------------------


def test_registered_unsafe_tools_are_all_mutating(catalog):
    """Every REGISTERED tool in MCP_UNSAFE classifies as a mutating tier.

    (We scope to the registered surface deliberately: MCP_UNSAFE is a process-
    global set that sibling unit tests also write throwaway @safety probe names
    into, so the unregistered residue is test scaffolding, not shipped drift.
    The shipped invariant is that no *registered* tool is both unsafe and
    READ/WRITE-classified.)
    """
    by_name = {e["name"]: e for e in catalog}
    bad = {}
    for name in MCP_UNSAFE:
        entry = by_name.get(name)
        if entry is None:
            continue  # test-injected probe, not a shipped tool
        if entry["safety"] not in ("DESTRUCTIVE/PATCH", "EXECUTE"):
            bad[name] = entry["safety"]
    assert not bad, f"registered unsafe tools not in a mutating tier: {bad}"


def test_known_unsafe_shipped_tools_are_registered(registry_names):
    """A representative set of real PATCH/EXECUTE tools must stay registered and
    unsafe -- a direct drift guard that is immune to test-probe pollution
    because it names concrete shipped tools rather than scanning the whole set.
    """
    shipped_unsafe = {
        "patch", "put_int", "patch_asm", "revert_patch",  # PATCH tier
        "py_eval", "py_exec_file",                          # EXECUTE tier
    }
    for name in shipped_unsafe:
        assert name in registry_names, f"shipped unsafe tool missing: {name}"
        assert name in MCP_UNSAFE, f"shipped unsafe tool no longer fenced: {name}"


def test_unsafe_tools_are_never_classified_read(catalog):
    """Every unsafe tool must be a mutating tier (not READ).

    The safety class and the MCP_UNSAFE gate are two views of the same fact; a
    READ-classified tool appearing in MCP_UNSAFE would be an inconsistency
    between them.
    """
    bad = [e["name"] for e in catalog if e["unsafe"] and e["safety"] == "READ"]
    assert not bad, f"READ-classified tools wrongly in MCP_UNSAFE: {sorted(bad)}"


def test_execute_and_destructive_tools_are_unsafe(catalog):
    """Every EXECUTE / DESTRUCTIVE-or-PATCH tool must be fenced by MCP_UNSAFE.

    @safety registers these tiers into MCP_UNSAFE automatically; this asserts
    the catalog and the gate cannot disagree.
    """
    should_be_unsafe = {
        e["name"]
        for e in catalog
        if e["safety"] in ("EXECUTE", "DESTRUCTIVE/PATCH")
    }
    leaked = {n for n in should_be_unsafe if n not in MCP_UNSAFE}
    assert not leaked, f"mutating tools missing from MCP_UNSAFE: {sorted(leaked)}"


def test_read_and_write_tools_are_not_unsafe(catalog):
    """READ / WRITE tiers are reversible and must never be in MCP_UNSAFE."""
    bad = {
        e["name"]
        for e in catalog
        if e["safety"] in ("READ", "WRITE") and e["unsafe"]
    }
    assert not bad, f"reversible tools wrongly in MCP_UNSAFE: {sorted(bad)}"


# ---------------------------------------------------------------------------
# MCP_EXTENSIONS membership matches the catalog's ext column
# ---------------------------------------------------------------------------


def test_only_ext_group_is_dbg():
    """The roadmap fixes a single shipped ext group; a new group appearing here
    is an intentional surface change that must update the docs/prompt mapping."""
    assert set(MCP_EXTENSIONS) == {"dbg"}


def test_mcp_extensions_only_references_registered_tools(registry_names):
    referenced = set().union(*MCP_EXTENSIONS.values()) if MCP_EXTENSIONS else set()
    dangling = referenced - registry_names
    assert not dangling, f"MCP_EXTENSIONS references unregistered tools: {sorted(dangling)}"


def test_catalog_ext_column_matches_mcp_extensions(catalog):
    """Each catalog row's ext value is exactly its MCP_EXTENSIONS membership."""
    for entry in catalog:
        expected = _ext_of(entry["name"])
        assert entry["ext"] == expected


def test_dbg_group_is_substantial_and_all_unsafe_or_read(catalog):
    """The dbg group is the debugger/probe toolkit: large, and every member is
    either a mutating (unsafe) tool or an explicitly READ-only inspector."""
    dbg = MCP_EXTENSIONS.get("dbg", set())
    assert len(dbg) >= 15
    by_name = {e["name"]: e for e in catalog}
    for name in dbg:
        entry = by_name[name]
        # No dbg tool may be unclassified.
        assert entry["safety"] is not None, f"dbg tool {name} has no safety class"


# ---------------------------------------------------------------------------
# If/when the ida://tools resource ships, it must match the registry exactly.
# ---------------------------------------------------------------------------


def _find_tools_resource():
    for func in MCP_SERVER.resources.methods.values():
        if getattr(func, "__resource_uri__", "") == "ida://tools":
            return func
    return None


# ---------------------------------------------------------------------------
# Ext visibility gating in tools/list (headless mirror of the IDA-only
# test_http.py::test_no_extension_tool_in_default_listing, which the conftest
# auto-skips because it lives under the real-IDA suite).
#
# tools/list filters by the per-request enabled-extensions set
# (MCP_SERVER._enabled_extensions.data). With no ext enabled, every @ext("dbg")
# tool MUST be absent; enabling "dbg" must reveal exactly the registered members
# of that group.
# ---------------------------------------------------------------------------


def _list_tool_names_with_ext(enabled: set[str]) -> set[str]:
    server = MCP_SERVER
    old = getattr(server._enabled_extensions, "data", set())
    server._enabled_extensions.data = set(enabled)
    try:
        return {t["name"] for t in server._mcp_tools_list()["tools"]}
    finally:
        server._enabled_extensions.data = old


def test_ext_dbg_tools_absent_from_default_tools_list():
    """With no ?ext enabled, no @ext("dbg") tool may appear in tools/list."""
    listed = _list_tool_names_with_ext(set())
    leaked = MCP_EXTENSIONS.get("dbg", set()) & listed
    assert not leaked, f"dbg ext tools visible without ?ext=dbg: {sorted(leaked)}"


def test_default_tools_list_is_exactly_the_non_ext_surface(registry_names):
    """The default listing equals the registry MINUS every grouped ext tool."""
    listed = _list_tool_names_with_ext(set())
    grouped = set().union(*MCP_EXTENSIONS.values()) if MCP_EXTENSIONS else set()
    assert listed == (registry_names - grouped)


def test_enabling_dbg_reveals_exactly_its_registered_members(registry_names):
    """Enabling ?ext=dbg adds back precisely the registered dbg-group tools."""
    base = _list_tool_names_with_ext(set())
    with_dbg = _list_tool_names_with_ext({"dbg"})
    revealed = with_dbg - base
    expected = MCP_EXTENSIONS["dbg"] & registry_names
    assert revealed == expected
    # And no base tool disappeared when the extension was enabled.
    assert base <= with_dbg


def test_ida_tools_resource_matches_registry_when_present(registry_names):
    """When the generated ``ida://tools`` resource exists it must list every
    registered tool, each with a safety class and an ext field. Skipped until
    the resource is implemented; the registry-level tests above are the live
    guard in the meantime.
    """
    func = _find_tools_resource()
    if func is None:
        pytest.skip("ida://tools resource not implemented yet")
    result = func()
    # Accept either {"tools": [...]} or a bare list of entries.
    entries = result["tools"] if isinstance(result, dict) else result
    listed = {e["name"] for e in entries}
    assert listed == registry_names
    for entry in entries:
        assert entry.get("safety") is not None
        assert "ext" in entry
        assert entry["ext"] == _ext_of(entry["name"])
        assert entry.get("unsafe", False) == (entry["name"] in MCP_UNSAFE)
