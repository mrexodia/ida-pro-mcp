"""Unit tests for the @safety / @title decorators and the schema builder.

Verifies:
  * @safety sets func.__mcp_annotations__ to the right hint set per class.
  * @safety("DESTRUCTIVE"/"EXECUTE") registers the tool into MCP_UNSAFE,
    while READ/WRITE do not.
  * @title sets func.__mcp_title__.
  * the zeromcp schema builder emits both `title` and `annotations`.
"""

import pytest

from ida_pro_mcp.ida_mcp.rpc import (
    MCP_SERVER,
    MCP_UNSAFE,
    safety,
    title,
)


# --------------------------------------------------------------------------
# @safety annotation hint sets
# --------------------------------------------------------------------------


def test_safety_read_annotations():
    @safety("READ")
    def t_read():
        return 1

    ann = t_read.__mcp_annotations__
    assert ann == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }


def test_safety_write_annotations():
    @safety("WRITE")
    def t_write():
        return 1

    ann = t_write.__mcp_annotations__
    assert ann["readOnlyHint"] is False
    assert ann["destructiveHint"] is False
    assert ann["idempotentHint"] is True
    assert ann["openWorldHint"] is False


def test_safety_destructive_annotations():
    @safety("DESTRUCTIVE")
    def t_destructive():
        return 1

    ann = t_destructive.__mcp_annotations__
    assert ann["destructiveHint"] is True
    assert ann["idempotentHint"] is False
    assert ann["readOnlyHint"] is False
    assert ann["openWorldHint"] is False


def test_safety_execute_annotations():
    @safety("EXECUTE")
    def t_execute():
        return 1

    ann = t_execute.__mcp_annotations__
    assert ann["destructiveHint"] is True
    assert ann["openWorldHint"] is True  # the EXECUTE-only distinction
    assert ann["idempotentHint"] is False
    assert ann["readOnlyHint"] is False


def test_safety_annotations_are_copies_not_shared():
    @safety("READ")
    def a():
        return 1

    @safety("READ")
    def b():
        return 1

    a.__mcp_annotations__["readOnlyHint"] = False
    assert b.__mcp_annotations__["readOnlyHint"] is True  # not aliased


def test_unknown_safety_level_raises():
    with pytest.raises(ValueError):
        @safety("YOLO")
        def bad():
            return 1


# --------------------------------------------------------------------------
# MCP_UNSAFE registration semantics
# --------------------------------------------------------------------------


def test_destructive_registers_into_mcp_unsafe():
    @safety("DESTRUCTIVE")
    def unsafe_destructive_probe():
        return 1

    assert "unsafe_destructive_probe" in MCP_UNSAFE


def test_execute_registers_into_mcp_unsafe():
    @safety("EXECUTE")
    def unsafe_execute_probe():
        return 1

    assert "unsafe_execute_probe" in MCP_UNSAFE


def test_read_does_not_register_into_mcp_unsafe():
    @safety("READ")
    def safe_read_probe():
        return 1

    assert "safe_read_probe" not in MCP_UNSAFE


def test_write_does_not_register_into_mcp_unsafe():
    @safety("WRITE")
    def safe_write_probe():
        return 1

    assert "safe_write_probe" not in MCP_UNSAFE


# --------------------------------------------------------------------------
# @title
# --------------------------------------------------------------------------


def test_title_sets_attribute():
    @title("Friendly Title")
    def t():
        return 1

    assert t.__mcp_title__ == "Friendly Title"


def test_title_and_safety_compose():
    @safety("READ")
    @title("Read Something")
    def t():
        return 1

    assert t.__mcp_title__ == "Read Something"
    assert t.__mcp_annotations__["readOnlyHint"] is True


# --------------------------------------------------------------------------
# schema builder emits title + annotations
# --------------------------------------------------------------------------


def test_schema_emits_title_and_annotations():
    @safety("EXECUTE")
    @title("Do The Thing")
    def my_tool(x: int) -> int:
        """Docstring."""
        return x

    schema = MCP_SERVER._build_tool_schema("my_tool", my_tool)
    assert schema["name"] == "my_tool"
    assert schema["title"] == "Do The Thing"
    assert schema["annotations"]["openWorldHint"] is True
    assert schema["annotations"]["destructiveHint"] is True


def test_schema_omits_title_and_annotations_when_absent():
    def plain_tool(x: int) -> int:
        """Plain."""
        return x

    schema = MCP_SERVER._build_tool_schema("plain_tool", plain_tool)
    assert "title" not in schema
    assert "annotations" not in schema


def test_real_shipped_search_docs_is_read_and_titled():
    from ida_pro_mcp.ida_mcp.api_docs import search_docs

    assert search_docs.__mcp_annotations__["readOnlyHint"] is True
    assert search_docs.__mcp_title__ == "Search the MCP documentation"
    assert "search_docs" not in MCP_UNSAFE


# --------------------------------------------------------------------------
# PATCH safety tier (binary-byte writers) — axis 7
# --------------------------------------------------------------------------


def test_patch_level_exists_and_implies_destructive():
    @safety("PATCH")
    def t_patch():
        return 1

    ann = t_patch.__mcp_annotations__
    assert ann["destructiveHint"] is True
    assert ann["readOnlyHint"] is False
    assert ann["idempotentHint"] is False
    # PATCH is distinguished from EXECUTE: it does not touch the open world.
    assert ann["openWorldHint"] is False


def test_patch_level_registers_into_mcp_unsafe():
    @safety("PATCH")
    def unsafe_patch_probe():
        return 1

    assert "unsafe_patch_probe" in MCP_UNSAFE


def test_binary_byte_writers_are_unsafe():
    """The real image-byte writers must all be in the unsafe (PATCH) tier."""
    # Import the modules so their @safety decorators have run.
    from ida_pro_mcp.ida_mcp import api_memory, api_modify  # noqa: F401

    for name in ("patch", "put_int", "patch_asm", "revert_patch"):
        assert name in MCP_UNSAFE, f"{name} should be a binary-byte (PATCH) tier tool"


def test_reversible_metadata_edits_are_not_unsafe():
    """WRITE-tier IDB annotation edits are reversible and must NOT be unsafe."""
    from ida_pro_mcp.ida_mcp import api_modify  # noqa: F401

    for name in ("rename", "set_comments", "append_comments", "set_op_type"):
        assert name not in MCP_UNSAFE, f"{name} is reversible metadata (WRITE), not unsafe"


def test_list_patches_is_read_only_not_unsafe():
    from ida_pro_mcp.ida_mcp import api_memory  # noqa: F401

    assert "list_patches" not in MCP_UNSAFE
