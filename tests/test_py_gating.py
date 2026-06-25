"""Headless tests for the axis-7 injected-Python patch gate.

Covers consent.block_byte_writes (the image-byte-write fence) and api_python.py_eval's
allow_patch parameter. These run under the stub idaapi (tests/conftest.py), where
ida_bytes is a MagicMock module, so the swap-and-restore behaviour is observable
without a real IDA.
"""

import pytest


def test_block_byte_writes_blocks_image_writer_and_restores():
    import ida_bytes
    from ida_pro_mcp.ida_mcp.consent import block_byte_writes, PatchBlockedError

    original = ida_bytes.patch_bytes
    with block_byte_writes():
        with pytest.raises(PatchBlockedError):
            ida_bytes.patch_bytes(0x1000, b"\x90")
    # The original function is restored on exit.
    assert ida_bytes.patch_bytes is original


def test_block_byte_writes_leaves_revert_callable():
    # revert_byte (the patch UNDO) is the antidote and must never be blocked.
    import ida_bytes
    from ida_pro_mcp.ida_mcp.consent import block_byte_writes

    with block_byte_writes():
        ida_bytes.revert_byte(0x1000)  # must not raise


def test_py_eval_blocks_image_patch_by_default():
    from ida_pro_mcp.ida_mcp.api_python import py_eval

    res = py_eval("ida_bytes.patch_bytes(0x1000, b'\\x90')")
    blob = res["stderr"].lower()
    assert "patchblockederror" in blob or "disabled" in blob, res


def test_py_eval_allows_image_patch_when_opted_in():
    from ida_pro_mcp.ida_mcp.api_python import py_eval

    res = py_eval("ida_bytes.patch_bytes(0x1000, b'\\x90')", allow_patch=True)
    # With the stub, patch_bytes is a MagicMock that merely records the call;
    # no PatchBlockedError should surface when patching is explicitly allowed.
    assert "PatchBlockedError" not in res["stderr"], res
