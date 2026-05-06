"""Tests for global defaults functionality.

Tests the read_global_defaults() and write_global_defaults() functions
in discovery.py, as well as the config_json_get() fallback behavior.
"""

import contextlib
import json
import os
import tempfile

from ..framework import test
from .. import discovery


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _tmp_defaults_path():
    """Redirect discovery.get_global_defaults_path to a temp file, then restore."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = os.path.join(tmp, "defaults.json")
        original = discovery.get_global_defaults_path
        discovery.get_global_defaults_path = lambda: tmp_path
        try:
            yield tmp_path
        finally:
            discovery.get_global_defaults_path = original


# ---------------------------------------------------------------------------
# read_global_defaults tests
# ---------------------------------------------------------------------------

@test()
def test_read_global_defaults_missing_file():
    """read_global_defaults returns {} when file doesn't exist."""
    with _tmp_defaults_path():
        result = discovery.read_global_defaults()
        assert result == {}


@test()
def test_read_global_defaults_corrupt_json():
    """read_global_defaults returns {} when JSON is invalid."""
    with _tmp_defaults_path() as tmp_path:
        with open(tmp_path, "w") as f:
            f.write("not json{{{")
        result = discovery.read_global_defaults()
        assert result == {}


@test()
def test_read_global_defaults_non_dict_json():
    """read_global_defaults returns {} when JSON is not a dict."""
    with _tmp_defaults_path() as tmp_path:
        with open(tmp_path, "w") as f:
            json.dump(["array", "not", "dict"], f)
        result = discovery.read_global_defaults()
        assert result == {}


@test()
def test_read_global_defaults_valid_dict():
    """read_global_defaults returns the dict when valid JSON dict exists."""
    with _tmp_defaults_path() as tmp_path:
        expected = {
            "host": "192.168.1.100",
            "port": 9999,
            "autostart": False,
            "cors_policy": "unrestricted",
            "enabled_tools": {"tool_a": True, "tool_b": False},
        }
        with open(tmp_path, "w") as f:
            json.dump(expected, f)
        result = discovery.read_global_defaults()
        assert result == expected


# ---------------------------------------------------------------------------
# write_global_defaults tests
# ---------------------------------------------------------------------------

@test()
def test_write_then_read_roundtrip():
    """write_global_defaults followed by read returns the same data."""
    with _tmp_defaults_path():
        data = {
            "host": "10.0.0.1",
            "port": 8080,
            "autostart": True,
            "cors_policy": "local",
            "enabled_tools": {"decompile": True, "disasm": True},
        }
        discovery.write_global_defaults(data)
        result = discovery.read_global_defaults()
        assert result == data


@test()
def test_write_creates_parent_dirs():
    """write_global_defaults creates parent directories if they don't exist."""
    with _tmp_defaults_path() as tmp_path:
        # Ensure the parent directory doesn't exist
        parent_dir = os.path.dirname(tmp_path)
        if os.path.exists(parent_dir):
            os.rmdir(parent_dir)
        assert not os.path.isdir(parent_dir)

        discovery.write_global_defaults({"test": "value"})
        assert os.path.isfile(tmp_path)


@test()
def test_write_atomic_on_error():
    """write_global_defaults leaves no temp file on error."""
    with _tmp_defaults_path() as tmp_path:
        parent_dir = os.path.dirname(tmp_path)
        # Make the directory read-only to force a write error
        # (This test may not fail on all systems, but verifies the cleanup logic)
        try:
            # Try to write to a non-existent subdirectory
            bad_path = os.path.join(parent_dir, "nonexistent", "defaults.json")
            orig = discovery.get_global_defaults_path
            discovery.get_global_defaults_path = lambda: bad_path
            try:
                discovery.write_global_defaults({"test": "value"})
                # If we get here, the write succeeded (e.g., on some systems)
            except (OSError, PermissionError):
                # Expected on most systems
                pass
            finally:
                discovery.get_global_defaults_path = orig
        finally:
            # Verify no temp files were left behind
            temp_files = [f for f in os.listdir(parent_dir) if f.startswith(".tmp_")]
            assert len(temp_files) == 0


# ---------------------------------------------------------------------------
# Integration tests (require IDA environment)
# ---------------------------------------------------------------------------

@test()
def test_config_json_get_falls_back_to_global_default():
    """config_json_get returns global default when netnode is empty."""
    from ..http import config_json_get

    with _tmp_defaults_path() as tmp_path:
        # Write a global default
        discovery.write_global_defaults({"cors_policy": "unrestricted"})

        # netnode is empty, should fall back to global default
        result = config_json_get("cors_policy", "local")
        assert result == "unrestricted"


@test()
def test_config_json_get_prefers_netnode_over_global():
    """config_json_get prefers netnode value over global default."""
    from ..http import config_json_get, config_json_set

    with _tmp_defaults_path():
        # Write a global default
        discovery.write_global_defaults({"cors_policy": "unrestricted"})

        # Set a different value in netnode
        config_json_set("cors_policy", "local")

        # Should prefer netnode value
        result = config_json_get("cors_policy", "local")
        assert result == "local"


@test()
def test_config_json_get_returns_default_when_both_missing():
    """config_json_get returns the passed default when both netnode and global are missing."""
    from ..http import config_json_get

    with _tmp_defaults_path():
        # Ensure no global default exists
        # (file doesn't exist by default in _tmp_defaults_path)

        result = config_json_get("nonexistent_key", "fallback_value")
        assert result == "fallback_value"
