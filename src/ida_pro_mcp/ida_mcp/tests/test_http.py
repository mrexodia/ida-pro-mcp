"""Tests for HTTP/config helpers that are not tied to a specific binary."""

from ..framework import test
from .. import http as http_mod


class _FakeRegistry:
    def __init__(self, methods):
        self.methods = methods


@test()
def test_handle_enabled_tools_keeps_discovery_tools_enabled_on_startup():
    """Saved config should not be able to hide discovery/recovery tools at startup."""
    original_get = http_mod.config_json_get
    original_set = http_mod.config_json_set
    registry = _FakeRegistry(
        {
            "list_instances": object(),
            "select_instance": object(),
            "open_file": object(),
            "decompile": object(),
        }
    )
    saved_config = {name: False for name in registry.methods}

    http_mod.config_json_get = lambda key, default: saved_config.copy()
    http_mod.config_json_set = lambda key, value: None
    try:
        http_mod.handle_enabled_tools(registry, "enabled_tools")
        assert "list_instances" in registry.methods
        assert "select_instance" in registry.methods
        assert "open_file" in registry.methods
        assert "decompile" not in registry.methods
    finally:
        http_mod.config_json_get = original_get
        http_mod.config_json_set = original_set
