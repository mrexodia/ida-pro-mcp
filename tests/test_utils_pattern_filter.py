import importlib.util
import pathlib
import sys
import types

import pytest


class _IdaStub(types.ModuleType):
    def __getattr__(self, name):
        dummy = type(name, (), {})
        setattr(self, name, dummy)
        return dummy


def _load_utils_module():
    pkg_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
    pkg_name = "_test_stub_ida_mcp_utils"

    for module_name in (
        "ida_bytes",
        "ida_funcs",
        "ida_hexrays",
        "ida_kernwin",
        "ida_nalt",
        "ida_typeinf",
        "idaapi",
        "idautils",
        "idc",
    ):
        sys.modules.setdefault(module_name, _IdaStub(module_name))

    package = types.ModuleType(pkg_name)
    package.__path__ = [str(pkg_root)]
    sys.modules[pkg_name] = package

    sync_module = types.ModuleType(pkg_name + ".sync")

    class IDAError(Exception):
        pass

    setattr(sync_module, "IDAError", IDAError)
    sys.modules[pkg_name + ".sync"] = sync_module

    utils_name = pkg_name + ".utils"
    spec = importlib.util.spec_from_file_location(utils_name, pkg_root / "utils.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[utils_name] = module
    spec.loader.exec_module(module)
    return module, IDAError


def test_pattern_filter_rejects_non_string_filter_before_pattern_matching():
    utils, IDAError = _load_utils_module()

    with pytest.raises(IDAError, match="Filter pattern must be a string, got dict"):
        utils.pattern_filter([{"name": "main"}], {"contains": "main"}, "name")


def test_pattern_filter_keeps_existing_string_matching_modes():
    utils, _ = _load_utils_module()
    data = [{"name": "main"}, {"name": "helper"}, {"name": "sub_1000"}]

    assert utils.pattern_filter(data, "main", "name") == [{"name": "main"}]
    assert utils.pattern_filter(data, "sub_*", "name") == [{"name": "sub_1000"}]
    assert utils.pattern_filter(data, "/HELP/i", "name") == [{"name": "helper"}]
