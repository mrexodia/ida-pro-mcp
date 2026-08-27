import json
import tomllib
from pathlib import Path

import ida_pro_mcp.installer as installer


def test_claude_config_contains_ten_consecutive_http_endpoints(monkeypatch):
    monkeypatch.setattr(installer, "IDA_HOST", "127.0.0.1")
    monkeypatch.setattr(installer, "IDA_PORT", 13337)

    configs = installer.generate_mcp_configs(
        client_name="Claude", transport="streamable-http"
    )

    assert list(configs) == [f"ida-pro-mcp-{i}" for i in range(1, 11)]
    assert [
        config["url"] for config in configs.values()
    ] == [f"http://127.0.0.1:{port}/mcp" for port in range(13337, 13347)]


def test_codex_stdio_config_is_pinned_to_each_port(monkeypatch):
    monkeypatch.setattr(installer, "IDA_PORT", 14000)

    configs = installer.generate_mcp_configs(client_name="Codex", transport="stdio")

    assert len(configs) == 10
    for index, config in enumerate(configs.values()):
        assert config["args"][-2:] == [
            "--ida-rpc",
            f"http://127.0.0.1:{14000 + index}",
        ]


def test_other_clients_keep_single_server_config(monkeypatch):
    monkeypatch.setattr(installer, "IDA_PORT", 15000)

    configs = installer.generate_mcp_configs(
        client_name="Cursor", transport="streamable-http"
    )

    assert list(configs) == ["ida-pro-mcp"]
    assert configs["ida-pro-mcp"]["url"] == "http://127.0.0.1:15000/mcp"


def test_opencode_config_contains_ten_remote_endpoints(monkeypatch):
    monkeypatch.setattr(installer, "IDA_PORT", 15500)

    configs = installer.generate_mcp_configs(
        client_name="Opencode", transport="streamable-http"
    )

    assert len(configs) == 10
    for index, config in enumerate(configs.values(), start=1):
        assert config == {
            "type": "remote",
            "url": f"http://127.0.0.1:{15499 + index}/mcp",
        }


def test_install_replaces_legacy_single_entry_with_pool(tmp_path, monkeypatch):
    config_dir = tmp_path / "claude"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "ida-pro-mcp": {"type": "http", "url": "http://old/mcp"},
                    "other-server": {"command": "keep-me"},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        installer,
        "get_global_configs",
        lambda: {"Claude": (str(config_dir), "config.json")},
    )
    monkeypatch.setattr(installer, "IDA_PORT", 16000)

    installer.install_mcp_servers(
        only=["Claude"], transport="streamable-http", quiet=True
    )

    result = json.loads(config_path.read_text(encoding="utf-8"))
    servers = result["mcpServers"]
    assert "other-server" in servers
    assert "ida-pro-mcp" not in servers
    assert len([name for name in servers if name.startswith("ida-pro-mcp-")]) == 10
    assert servers["ida-pro-mcp-10"]["url"] == "http://127.0.0.1:16009/mcp"


def test_claude_and_codex_plugin_manifests_expose_same_port_pool():
    root = Path(__file__).parents[1]
    claude = json.loads((root / ".claude-plugin" / "plugin.json").read_text())
    codex = json.loads((root / ".codex-plugin" / "mcp.json").read_text())

    for manifest in (claude, codex):
        servers = manifest["mcpServers"]
        assert [
            servers[f"ida-pro-mcp-{i}"]["url"]
            for i in range(1, 11)
        ] == [f"http://127.0.0.1:{port}/mcp" for port in range(13337, 13347)]


def test_codex_toml_install_uses_mcp_servers_pool(tmp_path, monkeypatch):
    config_dir = tmp_path / "codex"
    config_dir.mkdir()
    config_path = config_dir / "config.toml"
    config_path.write_text(
        '[mcp_servers.other]\nurl = "http://other/mcp"\n', encoding="utf-8"
    )
    monkeypatch.setattr(
        installer,
        "get_global_configs",
        lambda: {"Codex": (str(config_dir), "config.toml")},
    )
    monkeypatch.setattr(installer, "IDA_PORT", 17000)

    installer.install_mcp_servers(
        only=["Codex"], transport="streamable-http", quiet=True
    )

    servers = tomllib.loads(config_path.read_text(encoding="utf-8"))["mcp_servers"]
    assert servers["other"]["url"] == "http://other/mcp"
    assert servers["ida-pro-mcp-1"]["url"] == "http://127.0.0.1:17000/mcp"
    assert servers["ida-pro-mcp-10"]["url"] == "http://127.0.0.1:17009/mcp"
