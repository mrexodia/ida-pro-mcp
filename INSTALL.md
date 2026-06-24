# Installing the AriusII fork of IDA Pro MCP

This is the install guide for the **AriusII fork** of `ida-pro-mcp`
(`https://github.com/AriusII/ida-pro-mcp`). It covers installing the package,
installing the IDA plugin, and pointing an MCP client at the running server.

## Requirements

- **IDA Pro 9.3** (or later in the 9.x line). IDA Free is rejected by the
  installer unless you pass `--allow-ida-free`.
- **Python 3.13.** The package supports `>=3.11,<3.14`, but **3.13 is the
  practical floor for IDA 9.3**: the `ida-domain` / `idapro` dependencies pin the
  3.13 ceiling, and that is the interpreter the plugin runs under.
- IDA must be using the same Python as the one you install the package into. If
  IDA does not pick up the right interpreter, run the bundled
  **`idapyswitch`** tool (shipped with IDA) and select your Python 3.13
  installation, then restart IDA.

## 1. Install the package

### From git (recommended)

With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/AriusII/ida-pro-mcp
```

Or with pip:

```bash
pip install git+https://github.com/AriusII/ida-pro-mcp
```

### From a GitHub Release wheel

Each tagged release (`v*`) publishes a built wheel + sdist on the
[Releases page](https://github.com/AriusII/ida-pro-mcp/releases). Download the
`.whl` and install it directly:

```bash
uv tool install ./ida_pro_mcp-<version>-py3-none-any.whl
# or
pip install ./ida_pro_mcp-<version>-py3-none-any.whl
```

After installation the following console scripts are on your `PATH` (defined in
`pyproject.toml` under `[project.scripts]`):

| Command | Purpose |
|---|---|
| `ida-pro-mcp` | The MCP server + plugin installer (the main entry point) |
| `idalib-mcp` | The idalib supervisor (headless idalib server) |
| `ida-mcp-test` | Test runner against a sample database |
| `ida-mcp-trace-dump` | Trace dump utility |

## 2. Install the IDA plugin

Run the installer entry point. The IDA plugin is installed immediately, and you
are prompted to wire up your MCP client(s):

```bash
ida-pro-mcp --install
```

You can target specific clients non-interactively, e.g.:

```bash
ida-pro-mcp --install claude,cursor
```

Useful flags:

- `--list-clients` — list every supported MCP client target.
- `--scope project|global` — install for the current directory (default) or
  user-wide.
- `--transport streamable-http|stdio|sse` — transport written into the client
  config (default: `streamable-http`).
- `--allow-ida-free` — permit installation when only IDA Free is present.
- `--uninstall [TARGETS]` — reverse the install.

## 3. Configure your MCP client

The plugin runs an HTTP MCP server inside IDA on **port 13337**. There are two
endpoints:

| Endpoint | Toolset |
|---|---|
| `http://127.0.0.1:13337/mcp` | **Base** — static-analysis tools only |
| `http://127.0.0.1:13337/mcp?ext=dbg` | **Debugger-extended** — the base tools **plus** the live debugger + probe toolkit (`dbg_*`) |

The `?ext=dbg` endpoint is a **superset** of the base one — prefer it for full
static + dynamic coverage from a single connection.

Example client registration (Claude Code), pointing at the debugger-extended
endpoint:

```bash
claude mcp add --transport http ida "http://127.0.0.1:13337/mcp?ext=dbg"
```

If the `dbg_*` tools are missing from your session, you are connected to the
base `/mcp` endpoint — re-register on `?ext=dbg`.

## 4. Smoke check

Confirm the CLI is installed and resolves correctly:

```bash
uv run ida-pro-mcp --help
```

(or `ida-pro-mcp --help` if you installed with `uv tool install` / `pip`.) You
should see the server's argument help, including `--install`, `--uninstall`,
`--list-clients`, and `--transport`.

Then open a database in IDA Pro, and verify your MCP client lists the
`mcp__ida__*` tools.
