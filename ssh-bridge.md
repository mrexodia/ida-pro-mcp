# ssh-bridge: use a local IDA Pro from a remote agent

`ida-pro-mcp ssh-bridge` lets an MCP client (Claude Code, etc.) running on a
**remote SSH server** reach an IDA Pro instance running on your **local
workstation**.

This guide has three parts: [How it works](#1-how-it-works) ·
[Usage](#2-usage) · [Security](#3-security).

> 中文版见 [ssh-bridge.zh-CN.md](ssh-bridge.zh-CN.md).

---

## 1. How it works

### 1.1 The problem

`ida-pro-mcp` has two independent components:

| Component | Role | Usually runs on |
|-----------|------|-----------------|
| **IDA plugin** (`ida_mcp`) | Listens on `127.0.0.1:13337` inside IDA and exposes a JSON-RPC interface | Local (installed into your local IDA) |
| **MCP server** (`server.py`) | A pure-Python proxy: speaks MCP upstream, forwards requests over HTTP to `13337` downstream | Anywhere (**does not require IDA**) |

In a typical remote-development setup IDA runs locally while the AI agent runs
on a remote server. The agent-side MCP server connects to `127.0.0.1:13337`,
but that resolves to the **remote server itself**, whereas the IDA plugin is
listening on the **local** loopback address — the link is broken at the
network layer.

```
Local workstation                       Remote server
┌──────────────────┐                    ┌──────────────────────┐
│ IDA + plugin     │                    │ Claude Code (agent)  │
│ 127.0.0.1:13337  │   ✗ unreachable ✗  │   └─ MCP server      │
└──────────────────┘                    │      connects to     │
                                         │      127.0.0.1 → self│
                                         └──────────────────────┘
```

### 1.2 The solution: an SSH reverse tunnel

The two sides communicate over plain "HTTP to some host:port". `ssh-bridge`
opens an SSH connection from your **local** machine to the remote and sets up a
**reverse port forward** (`ssh -R`), so traffic to a loopback port on the
remote is carried back to the local machine over the encrypted tunnel.

```
Local workstation                            Remote server
┌──────────────────┐                         ┌──────────────────────────┐
│ IDA + plugin     │◀── tunnel carries back ──│ 127.0.0.1:<port> (listen) │
│ 127.0.0.1:13337  │                          │        ▲                  │
└────────▲─────────┘                          │        │ connects to      │
         │   ssh-bridge dials outbound ──────▶ sshd    │ local loopback    │
         └─────────────────────────────────────────── Claude Code (agent) │
                                               └──────────────────────────┘
```

**Key point: connection direction.** The SSH connection is initiated
**outbound from local to remote** (the same direction you log in with). As a
result:

- **It works even when the local machine is behind NAT / on an intranet** — all
  you need is outbound SSH from local to the server; the server does not need to
  reach back into your network.
- The only requirement is that the **remote server runs `sshd`**.

### 1.3 Two modes

#### `sse` mode (default — nothing to install on the remote)

`ssh-bridge` starts an extra SSE-style MCP server **locally** (it connects to
the local IDA on `13337` over loopback, never across the network), then
reverse-forwards only that SSE port (default `8744`) to the remote. The remote
Claude Code points its MCP server at the tunneled URL (e.g.
`http://127.0.0.1:8744/sse`).

**Nothing needs to be installed on the remote server** — it just talks MCP over
HTTP/SSE to the local machine through the tunnel.

```
Local: IDA(13337) ←loopback← local SSE server(8744) ←reverse-forward 8744→ Remote: Claude Code → 8744
```

#### `rpc` mode (remote runs `ida-pro-mcp`)

Reverse-forwards the IDA RPC port(s) (`13337`, etc.) directly to the remote.
The remote needs `ida-pro-mcp` installed (pure Python — **IDA is not
required** there), launched over stdio by Claude Code with
`--ida-rpc http://127.0.0.1:13337` pointing at the tunneled port. Use
`--all-instances` to forward every running local IDA instance at once.

### 1.4 Robustness

`ssh-bridge` configures the underlying ssh with `ServerAliveInterval`
(keepalive heartbeats), `ExitOnForwardFailure=yes` (exit immediately if a
forward can't be established), and a `ConnectTimeout`. If the connection drops,
it **auto-reconnects** with exponential backoff; once a connection stays up for
more than 30s the backoff is reset. `Ctrl-C` tears down both the tunnel and the
local SSE server.

---

## 2. Usage

### 2.1 Prerequisites

- **Local**: IDA Pro and the `ida-pro-mcp` plugin installed, and the MCP plugin
  started in IDA (`Edit -> Plugins -> MCP`, shortcut `Ctrl+Alt+M` /
  `Ctrl+Option+M` on macOS).
- **Local**: a working `ssh` client that can log into the remote server (key
  auth recommended).
- **Remote**: `sshd` reachable. In `sse` mode the remote needs nothing else; in
  `rpc` mode the remote needs `pip/uv install ida-pro-mcp`.

> Always run `ssh-bridge` on the **local workstation** (the machine running IDA).

### 2.2 Getting and launching the bridge

`ssh-bridge` ships with this source tree. If you installed `ida-pro-mcp` from a
release that predates this feature, get this version first (e.g. clone the repo
onto your local machine). Then launch it on the **local workstation** using any
of the following.

**Option A — uv (recommended; matches the rest of the repo):**

```sh
cd ida-pro-mcp
uv run ida-pro-mcp ssh-bridge user@remote-server
```

**Option B — editable pip install (registers the `ida-pro-mcp` console script):**

```sh
cd ida-pro-mcp
pip install -e .
ida-pro-mcp ssh-bridge user@remote-server
```

**Option C — run the module directly (no install; quickest to try):**

```sh
cd ida-pro-mcp
PYTHONPATH=src python3 -m ida_pro_mcp.ssh_bridge user@remote-server
```

> Option C imports only the standard library for the bridge itself, but in
> `sse` mode it launches a local SSE server via `python -m ida_pro_mcp.server`,
> which needs the project's dependencies (`tomli_w`, `idapro`). For a smooth
> run, prefer Option A or B, which install dependencies for you.

Confirm the command before connecting with `--dry-run` (see §2.6). The bridge
must keep running for the remote agent to stay connected; `Ctrl-C` stops it
(and tears down the tunnel and local SSE server).

### 2.3 `sse` mode (recommended)

**Step 1 (local)** — start the bridge:

```sh
uv run ida-pro-mcp ssh-bridge user@remote-server
# or pick a different local SSE port: --sse-port 8744
```

It prints the URL to use on the remote, e.g.:

```
[ssh-bridge] On the remote server, configure your MCP client with URL:
[ssh-bridge]     http://127.0.0.1:8744/sse
```

**Step 2 (remote)** — register that URL with the Claude Code MCP client:

```sh
# run on the remote server
claude mcp add --transport sse ida http://127.0.0.1:8744/sse
```

The remote Claude can now call all of the local IDA tools. Keep the
`ssh-bridge` process running on the local machine.

### 2.4 `rpc` mode

**Step 1 (local)** — forward the RPC port(s):

```sh
# forward the single default port
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc
# or auto-forward every running local IDA instance
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc --all-instances
# or specify ports explicitly (repeatable)
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc --port 13337 --port 13338
```

It prints the configuration the remote should use, e.g.
`ida-pro-mcp --ida-rpc http://127.0.0.1:13337`.

**Step 2 (remote)** — install and configure:

```sh
# on the remote server: install the pure-Python package (no IDA needed)
uv tool install ida-pro-mcp   # or pip install ida-pro-mcp
# register it as a stdio MCP server in Claude Code
claude mcp add ida -- ida-pro-mcp --ida-rpc http://127.0.0.1:13337
```

### 2.5 Options reference

| Option | Description | Default |
|--------|-------------|---------|
| `target` | SSH target, e.g. `user@host` or a `~/.ssh/config` alias | required |
| `--mode {sse,rpc}` | Bridge mode | `sse` |
| `--sse-port` | Local SSE port (`sse` mode) | `8744` |
| `--port` | IDA port to forward (`rpc` mode, repeatable) | — |
| `--all-instances` | `rpc` mode: discover and forward all local IDA instances | off |
| `--ida-rpc` | `sse` mode: IDA target the local SSE server connects to | auto-discover |
| `--remote-bind` | Remote-side bind address for the tunnel | `127.0.0.1` |
| `--identity` | SSH private key file (`ssh -i`) | — |
| `--port-ssh` | Remote SSH port (`ssh -p`) | — |
| `--keepalive` | `ServerAliveInterval` seconds | `30` |
| `--dry-run` | Print the ssh command(s) that would run, then exit | off |
| `-v, --verbose` | Print ssh / local-server commands (for debugging) | off |

### 2.6 Preview what will run (without connecting)

```sh
uv run ida-pro-mcp ssh-bridge user@remote-server --dry-run
```

### 2.7 Troubleshooting

- **Remote calls fail with "Failed to complete request to IDA Pro"**: the MCP
  plugin isn't started in your local IDA, or (in `sse` mode) the local SSE
  server couldn't reach IDA. Start it via `Edit -> Plugins -> MCP`.
- **Tunnel keeps reconnecting**: check that you can `ssh user@remote-server`
  manually; run with `-v` to see the ssh error; verify your key /
  `~/.ssh/config`.
- **Remote port already in use**: change `--sse-port` (sse) or the target ports;
  with `ExitOnForwardFailure` ssh exits and reconnects if the remote port is
  taken by another process.
- **Shared remote host**: see the security notes below.

---

## 3. Security

### 3.1 Secure by default

- **All traffic is SSH-encrypted**, reusing your existing SSH authentication and
  keys.
- **Loopback-only binding**: the remote listener binds to `127.0.0.1` by default
  (`--remote-bind`), so the IDA RPC interface is **never exposed to the
  network** — only the remote host itself can reach it.
- **No inbound on the local side**: the connection is initiated outbound from
  local, so the local machine exposes no listening port to the network.

### 3.2 IDA RPC has no built-in authentication — what that means

The IDA plugin's `13337` interface performs **no identity checks**. The security
boundary therefore rests entirely on "loopback binding + SSH encryption":

- **Do not** bind the IDA plugin or the SSE server to `0.0.0.0`.
- **Use `--remote-bind 0.0.0.0` with care**: it makes the tunneled port visible
  outside the remote host and requires `GatewayPorts yes` (or `clientspecified`)
  in the remote `sshd` config. Avoid it unless you explicitly need it; the tool
  prints a warning when a non-loopback bind is detected.

### 3.3 Shared / multi-user remote hosts

Even with loopback binding, **other logged-in users** on the remote host can
reach `127.0.0.1:<port>` (loopback is visible to every user on that host). If
the remote is a shared server, be aware they could connect to your IDA.
Mitigations:

- Use a remote host / container that is yours alone;
- Pick a hard-to-guess port (only lowers the chance of accidental collisions —
  it is **not** authentication);
- Stop the bridge (`Ctrl-C`) when done; don't leave a tunnel hanging idle.

> The IDA RPC interface can perform high-privilege operations: modifying the
> database, running Python (`api_python`), controlling the debugger, etc.
> Exposing it to untrusted users is equivalent to handing over control of your
> local IDA. Only use this on remote hosts you trust.

### 3.4 Recommended practices

- Use **key-based authentication** (`--identity` or `~/.ssh/config`); avoid
  passwords.
- Choose a **single-tenant remote host you control**.
- Keep `--remote-bind 127.0.0.1` (the default).
- Stop the bridge process as soon as the task is done.
