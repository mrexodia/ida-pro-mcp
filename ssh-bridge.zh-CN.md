# ssh-bridge：从远程 Agent 使用本地 IDA Pro

`ida-pro-mcp ssh-bridge` 让运行在**远程 SSH 服务器**上的 MCP 客户端（Claude Code 等）
访问运行在**本地工作站**上的 IDA Pro。

本文分三部分：[原理](#一原理) · [使用方法](#二使用方法) · [安全](#三安全)。

---

## 一、原理

### 1.1 问题

`ida-pro-mcp` 有两个相互独立的组件：

| 组件 | 作用 | 通常运行在 |
|------|------|-----------|
| **IDA 插件**（`ida_mcp`） | 在 IDA 进程内监听 `127.0.0.1:13337`，提供 JSON-RPC 接口 | 本地（装进本地 IDA） |
| **MCP server**（`server.py`） | 纯 Python 的代理：对上讲 MCP，对下把请求 HTTP 转发到 `13337` | 任意（**不依赖 IDA**） |

典型远程开发场景下，IDA 在本地，AI Agent 在远程服务器。Agent 侧的 MCP server
去连 `127.0.0.1:13337`，连到的却是**远程服务器自己**，而 IDA 插件监听的是**本地**
的回环地址——链路在网络层断开。

```
本地工作站                              远程服务器
┌──────────────────┐                   ┌──────────────────────┐
│ IDA + 插件        │                   │ Claude Code (Agent)  │
│ 127.0.0.1:13337  │   ✗ 够不到 ✗      │   └─ MCP server      │
└──────────────────┘                   │      连 127.0.0.1 →  │
                                        │      连到的是自己     │
                                        └──────────────────────┘
```

### 1.2 解法：SSH 反向隧道

两者之间本质是「连接到某个 host:port 的 HTTP 通信」。`ssh-bridge` 在**本地**发起一条
到远程的 SSH 连接，并建立**反向端口转发**（`ssh -R`），把远程某个回环端口的流量经
加密隧道送回本地。

```
本地工作站                                   远程服务器
┌──────────────────┐                        ┌──────────────────────────┐
│ IDA + 插件        │◀── 隧道把流量送回本地 ──│ 127.0.0.1:<port> (监听)   │
│ 127.0.0.1:13337  │                         │        ▲                  │
└────────▲─────────┘                         │        │ 连本地回环即可    │
         │   ssh-bridge 发起出站 SSH ───────▶ sshd    │                  │
         └────────────────────────────────────────── Claude Code (Agent) │
                                              └──────────────────────────┘
```

**关键点：连接方向。** SSH 由本地**主动向外发起**（和你平时登录服务器的方向一致）。
因此：

- **本地在内网 / NAT 后也能用**——只要本地能 SSH 出站到服务器即可，不要求服务器能反连本地。
- 唯一前提是**远程服务器开放了 `sshd`**。

### 1.3 两种模式

#### `sse` 模式（默认，远程零安装）

`ssh-bridge` 在**本地**额外拉起一个 SSE 形态的 MCP server（它在本机直连 IDA 的
`13337`，不跨网络），然后只把这个 SSE 端口（默认 `8744`）反向转发到远程。远程的
Claude Code 把 MCP server 配成隧道里的 URL（如 `http://127.0.0.1:8744/sse`）即可。

**远程服务器上不需要安装任何东西**，只是通过隧道用 HTTP/SSE 跟本地对话。

```
本地: IDA(13337) ←本机直连← 本地SSE server(8744) ←反向转发8744→ 远程: Claude Code 连 8744
```

#### `rpc` 模式（远程运行 `ida-pro-mcp`）

直接把 IDA 的 RPC 端口（`13337` 等）反向转发到远程。远程需要安装 `ida-pro-mcp`
（纯 Python，**不需要 IDA**），由 Claude Code 以 stdio 拉起，并用
`--ida-rpc http://127.0.0.1:13337` 指向隧道端口。支持 `--all-instances` 一次转发本机
所有运行中的 IDA 实例。

### 1.4 健壮性

`ssh-bridge` 给底层 ssh 加了 `ServerAliveInterval`（保活心跳）、
`ExitOnForwardFailure=yes`（转发建立失败立即退出）和 `ConnectTimeout`；连接断开后
按指数退避**自动重连**，连接稳定超过 30s 则重置退避。`Ctrl-C` 会一并关闭隧道与本地
SSE server。

---

## 二、使用方法

### 2.1 前置条件

- **本地**：已安装 IDA Pro 与 `ida-pro-mcp` 插件，并在 IDA 中启动了 MCP 插件
  （`Edit -> Plugins -> MCP`，快捷键 `Ctrl+Alt+M` / mac `Ctrl+Option+M`）。
- **本地**：可用的 `ssh` 客户端，且能 SSH 登录到远程服务器（密钥认证最佳）。
- **远程**：开放 `sshd`。`sse` 模式下远程无需其它依赖；`rpc` 模式需要远程能
  `pip/uv install ida-pro-mcp`。

> `ssh-bridge` 一律在**本地工作站**（IDA 所在机器）运行。

### 2.2 获取与启动

`ssh-bridge` 随这份源码一起发布。如果你装的是早于该功能的发布版 `ida-pro-mcp`，
需先获取这份代码（例如把仓库 clone 到本地机器）。然后在**本地工作站**用下列任一方式启动。

**方式 A — uv（推荐，仓库本来就这么用）：**

```sh
cd ida-pro-mcp
uv run ida-pro-mcp ssh-bridge user@remote-server
```

**方式 B — pip 可编辑安装（注册 `ida-pro-mcp` 控制台命令）：**

```sh
cd ida-pro-mcp
pip install -e .
ida-pro-mcp ssh-bridge user@remote-server
```

**方式 C — 直接运行模块（免安装，最快验证）：**

```sh
cd ida-pro-mcp
PYTHONPATH=src python3 -m ida_pro_mcp.ssh_bridge user@remote-server
```

> 方式 C 的桥接本体只依赖标准库，但 `sse` 模式下它会通过 `python -m ida_pro_mcp.server`
> 拉起本地 SSE server，而后者需要项目依赖（`tomli_w`、`idapro`）。为顺利运行，建议用
> 方式 A 或 B，它们会替你装好依赖。

正式连接前可用 `--dry-run` 确认命令（见 §2.6）。桥接进程必须保持运行，远程 Agent 才能持续
连通；`Ctrl-C` 会停止它（并关闭隧道与本地 SSE server）。

### 2.3 `sse` 模式（推荐）

**第 1 步（本地）** 启动桥接：

```sh
uv run ida-pro-mcp ssh-bridge user@remote-server
# 或自定义本地 SSE 端口：--sse-port 8744
```

命令会打印出供远程使用的 URL，例如：

```
[ssh-bridge] On the remote server, configure your MCP client with URL:
[ssh-bridge]     http://127.0.0.1:8744/sse
```

**第 2 步（远程）** 把该 URL 配进 Claude Code 的 MCP 客户端：

```sh
# 在远程服务器上执行
claude mcp add --transport sse ida http://127.0.0.1:8744/sse
```

完成后，远程的 Claude 即可调用本地 IDA 的全部工具。保持 `ssh-bridge` 进程在本地运行。

### 2.4 `rpc` 模式

**第 1 步（本地）** 转发 RPC 端口：

```sh
# 转发单个默认端口
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc
# 或自动转发本机所有运行中的 IDA 实例
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc --all-instances
# 或显式指定端口（可重复）
uv run ida-pro-mcp ssh-bridge user@remote-server --mode rpc --port 13337 --port 13338
```

命令会打印远程应使用的配置，例如 `ida-pro-mcp --ida-rpc http://127.0.0.1:13337`。

**第 2 步（远程）** 安装并配置：

```sh
# 在远程服务器上：安装纯 Python 包（不需要 IDA）
uv tool install ida-pro-mcp   # 或 pip install ida-pro-mcp
# 把它作为 stdio MCP server 配进 Claude Code
claude mcp add ida -- ida-pro-mcp --ida-rpc http://127.0.0.1:13337
```

### 2.5 参数速查

| 参数 | 说明 | 默认 |
|------|------|------|
| `target` | SSH 目标，如 `user@host` 或 `~/.ssh/config` 中的别名 | 必填 |
| `--mode {sse,rpc}` | 桥接模式 | `sse` |
| `--sse-port` | `sse` 模式本地 SSE 端口 | `8744` |
| `--port` | `rpc` 模式要转发的 IDA 端口（可重复） | — |
| `--all-instances` | `rpc` 模式：发现并转发本机所有 IDA 实例 | 关 |
| `--ida-rpc` | `sse` 模式：本地 SSE server 连接的 IDA 目标 | 自动发现 |
| `--remote-bind` | 远程侧隧道绑定地址 | `127.0.0.1` |
| `--identity` | SSH 私钥文件（`ssh -i`） | — |
| `--port-ssh` | 远程 SSH 端口（`ssh -p`） | — |
| `--keepalive` | `ServerAliveInterval` 秒 | `30` |
| `--dry-run` | 只打印将执行的 ssh 命令并退出 | 关 |
| `-v, --verbose` | 打印 ssh/本地 server 命令，便于排障 | 关 |

### 2.6 先看看会执行什么（不实际连接）

```sh
uv run ida-pro-mcp ssh-bridge user@remote-server --dry-run
```

### 2.7 故障排查

- **远程调用报「Failed to complete request to IDA Pro」**：本地 IDA 里没启动 MCP 插件，
  或 `sse` 模式下本地 SSE server 没连上 IDA。先在 IDA 里 `Edit -> Plugins -> MCP`。
- **隧道反复重连**：检查能否手动 `ssh user@remote-server` 登录；用 `-v` 看 ssh 报错；
  确认密钥/`~/.ssh/config` 正确。
- **远程端口被占用**：换 `--sse-port`（sse）或目标端口；注意远程同一端口若被别的进程占用，
  `ExitOnForwardFailure` 会让 ssh 退出后重连。
- **多用户共享远程主机**：见下方安全说明。

---

## 三、安全

### 3.1 默认即安全

- **全程 SSH 加密**：隧道流量走 SSH，复用你已有的 SSH 认证与密钥体系。
- **仅绑回环**：远程监听默认绑 `127.0.0.1`（`--remote-bind` 默认值），IDA 的 RPC 接口
  **不会暴露到网络**，只有该远程主机本机可达。
- **本地无需开放入站**：连接由本地出站发起，本地不暴露任何监听端口给公网。

### 3.2 IDA RPC 没有内建鉴权——这意味着什么

IDA 插件的 `13337` 接口本身**不做身份校验**。因此安全边界完全依赖「绑定回环 + SSH 加密」：

- **不要**把 IDA 插件或 SSE server 绑到 `0.0.0.0`。
- **谨慎使用 `--remote-bind 0.0.0.0`**：它会让隧道端口对远程主机外部可见，且需要远程
  `sshd` 配置 `GatewayPorts yes`（或 `clientspecified`）。除非你明确需要，否则不要这么做；
  本工具在检测到非回环绑定时会打印警告。

### 3.3 多用户共享的远程主机

即使绑回环，远程主机上的**其他登录用户**也能访问 `127.0.0.1:<port>`（回环对该主机所有用户可见）。
如果远程是多人共享的服务器，应意识到他们也能连到你的 IDA。缓解措施：

- 用你独占的远程主机 / 容器；
- 选用不易被猜到的端口（仅为降低被无意撞上的概率，**不是**真正的鉴权）；
- 用完即停（`Ctrl-C` 结束 `ssh-bridge`），不要长期空挂隧道。

> IDA RPC 可执行修改、运行 Python（`api_python`）、控制调试器等高权限操作。把它暴露给
> 不可信用户等同于把本地 IDA 的控制权交出去。务必只在可信的远程主机上使用。

### 3.4 推荐实践

- 使用**密钥认证**（`--identity` 或 `~/.ssh/config`），避免口令。
- 远程主机选择**自己可控、单租户**的环境。
- 保持 `--remote-bind 127.0.0.1`（默认）。
- 任务结束及时停止桥接进程。
