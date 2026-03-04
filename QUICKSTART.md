# Quick Start（本 fork：默认 compact 工具集）

本文面向“从零安装 → 打开 IDA Pro 立刻可用”，并提供用 `@modelcontextprotocol/inspector` 快速验证 compact 工具集是否生效的方法。

> 说明：这里的 **IDA** 指 Hex-Rays IDA Pro（不是 IntelliJ IDEA）。

## 0. 前置条件

- Python **3.11+**（建议用 venv 或 uv）
- IDA Pro **8.3+**（推荐 9.x），并确认能正常加载 IDAPython
- （可选）Node.js 18+：用于运行 `@modelcontextprotocol/inspector`

## 1. 从零安装（推荐开发模式：可直接改代码生效）

在你 fork 的仓库根目录执行。

### 用 uv（推荐）

```sh
# 1) 创建并同步虚拟环境（会读取 pyproject.toml / uv.lock）
uv sync

# 2) 以可编辑模式安装（你改源码会立刻影响这个 venv 里的包）
uv pip install -e .

# 3) 安装/更新 IDA 插件 + 写入 MCP client 配置（如 Claude/Cursor/VS
# 注意：使用 Python 模块方式运行，因为命令行工具可能不在 PATH 中
uv run python -m ida_pro_mcp.server --install
```

`--install` 做了两件事：

- 把 IDA 插件安装到用户目录的 `plugins/` 下：`ida_mcp.py`（loader）和 `ida_mcp/`（包目录）
- 尝试为常见 MCP client 写入配置（找不到配置文件的 client 会跳过）

Windows 默认路径是：`%APPDATA%\Hex-Rays\IDA Pro\plugins\`

macOS/Linux 默认路径是：`~/.idapro/plugins/`

> 多版本 IDA Pro：只要它们共用同一个用户目录（上面这个路径），就会共用同一套插件，所以一般没问题。

## 2. 启用 compact 工具集（默认就是 compact）

这个 fork 默认 `IDA_MCP_TOOLSET=compact`，即只暴露少量聚合工具。

如果你想显式指定（推荐在你调试工具集切换时使用），在启动 IDA 前设置环境变量：

### Windows（CMD）

```bat
set IDA_MCP_TOOLSET=compact
start "" "C:\Path\To\ida64.exe"
```

### Windows（PowerShell）

```powershell
$env:IDA_MCP_TOOLSET = "compact"
Start-Process "C:\Path\To\ida64.exe"
```

### macOS/Linux

```sh
export IDA_MCP_TOOLSET=compact
/path/to/ida64
```

如需恢复原版全量工具（full）：

```sh
IDA_MCP_TOOLSET=full
```

## 3. 在 IDA Pro 里启动 MCP Server

1) 打开任意二进制（必须先有数据库/工程）
2) 触发插件：`Edit -> Plugins -> MCP (Ctrl+Alt+M)`
3) 看到类似提示表示服务已启动：`Config: http://127.0.0.1:13337/config.html`

## 4. 用 Inspector 快速验证 compact 是否可用

### 4.1 启动 inspector

在任意终端执行：

```sh
npx -y @modelcontextprotocol/inspector
```

它会启动一个本地网页（控制台会打印 URL）。

### 4.2 连接到 IDA 的 MCP HTTP 服务

在 inspector 页面里：

- 选择连接方式：**HTTP**
- URL 填：`http://127.0.0.1:13337/mcp`

如果连接失败：

- 确认 IDA 里已经执行过插件菜单启动服务
- 打开 `http://127.0.0.1:13337/config.html`，必要时把 CORS 策略调成允许本地页面访问（否则浏览器可能拦截）

### 4.3 观察 tools/list

compact 生效时，你应该只看到 3 个工具：

- `main_flow`
- `list_user_funcs`
- `view_func`

### 4.4 实际调用验证

在 inspector 里依次 call：

- `main_flow`：参数全默认即可
- `list_user_funcs`：例如 `{"count": 50}`
- `view_func`：例如 `{"query": "main"}`（或传任意函数地址 `0x...`）

能正常返回 structured result 就说明 compact 工具集可用。

## 5. 你改完代码后，如何让 IDA 立刻用到新代码

关键取决于安装时是 **软链（symlink）** 还是 **复制（copy）** 安装：

- **软链**：通常你改完仓库代码后，重启 IDA 即可；甚至可以在 IDA 里再次触发插件启动（它会先 `unload_package("ida_mcp")` 再 import，相当于热重载）。
- **复制**：你改完代码后需要再跑一次安装命令把新代码复制到 `plugins/`，再重启 IDA。

Windows 下如果你希望尽量走软链模式，一般需要开启"开发者模式"或使用管理员权限运行安装命令。

### 重新安装命令

如果需要重新安装插件：

**使用 uv（推荐）：**
```sh
uv run python -m ida_pro_mcp.server --install
```
