# IDA Pro MCP (Compact)

> Forked from [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

## 改动思路

原仓库提供了大量原子化的 MCP 工具（如 `decompile`、`disasm`、`xrefs_to` 等），虽然功能完整，但对于 AI Agent 来说过于细碎，需要多次调用才能完成一个简单的分析任务。

本仓库的改动思路：**提供聚合能力，减少 AI 与 IDA 的交互轮次**。

默认启用 **compact** 工具集，只暴露 2 个聚合工具：

- `list_user_funcs(...)`: 列出"更像用户代码"的函数（排除库/导入/跳板，支持分页/过滤）
- `view_func(...)`: 查看函数反编译与带地址汇编

如需原始完整工具集（包含修改/内存/调试/Python 执行等），启动 IDA 前设置环境变量：

```sh
IDA_MCP_TOOLSET=full
```

## 安装与使用

请参考原仓库 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的安装说明。
