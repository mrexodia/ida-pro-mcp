import json
import os
from typing import Any, Optional
from .zeromcp import McpRpcRegistry, McpServer, McpToolError, McpHttpRequestHandler

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)

# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT_MAX_CHARS = 50000
OUTPUT_CACHE_MAX_SIZE = 100
_output_cache: dict[str, Any] = {}
_download_base_url: str = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:13337")


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return _download_base_url


def _generate_output_id() -> str:
    import uuid
    return str(uuid.uuid4())


OUTPUT_LIMIT_PREVIEW_ITEMS = 10
OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000


def _truncate_value(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return value

    if isinstance(value, str) and len(value) > OUTPUT_LIMIT_PREVIEW_STR_LEN:
        return value[:OUTPUT_LIMIT_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"

    if isinstance(value, list):
        truncated_list = [
            _truncate_value(item, depth + 1)
            for item in value[:OUTPUT_LIMIT_PREVIEW_ITEMS]
        ]
        if len(value) > OUTPUT_LIMIT_PREVIEW_ITEMS:
            truncated_list.append(
                {"_truncated": f"... and {len(value) - OUTPUT_LIMIT_PREVIEW_ITEMS} more items"}
            )
        return truncated_list

    if isinstance(value, dict):
        return {k: _truncate_value(v, depth + 1) for k, v in value.items()}

    return value


def _add_download_info(result: Any, output_id: str, total_chars: int) -> Any:
    download_url = f"{_download_base_url}/output/{output_id}.json"
    info = {
        "_output_truncated": True,
        "_total_chars": total_chars,
        "_output_id": output_id,
        "_download_url": download_url,
        "_download_hint": f"Output truncated. Run: curl -o .ida-mcp/{output_id}.json {download_url}",
    }

    if isinstance(result, dict):
        return {**result, **info}

    if isinstance(result, list) and result:
        result = list(result)
        if isinstance(result[0], dict):
            result[0] = {**result[0], **info}
        else:
            result.insert(0, info)
        return result

    return {"_preview": result, **info}


def get_cached_output(output_id: str) -> Optional[Any]:
    return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
        oldest_key = next(iter(_output_cache))
        del _output_cache[oldest_key]
    _output_cache[output_id] = data


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        response = original(name, arguments, _meta)

        if response.get("isError"):
            return response

        structured = response.get("structuredContent")
        if structured is None:
            return response

        serialized = json.dumps(structured)
        if len(serialized) <= OUTPUT_LIMIT_MAX_CHARS:
            return response

        output_id = _generate_output_id()
        _cache_output(output_id, structured)

        preview = _truncate_value(structured)
        preview = _add_download_info(preview, output_id, len(serialized))

        return {
            "structuredContent": preview,
            "content": response.get("content", []),
            "isError": False,
        }

    MCP_SERVER.registry.methods["tools/call"] = patched


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
   return MCP_SERVER.tool(func)


def resource(uri):
   return MCP_SERVER.resource(uri)


def unsafe(func):
   MCP_UNSAFE.add(func.__name__)
   return func


def ext(group: str):
   """Mark a tool as belonging to an extension group.

   Tools in extension groups are hidden by default. Enable via ?ext=group query param.
   Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
   """
   def decorator(func):
      if group not in MCP_EXTENSIONS:
         MCP_EXTENSIONS[group] = set()
      MCP_EXTENSIONS[group].add(func.__name__)
      return func
   return decorator


__all__ = [
   "McpRpcRegistry",
   "McpServer",
   "McpToolError",
   "McpHttpRequestHandler",
   "MCP_SERVER",
   "MCP_UNSAFE",
   "MCP_EXTENSIONS",
   "tool",
   "unsafe",
   "ext",
   "resource",
   "get_cached_output",
   "set_download_base_url",
   "get_download_base_url",
]
