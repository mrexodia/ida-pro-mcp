import cgi
import html
import json
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar

from .sync import idaread, idawrite
from .rpc import McpRpcRegistry, McpHttpRequestHandler, MCP_SERVER, MCP_UNSAFE


T = TypeVar("T")


@idaread
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idawrite
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        if urlparse(self.path).path == "/config.html":
            self._handle_config_get()
        else:
            super().do_GET()

    def _send_html(self, status: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="submit"] {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover {
  opacity: 0.9;
}
  </style>
</head>
<body>
<h1>Enabled Tools</h1>
<form method="post" action="/config">
"""
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe = "⚠️ " if name in MCP_UNSAFE else ""
            checked = (
                "checked" if name in self.mcp_server.tools.methods else ""
            )  # Preserve state
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}' {checked}>{unsafe}{html.escape(name)}: {html.escape(description)}</label>"
        body += "<br><input type='submit' value='Save'></form>"
        body += "</body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Parse the form data
        ctype, pdict = cgi.parse_header(self.headers.get("content-type", ""))
        if ctype == "multipart/form-data":
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == "application/x-www-form-urlencoded":
            length = int(self.headers.get("content-length", "0"))
            postvars = parse_qs(self.rfile.read(length).decode("utf-8"))
        else:
            postvars = {}  # Handle other content types if needed

        # Update the server's tools
        enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Redirect back to the config page
        self.send_response(302)  # 302 Found is a common redirect status
        self.send_header("Location", "/config.html")
        self.end_headers()
