from urllib.parse import urlparse

from .rpc import McpHttpRequestHandler

class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        def send_html(status: int, text: str):
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        match urlparse(self.path).path:
            case "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            case "/config.html":
                send_html(200, "<html><body><h1>MCP Configuration Page</h1></body></html>")
            case _:
                return super().do_GET()
