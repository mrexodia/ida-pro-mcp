import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from ida_pro_mcp import server


class StubHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        resp = {"jsonrpc": "2.0", "id": body.get("id")}
        if body["method"] == "get_metadata":
            resp["result"] = {"module": "test.exe"}
        else:
            resp["result"] = "ok"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


def run_server(server):
    with server:
        server.serve_forever()


def test_check_connection(tmp_path):
    httpd = HTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=run_server, args=(httpd,), daemon=True)
    thread.start()
    server.ida_host = "127.0.0.1"
    server.ida_port = httpd.server_port
    try:
        result = server.check_connection()
        assert "Successfully connected" in result
        assert "test.exe" in result
    finally:
        httpd.shutdown()
        thread.join()
