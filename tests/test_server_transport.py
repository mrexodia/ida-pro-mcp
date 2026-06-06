import json
import unittest
from unittest.mock import patch

from ida_pro_mcp import server


class _FakeResponse:
    def __init__(self, status=200, reason="OK", body=b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'):
        self.status = status
        self.reason = reason
        self._body = body

    def read(self):
        return self._body


class _BaseFakeConnection:
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_calls = 0
        self.closed = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.request_calls += 1

    def close(self):
        self.closed = True


class _ResponseFailureConnection(_BaseFakeConnection):
    def getresponse(self):
        raise TimeoutError("read timeout")


class _Http503Connection(_BaseFakeConnection):
    def getresponse(self):
        return _FakeResponse(status=503, reason="Service Unavailable", body=b"busy")


class _ConnectFailureConnection(_BaseFakeConnection):
    def request(self, method, path, body, headers):
        super().request(method, path, body, headers)
        raise ConnectionRefusedError("refused")


class DispatchProxyTransportTests(unittest.TestCase):
    def setUp(self):
        _ResponseFailureConnection.reset()
        _Http503Connection.reset()
        _ConnectFailureConnection.reset()
        self._old_host = server.IDA_HOST
        self._old_port = server.IDA_PORT
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337

    def tearDown(self):
        server.IDA_HOST = self._old_host
        server.IDA_PORT = self._old_port

    def test_proxy_request_forwards_external_base_header(self):
        original_getter = server.get_current_request_external_base_url

        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.path = path
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.get_current_request_external_base_url = lambda: "https://mcp.example.com/base"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_ida(b"{}")
        finally:
            server.get_current_request_external_base_url = original_getter

        self.assertEqual(len(_RecordingConnection.instances), 1)
        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("X-IDA-MCP-External-Base"),
            "https://mcp.example.com/base",
        )

    def test_proxy_to_ida_targets_module_default(self):
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.IDA_HOST = "10.0.0.50"
        server.IDA_PORT = 24680
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
            server._proxy_to_ida(b"{}")
        self.assertEqual(
            (_RecordingConnection.instances[0].host, _RecordingConnection.instances[0].port),
            ("10.0.0.50", 24680),
        )

    def test_dispatch_proxy_does_not_retry_post_send_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ResponseFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("not retried automatically", response["error"]["message"])
        self.assertIn("read timeout", response["error"]["data"])
        self.assertEqual(len(_ResponseFailureConnection.instances), 1)
        self.assertEqual(_ResponseFailureConnection.instances[0].request_calls, 1)
        self.assertTrue(_ResponseFailureConnection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_http_503(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _Http503Connection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("HTTP 503 Service Unavailable", response["error"]["data"])
        self.assertEqual(len(_Http503Connection.instances), 1)
        self.assertEqual(_Http503Connection.instances[0].request_calls, 1)
        self.assertTrue(_Http503Connection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_connection_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ConnectFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("refused", response["error"]["data"])
        self.assertEqual(len(_ConnectFailureConnection.instances), 1)
        self.assertEqual(_ConnectFailureConnection.instances[0].request_calls, 1)


if __name__ == "__main__":
    unittest.main()
