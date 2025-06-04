from __future__ import annotations

import json
import http.client
from pathlib import Path
from urllib.parse import urlparse

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


class LocalLLM:
    """Simple client for an OpenAI compatible local LLM server."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            config_path = Path(__file__).with_name("config.example.toml")
        if isinstance(config_path, str):
            config_path = Path(config_path)
        with open(config_path, "rb") as f:
            cfg = tomllib.load(f)
        self.model: str = cfg.get("model", "")
        self.api_base: str = cfg.get("api_base", "http://localhost:11434")
        self.prompt_file: str | None = cfg.get("prompt_file")
        if self.prompt_file is not None:
            self.prompt_file = str(Path(config_path).parent / self.prompt_file)

    def _make_request(self, payload: dict, stream: bool):
        url = urlparse(self.api_base)
        path = url.path.rstrip("/") + "/v1/chat/completions"
        conn = http.client.HTTPConnection(url.hostname, url.port)
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            err = resp.read()
            raise RuntimeError(f"LLM error {resp.status}: {err.decode()}")
        return resp

    def chat(self, messages: list[dict[str, str]], *, stream: bool = False):
        payload = {"model": self.model, "messages": messages, "stream": stream}
        resp = self._make_request(payload, stream)
        if stream:
            buffer = ""
            while True:
                line = resp.readline()
                if not line:
                    break
                if line.startswith(b"data: "):
                    line = line[len(b"data: ") :]
                line = line.strip()
                if not line or line == b"[DONE]":
                    continue
                data = json.loads(line.decode())
                delta = data["choices"][0].get("delta", {}).get("content")
                if delta:
                    yield delta
        else:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
