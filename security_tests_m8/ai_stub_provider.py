"""Stub AI provider for the gateway live suite.

A minimal OpenAI-compatible provider that the AI gateway under test calls,
and that the suite observes and steers. It serves:

* ``GET /v1/models`` — the credential probe;
* ``POST /v1/embeddings``, ``POST /v1/rerank`` and
  ``POST /v1/chat/completions`` — the three non-OCR capabilities.

Every provider request is recorded with a fingerprint of the credential it
carried (the first 16 hex characters of the SHA-256 of the
``Authorization`` value), never the value itself, so a test can prove which
key reached the provider, or that none did.

The control API lives under ``/__stub/`` and needs the ``X-Stub-Control``
header when ``--control-token`` (or ``STUB_CONTROL_TOKEN``) is set:

* ``GET /__stub/state`` — the configuration and every recorded request;
* ``POST /__stub/config`` — merge a JSON object into the configuration;
* ``POST /__stub/reset`` — forget the requests, restore the defaults.

Configuration keys:

* ``keys`` — the accepted bearer keys; empty accepts any key (and none);
* ``mode`` — the answer to every provider request: ``ok``, ``gzip_bomb``
  (a small gzip body that inflates past any sane response cap),
  ``deep_json`` (nesting far past any sane parser depth), ``status:<code>``,
  ``throttle:<seconds>`` (``429`` with that ``Retry-After``) or
  ``delay:<seconds>`` (then ``ok``);
* ``dimensions`` — the length of each embedding vector;
* ``structured_output`` — the JSON object a chat completion returns.

The module imports nothing outside the standard library, so it runs from any
Python 3.12+ image on the network the gateway reaches its local providers
through, e.g. piped to the gateway's own image::

    docker run -d --name ai-stub --network <stack>_ai_net \\
        --network-alias ollama --entrypoint python ai-gateway-m8:stack \\
        -c "$(cat security_tests_m8/ai_stub_provider.py)" --port 11434

The stub is test tooling: it holds no secret and must never be reachable
from outside the stack under test.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

CONTROL_HEADER = "X-Stub-Control"
CONTROL_PREFIX = "/__stub/"
FINGERPRINT_LENGTH = 16

#: Decoded size of the ``gzip_bomb`` answer: far past any response cap.
GZIP_BOMB_BYTES = 64 * 1024 * 1024
#: Nesting depth of the ``deep_json`` answer: far past any parser cap.
DEEP_JSON_DEPTH = 256

_PROVIDER_ROUTES = frozenset(
    {
        ("GET", "/v1/models"),
        ("POST", "/v1/embeddings"),
        ("POST", "/v1/rerank"),
        ("POST", "/v1/chat/completions"),
    }
)


def default_config() -> dict[str, Any]:
    """Return the configuration a reset restores."""
    return {
        "keys": [],
        "mode": "ok",
        "dimensions": 8,
        "structured_output": {"answer": "stub"},
    }


def fingerprint(value: str) -> str:
    """Return the recorded fingerprint of a credential header value."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:FINGERPRINT_LENGTH]


def bearer_fingerprint(key: str) -> str:
    """Return the fingerprint a request carrying ``Bearer <key>`` records."""
    return fingerprint(f"Bearer {key}")


class StubState:
    """The stub's configuration and request log, shared by every handler."""

    def __init__(self, control_token: str | None = None) -> None:
        self.control_token = control_token or None
        self._lock = threading.Lock()
        self._config = default_config()
        self._requests: list[dict[str, Any]] = []

    def config(self) -> dict[str, Any]:
        """Return a copy of the current configuration."""
        with self._lock:
            return json.loads(json.dumps(self._config))

    def update(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Merge ``changes`` into the configuration and return the result."""
        with self._lock:
            self._config.update(changes)
        return self.config()

    def reset(self) -> None:
        """Forget every request and restore the default configuration."""
        with self._lock:
            self._config = default_config()
            self._requests = []

    def record(self, entry: dict[str, Any]) -> None:
        """Append one provider request to the log."""
        with self._lock:
            self._requests.append(entry)

    def snapshot(self) -> dict[str, Any]:
        """Return the configuration and every recorded request."""
        with self._lock:
            requests = list(self._requests)
        return {"config": self.config(), "requests": requests}


def _embeddings(body: dict[str, Any], dimensions: int) -> dict[str, Any]:
    inputs = body.get("input") or []
    if isinstance(inputs, str):
        inputs = [inputs]
    data = [
        {
            "object": "embedding",
            "index": index,
            "embedding": [round(0.01 * (index + 1), 4)] * dimensions,
        }
        for index in range(len(inputs))
    ]
    return {"object": "list", "data": data, "usage": {"prompt_tokens": len(inputs)}}


def _rerank(body: dict[str, Any]) -> dict[str, Any]:
    documents = body.get("documents") or []
    results = [
        {"index": index, "relevance_score": round(1.0 / (index + 1), 4)}
        for index in range(len(documents))
    ]
    return {"results": results, "usage": {"prompt_tokens": len(documents)}}


def _chat(output: dict[str, Any]) -> dict[str, Any]:
    message = {"role": "assistant", "content": json.dumps(output)}
    return {
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


def provider_answer(
    method: str, path: str, body: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    """Return the ``ok`` answer of one provider route."""
    if (method, path) == ("GET", "/v1/models"):
        return {"object": "list", "data": [{"id": "stub-model", "object": "model"}]}
    if path == "/v1/embeddings":
        return _embeddings(body, int(config["dimensions"]))
    if path == "/v1/rerank":
        return _rerank(body)
    return _chat(dict(config["structured_output"]))


def gzip_bomb() -> bytes:
    """Return a gzip body that inflates to :data:`GZIP_BOMB_BYTES` zero bytes."""
    return gzip.compress(b"\0" * GZIP_BOMB_BYTES, compresslevel=9)


def deep_json() -> bytes:
    """Return a JSON document nested :data:`DEEP_JSON_DEPTH` levels deep."""
    return (b'{"a":' * DEEP_JSON_DEPTH) + b"1" + (b"}" * DEEP_JSON_DEPTH)


class StubHandler(BaseHTTPRequestHandler):
    """Serve the provider routes and the control API."""

    server: StubServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        """Keep the stub silent: request lines could echo test material."""

    def do_GET(self) -> None:
        """Dispatch a GET."""
        self._dispatch("GET")

    def do_POST(self) -> None:
        """Dispatch a POST."""
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        body = self._read_body()
        path = self.path.split("?", 1)[0]
        if path.startswith(CONTROL_PREFIX):
            self._control(method, path, body)
            return
        if (method, path) not in _PROVIDER_ROUTES:
            self._json(HTTPStatus.NOT_FOUND, {"error": "no such route"})
            return
        self._provider(method, path, body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _control(self, method: str, path: str, raw: bytes) -> None:
        state = self.server.state
        token = state.control_token
        presented = self.headers.get(CONTROL_HEADER) or ""
        if token is not None and not hmac.compare_digest(presented, token):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "control token required"})
            return
        action = path[len(CONTROL_PREFIX) :]
        if (method, action) == ("GET", "state"):
            self._json(HTTPStatus.OK, state.snapshot())
        elif (method, action) == ("POST", "config"):
            self._json(HTTPStatus.OK, state.update(_json_object(raw)))
        elif (method, action) == ("POST", "reset"):
            state.reset()
            self._json(HTTPStatus.OK, state.snapshot())
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "no such control route"})

    def _provider(self, method: str, path: str, raw: bytes) -> None:
        state = self.server.state
        config = state.config()
        authorization = self.headers.get("Authorization")
        state.record(
            {
                "method": method,
                "path": path,
                "key_fingerprint": fingerprint(authorization)
                if authorization
                else None,
                "body_bytes": len(raw),
                "at": time.time(),
            }
        )
        keys = [str(key) for key in config["keys"]]
        if keys and authorization not in {f"Bearer {key}" for key in keys}:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid api key"})
            return
        self._answer(str(config["mode"]), method, path, _json_object(raw), config)

    def _answer(
        self,
        mode: str,
        method: str,
        path: str,
        body: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        if mode == "gzip_bomb":
            self._send(HTTPStatus.OK, gzip_bomb(), content_encoding="gzip")
        elif mode == "deep_json":
            self._send(HTTPStatus.OK, deep_json())
        elif mode.startswith("status:"):
            self._json(int(mode.split(":", 1)[1]), {"error": "stub status"})
        elif mode.startswith("throttle:"):
            retry_after = {"Retry-After": mode.split(":", 1)[1]}
            payload = json.dumps({"error": "rate limited"}).encode("utf-8")
            self._send(HTTPStatus.TOO_MANY_REQUESTS, payload, headers=retry_after)
        else:
            if mode.startswith("delay:"):
                time.sleep(float(mode.split(":", 1)[1]))
            self._json(HTTPStatus.OK, provider_answer(method, path, body, config))

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"))

    def _send(
        self,
        status: int,
        data: bytes,
        *,
        content_encoding: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if content_encoding is not None:
            self.send_header("Content-Encoding", content_encoding)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _json_object(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except ValueError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


class StubServer(ThreadingHTTPServer):
    """A threading HTTP server carrying the shared :class:`StubState`."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: StubState) -> None:
        super().__init__(address, StubHandler)
        self.state = state


def build_server(
    host: str = "127.0.0.1", port: int = 0, control_token: str | None = None
) -> StubServer:
    """Return a bound, not yet serving, stub server."""
    return StubServer((host, port), StubState(control_token))


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(description="Stub AI provider (live suite).")
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104 - a container port
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument(
        "--control-token",
        default=os.environ.get("STUB_CONTROL_TOKEN"),
        help="Required X-Stub-Control value. Default: STUB_CONTROL_TOKEN.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Serve until interrupted."""
    args = build_parser().parse_args(argv)
    server = build_server(args.host, args.port, args.control_token)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
