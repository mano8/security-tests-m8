"""Unit tests for the stub AI provider the gateway suite runs against.

The stub is a real HTTP server on an ephemeral loopback port; every test
talks to it over the wire, the way the gateway under test does.
"""

from __future__ import annotations

import gzip
import json
import threading
from collections.abc import Iterator

import pytest
import requests

from security_tests_m8 import ai_stub_provider as stub

_TOKEN = "control-token-for-tests"


def _serve(control_token: str | None) -> Iterator[str]:
    server = stub.build_server(control_token=control_token)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def base() -> Iterator[str]:
    yield from _serve(_TOKEN)


@pytest.fixture
def open_base() -> Iterator[str]:
    yield from _serve(None)


def _control(base: str, method: str, action: str, payload: dict | None = None) -> dict:
    response = requests.request(
        method,
        f"{base}/__stub/{action}",
        json=payload,
        headers={stub.CONTROL_HEADER: _TOKEN},
        timeout=5,
    )
    assert response.status_code == 200
    return response.json()


def test_models_probe_and_request_log(base: str) -> None:
    response = requests.get(
        f"{base}/v1/models", headers={"Authorization": "Bearer k1"}, timeout=5
    )

    assert response.status_code == 200
    assert response.json()["data"][0]["id"] == "stub-model"
    logged = _control(base, "GET", "state")["requests"]
    assert [(entry["method"], entry["path"]) for entry in logged] == [
        ("GET", "/v1/models")
    ]
    assert logged[0]["key_fingerprint"] == stub.bearer_fingerprint("k1")
    assert "k1" not in json.dumps(logged)


def test_embeddings_follow_input_order_and_dimensions(base: str) -> None:
    _control(base, "POST", "config", {"dimensions": 3})

    answer = requests.post(
        f"{base}/v1/embeddings", json={"input": ["a", "b"]}, timeout=5
    ).json()
    single = requests.post(f"{base}/v1/embeddings", json={"input": "a"}, timeout=5)

    assert [item["index"] for item in answer["data"]] == [0, 1]
    assert all(len(item["embedding"]) == 3 for item in answer["data"])
    assert len(single.json()["data"]) == 1


def test_rerank_and_chat_answers(base: str) -> None:
    _control(base, "POST", "config", {"structured_output": {"answer": "x"}})

    rerank = requests.post(
        f"{base}/v1/rerank", json={"documents": ["a", "b", "c"]}, timeout=5
    ).json()
    chat = requests.post(f"{base}/v1/chat/completions", json={}, timeout=5).json()

    assert [hit["index"] for hit in rerank["results"]] == [0, 1, 2]
    content = chat["choices"][0]["message"]["content"]
    assert json.loads(content) == {"answer": "x"}


def test_unrecorded_request_without_credential(base: str) -> None:
    requests.post(f"{base}/v1/embeddings", data=b"not json", timeout=5)
    requests.post(f"{base}/v1/embeddings", json=["a list"], timeout=5)

    logged = _control(base, "GET", "state")["requests"]

    assert [entry["key_fingerprint"] for entry in logged] == [None, None]


def test_keys_allow_list_refuses_other_credentials(base: str) -> None:
    _control(base, "POST", "config", {"keys": ["good"]})

    good = requests.get(
        f"{base}/v1/models", headers={"Authorization": "Bearer good"}, timeout=5
    )
    bad = requests.get(
        f"{base}/v1/models", headers={"Authorization": "Bearer bad"}, timeout=5
    )
    none = requests.get(f"{base}/v1/models", timeout=5)

    assert (good.status_code, bad.status_code, none.status_code) == (200, 401, 401)
    assert len(_control(base, "GET", "state")["requests"]) == 3


def test_gzip_bomb_mode(base: str) -> None:
    _control(base, "POST", "config", {"mode": "gzip_bomb"})

    response = requests.post(f"{base}/v1/embeddings", json={}, timeout=30, stream=True)
    raw = response.raw.read(decode_content=False)

    assert response.headers["Content-Encoding"] == "gzip"
    assert len(raw) < 1024 * 1024
    assert len(gzip.decompress(raw)) == stub.GZIP_BOMB_BYTES


def test_deep_json_mode(base: str) -> None:
    _control(base, "POST", "config", {"mode": "deep_json"})

    body = requests.post(f"{base}/v1/embeddings", json={}, timeout=5).content

    assert body.count(b"{") == stub.DEEP_JSON_DEPTH


def test_status_throttle_and_delay_modes(base: str) -> None:
    _control(base, "POST", "config", {"mode": "status:503"})
    failed = requests.post(f"{base}/v1/embeddings", json={}, timeout=5)
    _control(base, "POST", "config", {"mode": "throttle:7"})
    throttled = requests.post(f"{base}/v1/embeddings", json={}, timeout=5)
    _control(base, "POST", "config", {"mode": "delay:0.01"})
    delayed = requests.post(f"{base}/v1/embeddings", json={"input": ["a"]}, timeout=5)

    assert failed.status_code == 503
    assert throttled.status_code == 429
    assert throttled.headers["Retry-After"] == "7"
    assert delayed.status_code == 200


def test_reset_restores_defaults_and_forgets_requests(base: str) -> None:
    _control(base, "POST", "config", {"mode": "deep_json", "keys": ["k"]})
    requests.get(f"{base}/v1/models", timeout=5)

    snapshot = _control(base, "POST", "reset")

    assert snapshot == {"config": stub.default_config(), "requests": []}


def test_control_needs_the_token(base: str) -> None:
    missing = requests.get(f"{base}/__stub/state", timeout=5)
    wrong = requests.get(
        f"{base}/__stub/state", headers={stub.CONTROL_HEADER: "nope"}, timeout=5
    )

    assert (missing.status_code, wrong.status_code) == (401, 401)


def test_control_open_without_a_token(open_base: str) -> None:
    response = requests.get(f"{open_base}/__stub/state", timeout=5)

    assert response.status_code == 200


def test_unknown_routes(base: str) -> None:
    provider = requests.get(f"{base}/v1/unknown", timeout=5)
    control = requests.get(
        f"{base}/__stub/other", headers={stub.CONTROL_HEADER: _TOKEN}, timeout=5
    )
    wrong_method = requests.post(f"{base}/v1/models?x=1", json={}, timeout=5)

    assert (provider.status_code, control.status_code) == (404, 404)
    assert wrong_method.status_code == 404


def test_parser_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STUB_CONTROL_TOKEN", "from-env")

    args = stub.build_parser().parse_args([])

    expected = ("0.0.0.0", 11434, "from-env")  # nosec B104 - the stub's default
    assert (args.host, args.port, args.control_token) == expected


def test_main_serves_until_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def interrupted(self: stub.StubServer) -> None:
        calls.append("serve")
        raise KeyboardInterrupt

    monkeypatch.setattr(stub.StubServer, "serve_forever", interrupted)

    code = stub.main(["--host", "127.0.0.1", "--port", "0"])

    assert code == 0
    assert calls == ["serve"]
