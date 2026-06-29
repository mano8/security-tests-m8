"""Live stack detection helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import requests

from security_tests_m8._config import get_config

_DETECT_TIMEOUT = 5
DEFAULT_STATEFUL_MODE = "stateful"


def _read_env_value(path: Path, name: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{name}="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1].strip().strip("'\"")
    return None


def _configured_token_mode() -> str | None:
    env_value = os.getenv("LIVE_TEST_TOKEN_MODE")
    if env_value:
        return env_value.lower()
    deployment_root = get_config().deployment_root
    if deployment_root is None:
        return None
    token_mode = _read_env_value(deployment_root / "auth.env", "TOKEN_MODE")
    return token_mode.lower() if token_mode else None


@dataclass(frozen=True)
class StackInfo:
    """Detected live-stack security properties."""

    reachable: bool = False
    algorithm: str = "HS256"
    token_mode: str = DEFAULT_STATEFUL_MODE
    has_jwks: bool = False
    redis_ok: bool = True
    detail_available: bool = False
    token_mode_known: bool = False

    def get(self, key: str, default: object = None) -> object:
        """Dictionary-compatible accessor for ported pytest suites."""
        return getattr(self, key, default)


def _get_health_response() -> requests.Response | None:
    config = get_config()
    url = config.auth_health_url or f"{config.auth_base_url}/health"
    try:
        response = requests.get(
            url, headers=config.health_detail_headers(), timeout=_DETECT_TIMEOUT
        )
    except requests.RequestException:
        return None
    if response.status_code == 200:
        return response
    return None


def _is_reachable_via_meta(auth_base_url: str) -> bool:
    try:
        response = requests.get(f"{auth_base_url}/meta", timeout=_DETECT_TIMEOUT)
    except requests.RequestException:
        return False
    return response.status_code == 200


def _token_mode_from_health(
    response: requests.Response | None,
) -> tuple[str, bool, bool]:
    """Return (token_mode, redis_ok, detail_available)."""
    token_mode = _configured_token_mode() or DEFAULT_STATEFUL_MODE
    redis_ok = True
    detail_available = False
    if response is None:
        return token_mode, redis_ok, detail_available
    try:
        body = response.json()
        if "token_mode" in body or "redis" in body:
            detail_available = True
        if "token_mode" in body:
            token_mode = str(body["token_mode"])
        if "redis" in body:
            redis_ok = body["redis"] == "ok"
    except (KeyError, ValueError, TypeError):
        pass
    return token_mode, redis_ok, detail_available


def detect_stack() -> StackInfo:
    """Probe health/meta/JWKS endpoints to detect the running stack."""
    config = get_config()
    health_response = _get_health_response()
    if health_response is None and not _is_reachable_via_meta(config.auth_base_url):
        return StackInfo()

    token_mode, redis_ok, detail_available = _token_mode_from_health(health_response)
    token_mode_known = detail_available or _configured_token_mode() is not None
    algorithm = "HS256"
    has_jwks = False
    try:
        jwks = requests.get(
            f"{config.auth_base_url}/.well-known/jwks.json",
            timeout=_DETECT_TIMEOUT,
        )
        if jwks.status_code == 200:
            keys = jwks.json().get("keys", [])
            if keys:
                algorithm = str(keys[0].get("alg", "RS256"))
                has_jwks = True
    except (KeyError, ValueError, TypeError, requests.RequestException):
        pass

    return StackInfo(
        reachable=True,
        algorithm=algorithm,
        token_mode=token_mode,
        has_jwks=has_jwks,
        redis_ok=redis_ok,
        detail_available=detail_available,
        token_mode_known=token_mode_known,
    )
