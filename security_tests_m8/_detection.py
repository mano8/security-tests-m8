"""Live stack detection helpers."""

from __future__ import annotations

from dataclasses import dataclass

import requests

from security_tests_m8._config import get_config

_DETECT_TIMEOUT = 5
DEFAULT_STATEFUL_MODE = "stateful"


@dataclass(frozen=True)
class StackInfo:
    """Detected live-stack security properties."""

    reachable: bool = False
    algorithm: str = "HS256"
    token_mode: str = DEFAULT_STATEFUL_MODE
    has_jwks: bool = False
    redis_ok: bool = True

    def get(self, key: str, default: object = None) -> object:
        """Dictionary-compatible accessor for ported pytest suites."""
        return getattr(self, key, default)


def detect_stack() -> StackInfo:
    """Probe health and JWKS endpoints to detect the running stack."""
    config = get_config()
    try:
        response = requests.get(
            f"{config.auth_base_url}/health/", timeout=_DETECT_TIMEOUT
        )
        response.raise_for_status()
    except requests.RequestException:
        return StackInfo()

    token_mode = DEFAULT_STATEFUL_MODE
    redis_ok = True
    try:
        body = response.json()
        if "token_mode" in body:
            token_mode = str(body["token_mode"])
        if "redis" in body:
            redis_ok = body["redis"] == "ok"
    except (KeyError, ValueError, TypeError):
        pass

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
    )
