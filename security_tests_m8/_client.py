"""Synchronous HTTP helpers for live security tests."""

from __future__ import annotations

import requests

from security_tests_m8._config import get_config


class ConfigUrl:
    """String-like URL proxy resolved from the active configuration."""

    def __init__(self, key: str) -> None:
        self.key = key

    def __str__(self) -> str:
        config = get_config()
        if self.key == "auth":
            return config.auth_base_url
        return config.resolve_service_base_url()

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)


AUTH_BASE = ConfigUrl("auth")
SVC_BASE = ConfigUrl("service")
TIMEOUT = get_config().timeout


def timeout() -> int:
    """Return the configured request timeout."""
    return get_config().timeout


def auth_header(bearer: str) -> dict[str, str]:
    """Return an Authorization header dict for the given bearer token."""
    return {"Authorization": f"Bearer {bearer}"}


def fresh_login(
    email: str | None = None, password: str | None = None
) -> dict[str, object]:
    """Perform a fresh login and return token, cookies, and auth headers."""
    config = get_config()
    login_email = email or config.admin_email
    login_password = password or config.admin_password
    response = requests.post(
        f"{config.auth_base_url}/login/access-token",
        data={"username": login_email, "password": login_password},
        timeout=config.timeout,
    )
    assert response.status_code == 200, (
        f"Login failed for {login_email}: {response.text}"
    )
    token = str(response.json()["access_token"])
    return {
        "token": token,
        "cookies": dict(response.cookies),
        "headers": auth_header(token),
    }
