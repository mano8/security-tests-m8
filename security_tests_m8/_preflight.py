"""Fail-fast checks for live security test sessions."""

from __future__ import annotations

from pathlib import Path

import requests

from security_tests_m8._config import LiveTestConfig


class PreflightError(RuntimeError):
    """Raised when a live stack is not safe or ready for the full suite."""


def _read_env_value(path: Path, name: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{name}="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1].strip().strip("'\"")
    return None


def _ensure_not_bootstrap_superuser(config: LiveTestConfig) -> None:
    if not config.forbid_bootstrap_superuser or config.deployment_root is None:
        return

    bootstrap_email = _read_env_value(
        config.deployment_root / "auth.env", "FIRST_SUPERUSER"
    )
    if bootstrap_email and config.admin_email.lower() == bootstrap_email.lower():
        raise PreflightError(
            "Refusing to run with the stack bootstrap superuser. Configure "
            "LIVE_TEST_ADMIN_EMAIL/LIVE_TEST_ADMIN_PASSWORD with a dedicated "
            "test-only superuser."
        )


def _check_auth_available(config: LiveTestConfig) -> None:
    try:
        response = requests.get(
            f"{config.auth_base_url}/health/", timeout=config.timeout
        )
    except requests.RequestException as exc:
        raise PreflightError(
            f"Auth API is not reachable at {config.auth_base_url}: {exc}"
        ) from exc
    if response.status_code >= 500:
        raise PreflightError(
            f"Auth API health check returned {response.status_code}: {response.text}"
        )
    if response.status_code not in (200, 204):
        raise PreflightError(
            f"Auth API health check failed with {response.status_code}: {response.text}"
        )


def _check_services_available(config: LiveTestConfig) -> None:
    for name, base_url in config.service_base_urls.items():
        try:
            response = requests.get(base_url, timeout=config.timeout)
        except requests.RequestException as exc:
            raise PreflightError(
                f"Service {name!r} is not reachable at {base_url}: {exc}"
            ) from exc
        if response.status_code >= 500:
            raise PreflightError(
                f"Service {name!r} returned {response.status_code} at {base_url}: "
                f"{response.text}"
            )


def _check_admin_credentials(config: LiveTestConfig) -> None:
    try:
        response = requests.post(
            f"{config.auth_base_url}/login/access-token",
            data={"username": config.admin_email, "password": config.admin_password},
            timeout=config.timeout,
        )
    except requests.RequestException as exc:
        raise PreflightError(
            f"Admin login preflight could not reach auth API: {exc}"
        ) from exc

    if response.status_code == 200:
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise PreflightError(
                "Admin login returned non-JSON success response"
            ) from exc
        if not token:
            raise PreflightError("Admin login response did not contain access_token")
        return

    if response.status_code == 429:
        raise PreflightError(
            "Admin login is rate-limited. Wait for the lockout window or clear only "
            f"the live-test login limiter state. Response: {response.text}"
        )

    if response.status_code in (400, 401, 403, 404):
        raise PreflightError(
            "Configured live-test admin credentials are invalid or the dedicated "
            f"test superuser does not exist. Status {response.status_code}: "
            f"{response.text}"
        )

    raise PreflightError(
        f"Admin login preflight failed with {response.status_code}: {response.text}"
    )


def run_live_preflight(config: LiveTestConfig) -> None:
    """Validate that the full live suite can run before pytest collection."""
    _ensure_not_bootstrap_superuser(config)
    _check_auth_available(config)
    _check_services_available(config)
    _check_admin_credentials(config)
