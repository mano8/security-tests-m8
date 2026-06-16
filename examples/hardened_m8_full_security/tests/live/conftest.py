"""Live-test configuration for the fa-auth-m8 hardened_m8 compose stack."""

from __future__ import annotations

import os
from pathlib import Path

from security_tests_m8 import configure


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


HARDENED_STACK_ROOT = Path(
    os.getenv(
        "HARDENED_M8_STACK_ROOT",
        "/workspace/fa-auth-m8/examples/docker_compose/hardened_m8",
    )
).resolve()

FASTAPI_BASE_URL = os.getenv("LIVE_TEST_SVC_BASE", "http://localhost:9000/fastapi")

configure(
    auth_base_url=os.getenv("LIVE_TEST_AUTH_BASE", "http://localhost:9000/user"),
    admin_email=os.getenv("LIVE_TEST_ADMIN_EMAIL", "changethis"),
    admin_password=os.getenv("LIVE_TEST_ADMIN_PASSWORD", "changethis"),
    service_base_url=FASTAPI_BASE_URL,
    service_base_urls={"fastapi": FASTAPI_BASE_URL},
    default_service="fastapi",
    timeout=int(os.getenv("LIVE_TEST_TIMEOUT", "10")),
    repo_root=Path(os.getenv("LIVE_TEST_REPO_ROOT", str(HARDENED_STACK_ROOT))),
    deployment_root=Path(
        os.getenv("LIVE_TEST_DEPLOYMENT_ROOT", str(HARDENED_STACK_ROOT))
    ),
    public_base_url=os.getenv("LIVE_TEST_PUBLIC_BASE", "https://localhost:4430"),
    public_tls_verify=_env_bool("LIVE_TEST_PUBLIC_TLS_VERIFY", False),
    private_api_secret=os.getenv("LIVE_TEST_PRIVATE_API_SECRET", "changethis"),
    refresh_secret_key=os.getenv("LIVE_TEST_REFRESH_SECRET_KEY", "changethis"),
)
