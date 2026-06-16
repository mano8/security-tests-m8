"""Live-test configuration for the fa-auth-m8 hardened_m8 compose stack."""

from __future__ import annotations

import os
from pathlib import Path

from security_tests_m8 import configure_from_env

HARDENED_STACK_ROOT = Path(
    os.getenv(
        "HARDENED_M8_STACK_ROOT",
        "/workspace/fa-auth-m8/examples/docker_compose/hardened_m8",
    )
).resolve()

configure_from_env(
    auth_base_url="http://localhost:9000/user",
    service_base_url="http://localhost:9000/fastapi",
    service_base_urls={"fastapi": "http://localhost:9000/fastapi"},
    default_service="fastapi",
    timeout=10,
    repo_root=HARDENED_STACK_ROOT,
    deployment_root=HARDENED_STACK_ROOT,
    public_base_url="https://localhost:4430",
    public_tls_verify=False,
    fail_fast_preflight=True,
    forbid_bootstrap_superuser=True,
    protected_endpoints={
        "fastapi": ["/category/", "/dashboard/users/activity/"],
    },
)
