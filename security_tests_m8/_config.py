"""Runtime configuration for reusable live security tests."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from security_tests_m8._requests import install_live_tls_defaults


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_tls_verify(name: str, default: bool | str) -> bool | str:
    raw = os.getenv(name)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return raw


def _env_service_bases() -> dict[str, str]:
    raw = os.getenv("LIVE_TEST_SVC_BASES")
    if raw is None:
        return {}
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError("LIVE_TEST_SVC_BASES must be a JSON object")
    return {str(key): str(value).rstrip("/") for key, value in decoded.items()}


def _env_endpoint_map(name: str) -> dict[str, list[str]]:
    raw = os.getenv(name)
    if raw is None:
        return {}
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError(f"{name} must be a JSON object")
    endpoints: dict[str, list[str]] = {}
    for service, values in decoded.items():
        if not isinstance(values, list):
            raise ValueError(f"{name} values must be arrays")
        endpoints[str(service)] = [str(value) for value in values]
    return endpoints


DEFAULT_PLACEHOLDER_VALUE = "changethis"

INTERNAL_TOKEN_HEADER = "X-Internal-Token"
INTERNAL_CLIENT_HEADER = "X-Internal-Client"

_FIELD_ENV_NAMES = {
    "auth_base_url": ("LIVE_TEST_AUTH_BASE",),
    "internal_auth_base_url": ("LIVE_TEST_INTERNAL_AUTH_BASE",),
    "auth_health_url": ("LIVE_TEST_AUTH_HEALTH_URL",),
    "admin_email": ("LIVE_TEST_ADMIN_EMAIL",),
    "admin_password": ("LIVE_TEST_ADMIN_PASSWORD",),
    "service_base_url": ("LIVE_TEST_SVC_BASE",),
    "service_base_urls": ("LIVE_TEST_SVC_BASES",),
    "default_service": ("LIVE_TEST_DEFAULT_SVC",),
    "timeout": ("LIVE_TEST_TIMEOUT",),
    "repo_root": ("LIVE_TEST_REPO_ROOT",),
    "deployment_root": ("LIVE_TEST_DEPLOYMENT_ROOT",),
    "public_base_url": ("LIVE_TEST_PUBLIC_BASE",),
    "public_tls_verify": ("LIVE_TEST_PUBLIC_TLS_VERIFY",),
    "private_api_secret": ("LIVE_TEST_PRIVATE_API_SECRET",),
    "private_api_client_id": ("LIVE_TEST_PRIVATE_API_CLIENT_ID",),
    "health_detail_credential": ("LIVE_TEST_HEALTH_DETAIL_CREDENTIAL",),
    "refresh_secret_key": ("LIVE_TEST_REFRESH_SECRET_KEY",),
    "fail_fast_preflight": ("LIVE_TEST_FAIL_FAST_PREFLIGHT",),
    "forbid_bootstrap_superuser": ("LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER",),
    "protected_endpoints": ("LIVE_TEST_PROTECTED_ENDPOINTS",),
}


@dataclass(frozen=True)
class LiveTestConfig:
    """Configuration used by live security suites and pytest fixtures."""

    auth_base_url: str = "http://localhost:9000/user"
    internal_auth_base_url: str | None = None
    auth_health_url: str | None = None
    admin_email: str = "admin@example.com"
    admin_password: str = DEFAULT_PLACEHOLDER_VALUE
    service_base_url: str | None = None
    service_base_urls: dict[str, str] = field(default_factory=dict)
    default_service: str | None = None
    timeout: int = 10
    repo_root: Path | None = None
    deployment_root: Path | None = None
    public_base_url: str | None = "https://localhost:4430"
    public_tls_verify: bool | str = True
    private_api_secret: str | None = None
    private_api_client_id: str | None = None
    health_detail_credential: str | None = None
    refresh_secret_key: str | None = None
    fail_fast_preflight: bool = False
    forbid_bootstrap_superuser: bool = True
    protected_endpoints: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> LiveTestConfig:
        """Build a configuration object from environment variables."""
        service_base_url = os.getenv("LIVE_TEST_SVC_BASE")
        repo_root = os.getenv("LIVE_TEST_REPO_ROOT")
        deployment_root = os.getenv("LIVE_TEST_DEPLOYMENT_ROOT")
        return cls(
            auth_base_url=os.getenv(
                "LIVE_TEST_AUTH_BASE", "http://localhost:9000/user"
            ).rstrip("/"),
            internal_auth_base_url=(
                os.getenv("LIVE_TEST_INTERNAL_AUTH_BASE", "").rstrip("/") or None
            ),
            auth_health_url=(
                os.getenv("LIVE_TEST_AUTH_HEALTH_URL", "").rstrip("/") or None
            ),
            admin_email=os.getenv("LIVE_TEST_ADMIN_EMAIL", "admin@example.com"),
            admin_password=os.getenv(
                "LIVE_TEST_ADMIN_PASSWORD", DEFAULT_PLACEHOLDER_VALUE
            ),
            service_base_url=service_base_url.rstrip("/") if service_base_url else None,
            service_base_urls=_env_service_bases(),
            default_service=os.getenv("LIVE_TEST_DEFAULT_SVC"),
            timeout=_env_int("LIVE_TEST_TIMEOUT", 10),
            repo_root=Path(repo_root).resolve() if repo_root else None,
            deployment_root=Path(deployment_root).resolve()
            if deployment_root
            else None,
            public_base_url=os.getenv(
                "LIVE_TEST_PUBLIC_BASE", "https://localhost:4430"
            ).rstrip("/"),
            public_tls_verify=_env_tls_verify("LIVE_TEST_PUBLIC_TLS_VERIFY", True),
            private_api_secret=os.getenv("LIVE_TEST_PRIVATE_API_SECRET"),
            private_api_client_id=os.getenv("LIVE_TEST_PRIVATE_API_CLIENT_ID"),
            health_detail_credential=os.getenv("LIVE_TEST_HEALTH_DETAIL_CREDENTIAL"),
            refresh_secret_key=os.getenv("LIVE_TEST_REFRESH_SECRET_KEY"),
            fail_fast_preflight=_env_bool("LIVE_TEST_FAIL_FAST_PREFLIGHT", False),
            forbid_bootstrap_superuser=_env_bool(
                "LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER", True
            ),
            protected_endpoints=_env_endpoint_map("LIVE_TEST_PROTECTED_ENDPOINTS"),
        ).normalized()

    def normalized(self) -> LiveTestConfig:
        """Return a copy with URL mappings normalized."""
        urls = {key: value.rstrip("/") for key, value in self.service_base_urls.items()}
        protected_endpoints = {
            key: [endpoint for endpoint in endpoints]
            for key, endpoints in self.protected_endpoints.items()
        }
        service_base_url = (
            self.service_base_url.rstrip("/") if self.service_base_url else None
        )
        if service_base_url:
            urls.setdefault("default", service_base_url)
        default_service = self.default_service
        if default_service is None and service_base_url:
            default_service = "default"
        return replace(
            self,
            auth_base_url=self.auth_base_url.rstrip("/"),
            internal_auth_base_url=self.internal_auth_base_url.rstrip("/")
            if self.internal_auth_base_url
            else None,
            auth_health_url=self.auth_health_url.rstrip("/")
            if self.auth_health_url
            else None,
            service_base_url=service_base_url,
            service_base_urls=urls,
            default_service=default_service,
            public_base_url=self.public_base_url.rstrip("/")
            if self.public_base_url
            else None,
            protected_endpoints=protected_endpoints,
        )

    def resolve_service_base_url(self, service: str | None = None) -> str:
        """Resolve a named service URL, falling back to the configured default."""
        if service is not None:
            try:
                return self.service_base_urls[service]
            except KeyError as exc:
                names = ", ".join(sorted(self.service_base_urls)) or "<none>"
                raise LookupError(
                    f"Service {service!r} is not configured. Known services: {names}"
                ) from exc
        if self.default_service:
            return self.resolve_service_base_url(self.default_service)
        if self.service_base_url:
            return self.service_base_url
        raise LookupError(
            "No service URL configured. Set LIVE_TEST_SVC_BASE or "
            "LIVE_TEST_SVC_BASES, or call configure(service_base_url=...)."
        )

    def private_api_base_url(self) -> str:
        """Return the base URL that exposes ``/private/*`` routes.

        Hardened stacks block ``/private`` at the public edge (Traefik returns
        404), so private-route probes must target the internal service-to-service
        entrypoint. ``LIVE_TEST_INTERNAL_AUTH_BASE`` carries that URL when set;
        otherwise we fall back to ``auth_base_url`` for simple stacks where the
        public base reaches private routes directly.
        """
        return self.internal_auth_base_url or self.auth_base_url

    def internal_headers(self) -> dict[str, str]:
        """Return private-API auth headers for the configured consumer model.

        Emits ``X-Internal-Token`` when a private secret is set, and adds
        ``X-Internal-Client`` when a consumer id is configured — the
        per-consumer model required by fa-auth-m8 >= 1.0.0 (no shared-secret
        fallback). With no secret configured the probe stays unauthenticated.
        """
        if not self.private_api_secret:
            return {}
        headers = {INTERNAL_TOKEN_HEADER: self.private_api_secret}
        if self.private_api_client_id:
            headers[INTERNAL_CLIENT_HEADER] = self.private_api_client_id
        return headers

    def health_detail_headers(self) -> dict[str, str]:
        """Return headers that unlock the deep ``/health`` infrastructure detail.

        fa-auth-m8 >= 1.0.0 gates the detail body (token mode, Redis/DB
        reachability, degradation modes) on a dedicated ``HEALTH_DETAIL_CREDENTIAL``
        sent via ``X-Internal-Token`` — decoupled from ``PRIVATE_API_SECRET``
        (plan 9.3). Probes that read health detail (stack detection, token-mode
        and disclosure suites) must present that credential. Falls back to
        ``private_api_secret`` for legacy stacks that still reuse it for the
        health-detail gate; empty when neither is configured (shallow status only).
        """
        credential = self.health_detail_credential or self.private_api_secret
        if not credential:
            return {}
        return {INTERNAL_TOKEN_HEADER: credential}

    def legacy_internal_headers(self) -> dict[str, str]:
        """Return the legacy ``X-Internal-Token``-only private-API headers.

        Always omits ``X-Internal-Client`` so negative/legacy-detection probes
        can assert that a per-consumer issuer rejects the retired shared-secret
        shape. Empty when no secret is configured.
        """
        if not self.private_api_secret:
            return {}
        return {INTERNAL_TOKEN_HEADER: self.private_api_secret}


_CONFIG = LiveTestConfig.from_env()
install_live_tls_defaults(_CONFIG)


def configure(**kwargs: object) -> LiveTestConfig:
    """Update the module-level live-test configuration."""
    global _CONFIG
    current = _CONFIG
    data = current.__dict__ | kwargs
    if isinstance(data.get("repo_root"), str):
        data["repo_root"] = Path(str(data["repo_root"])).resolve()
    if isinstance(data.get("deployment_root"), str):
        data["deployment_root"] = Path(str(data["deployment_root"])).resolve()
    if isinstance(data.get("service_base_urls"), Mapping):
        data["service_base_urls"] = dict(data["service_base_urls"])
    _CONFIG = LiveTestConfig(**data).normalized()
    install_live_tls_defaults(_CONFIG)
    return _CONFIG


def load_env_file(path: str | Path, *, override: bool = False) -> dict[str, str]:
    """Load KEY=VALUE pairs from an env file into ``os.environ``."""
    env_path = Path(path)
    loaded: dict[str, str] = {}
    if not env_path.exists():
        return loaded
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip()
        value = value.strip().strip("'\"")
        if not name:
            continue
        loaded[name] = value
        if override or name not in os.environ:
            os.environ[name] = value
    return loaded


def configure_from_env(
    env_file: str | Path | None = None,
    *,
    override_env_file: bool = False,
    **defaults: Any,
) -> LiveTestConfig:
    """Load an optional env file and configure live tests from env plus defaults."""
    env_path = Path.cwd() / ".env" if env_file is None else Path(env_file)
    load_env_file(env_path, override=override_env_file)

    config = LiveTestConfig.from_env()
    data: dict[str, Any] = {}
    for field_name, default in defaults.items():
        env_names = _FIELD_ENV_NAMES.get(field_name, ())
        if not any(name in os.environ for name in env_names):
            data[field_name] = default

    return configure(**(config.__dict__ | data))


def get_config() -> LiveTestConfig:
    """Return the active live-test configuration."""
    return _CONFIG
