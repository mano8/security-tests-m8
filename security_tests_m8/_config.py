"""Runtime configuration for reusable live security tests."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path


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


def _env_service_bases() -> dict[str, str]:
    raw = os.getenv("LIVE_TEST_SVC_BASES")
    if raw is None:
        return {}
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError("LIVE_TEST_SVC_BASES must be a JSON object")
    return {str(key): str(value).rstrip("/") for key, value in decoded.items()}


DEFAULT_PLACEHOLDER_VALUE = "changethis"


@dataclass(frozen=True)
class LiveTestConfig:
    """Configuration used by live security suites and pytest fixtures."""

    auth_base_url: str = "http://localhost:9000/user"
    admin_email: str = "admin@example.com"
    admin_password: str = DEFAULT_PLACEHOLDER_VALUE
    service_base_url: str | None = None
    service_base_urls: dict[str, str] = field(default_factory=dict)
    default_service: str | None = None
    timeout: int = 10
    repo_root: Path | None = None
    deployment_root: Path | None = None
    public_base_url: str | None = "https://localhost:4430"
    public_tls_verify: bool = True
    private_api_secret: str | None = None
    refresh_secret_key: str | None = None

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
            public_tls_verify=_env_bool("LIVE_TEST_PUBLIC_TLS_VERIFY", True),
            private_api_secret=os.getenv("LIVE_TEST_PRIVATE_API_SECRET"),
            refresh_secret_key=os.getenv("LIVE_TEST_REFRESH_SECRET_KEY"),
        ).normalized()

    def normalized(self) -> LiveTestConfig:
        """Return a copy with URL mappings normalized."""
        urls = {key: value.rstrip("/") for key, value in self.service_base_urls.items()}
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
            service_base_url=service_base_url,
            service_base_urls=urls,
            default_service=default_service,
            public_base_url=self.public_base_url.rstrip("/")
            if self.public_base_url
            else None,
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


_CONFIG = LiveTestConfig.from_env()


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
    return _CONFIG


def get_config() -> LiveTestConfig:
    """Return the active live-test configuration."""
    return _CONFIG
