"""Python deployment preflight checks for compose-based M8 stacks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Severity = Literal["error", "warning"]


_SENSITIVE_KEY_PARTS = ("PASSWORD", "SECRET", "TOKEN", "KEY")
_HIGH_VALUE_SECRET_KEYS = {
    "REFRESH_SECRET_KEY",
    "PRIVATE_API_SECRET",
    "SESSION_SECRET",
    "TOKENS_ENCRYPTION_KEY",
    "EVENT_SIGNING_KEY",
    "DB_PASSWORD",
    "AUTH_DB_PASSWORD",
    "API_DB_PASSWORD",
    "REDIS_PASSWORD",
    "GF_SECURITY_ADMIN_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    "VAULT_DEV_TOKEN",
}
_PLACEHOLDER_WORDS = ("changethis",)
_PLACEHOLDER_COMMENT_WORDS = (
    "copy to ",
    "dev only",
    "do not use",
    "placeholder",
    "replace ",
)
_LOCALHOST_TOKENS = ("localhost", "127.0.0.1", "::1")
# Value being detected in env files, not bound by this package.
_PUBLIC_BIND_IP = "0.0.0.0"  # noqa: S104  # nosec B104
_TRUTHY = {"1", "true", "yes", "on"}
_DEFAULT_VAULT_TOKENS = {"root", "changethis", "dev-root-token", "vault-root-token"}
_DEFAULT_GRAFANA_PASSWORDS = {"admin", "changethis", "password"}
_DEFAULT_ROOT_DB_PASSWORDS = {"postgres", "password", "changethis"}
_EXAMPLE_ENV_SUFFIXES = (".env.example",)
_EXAMPLE_ENV_NAMES = {".env.example", "env.example"}


@dataclass(frozen=True)
class EnvValue:
    """One parsed environment setting and where it came from."""

    key: str
    value: str
    path: Path
    line: int | None = None


@dataclass(frozen=True)
class DeploymentFinding:
    """A preflight issue found in env or compose deployment files."""

    code: str
    message: str
    severity: Severity
    path: Path
    key: str | None = None

    def format(self, root: Path) -> str:
        """Return a compact, root-relative finding description."""
        try:
            location = self.path.relative_to(root)
        except ValueError:
            location = self.path
        target = f"{location}"
        if self.key:
            target = f"{target}:{self.key}"
        return f"{self.severity.upper()} {self.code} {target} - {self.message}"


@dataclass(frozen=True)
class DeploymentPreflightReport:
    """Result object returned by :func:`scan_deployment`."""

    root: Path
    findings: tuple[DeploymentFinding, ...]
    scanned_files: tuple[Path, ...] = ()

    @property
    def errors(self) -> tuple[DeploymentFinding, ...]:
        """Return only fatal preflight findings."""
        return tuple(
            finding for finding in self.findings if finding.severity == "error"
        )

    @property
    def warnings(self) -> tuple[DeploymentFinding, ...]:
        """Return non-fatal preflight findings."""
        return tuple(
            finding for finding in self.findings if finding.severity == "warning"
        )

    def assert_no_errors(self) -> None:
        """Assert the deployment has no fatal preflight findings."""
        assert not self.errors, "\n".join(
            finding.format(self.root) for finding in self.errors
        )


def _is_sensitive_key(key: str) -> bool:
    return any(part in key.upper() for part in _SENSITIVE_KEY_PARTS)


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def _strip_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'":
        return stripped[1:-1]
    return stripped


def _parse_env_file(path: Path) -> list[EnvValue]:
    values: list[EnvValue] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values.append(
            EnvValue(key=key, value=_strip_quotes(value), path=path, line=line_no)
        )
    return values


def _is_example_env_file(path: Path) -> bool:
    return path.name in _EXAMPLE_ENV_NAMES or path.name.endswith(_EXAMPLE_ENV_SUFFIXES)


def _is_candidate_env_file(path: Path) -> bool:
    if _is_example_env_file(path):
        return False
    return path.name == ".env" or path.suffix == ".env" or path.name.endswith(".env")


def _compose_files(root: Path) -> tuple[Path, ...]:
    names = (
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    )
    return tuple(path for path in (root / name for name in names) if path.exists())


def _load_compose(path: Path) -> Mapping[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, Mapping):
        return {}
    return loaded


def _iter_services(
    compose: Mapping[str, Any],
) -> Iterable[tuple[str, Mapping[str, Any]]]:
    services = compose.get("services", {})
    if not isinstance(services, Mapping):
        return
    for name, service in services.items():
        if isinstance(service, Mapping):
            yield str(name), service


def _compose_env_file_paths(root: Path, compose_files: Iterable[Path]) -> set[Path]:
    paths: set[Path] = set()
    for compose_path in compose_files:
        compose = _load_compose(compose_path)
        for _, service in _iter_services(compose):
            env_file = service.get("env_file")
            entries: Iterable[Any]
            if isinstance(env_file, str):
                entries = (env_file,)
            elif isinstance(env_file, list):
                entries = env_file
            else:
                entries = ()
            for entry in entries:
                if isinstance(entry, Mapping):
                    entry = entry.get("path")
                if isinstance(entry, str):
                    paths.add((compose_path.parent / entry).resolve())
    return {
        path
        for path in paths
        if path.exists() and path.is_file() and _is_candidate_env_file(path)
    }


def _candidate_env_files(
    root: Path, compose_files: tuple[Path, ...]
) -> tuple[Path, ...]:
    paths = set(_compose_env_file_paths(root, compose_files))
    ignored_names = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if ignored_names.intersection(path.parts):
            continue
        if _is_candidate_env_file(path):
            paths.add(path.resolve())
    return tuple(sorted(paths))


def _compose_environment_values(path: Path) -> list[EnvValue]:
    values: list[EnvValue] = []
    compose = _load_compose(path)
    for service_name, service in _iter_services(compose):
        environment = service.get("environment")
        if isinstance(environment, Mapping):
            for key, value in environment.items():
                if value is not None:
                    values.append(
                        EnvValue(key=str(key), value=str(value), path=path, line=None)
                    )
        elif isinstance(environment, list):
            for entry in environment:
                if isinstance(entry, str) and "=" in entry:
                    key, value = entry.split("=", 1)
                    values.append(EnvValue(key=key, value=value, path=path, line=None))
        if "image" in service and isinstance(service["image"], str):
            values.append(
                EnvValue(
                    key=f"COMPOSE_IMAGE_{service_name}",
                    value=service["image"],
                    path=path,
                    line=None,
                )
            )
    return values


def _collect_values(
    root: Path,
) -> tuple[tuple[EnvValue, ...], tuple[Path, ...]]:
    compose_files = _compose_files(root)
    env_files = _candidate_env_files(root, compose_files)
    values: list[EnvValue] = []
    for path in env_files:
        values.extend(_parse_env_file(path))
    for path in compose_files:
        values.extend(_compose_environment_values(path))
    scanned_files = tuple(sorted({*env_files, *compose_files}))
    return tuple(values), scanned_files


def _last_by_key(values: Iterable[EnvValue]) -> dict[str, EnvValue]:
    latest: dict[str, EnvValue] = {}
    for item in values:
        latest[item.key] = item
    return latest


def _add(
    findings: list[DeploymentFinding],
    code: str,
    message: str,
    severity: Severity,
    env_value: EnvValue,
) -> None:
    findings.append(
        DeploymentFinding(
            code=code,
            message=message,
            severity=severity,
            path=env_value.path,
            key=env_value.key,
        )
    )


def _is_hardened_or_production(root: Path, latest: Mapping[str, EnvValue]) -> bool:
    env = latest.get("ENVIRONMENT")
    strict = latest.get("STRICT_PRODUCTION_MODE")
    return (
        "hardened" in root.name.lower()
        or (env is not None and env.value.strip().lower() == "production")
        or _is_truthy(strict.value if strict else None)
    )


def _scan_placeholder_values(
    findings: list[DeploymentFinding], values: Iterable[EnvValue]
) -> None:
    for item in values:
        normalized = item.value.strip().lower()
        if normalized in _PLACEHOLDER_WORDS:
            _add(
                findings,
                "placeholder-value",
                "replace placeholder values before deployment",
                "error",
                item,
            )
        if _is_sensitive_key(item.key) and item.value == "":
            _add(
                findings,
                "empty-sensitive-value",
                "sensitive settings must not be empty",
                "error",
                item,
            )
        if item.value.lstrip().startswith("#") or any(
            word in normalized for word in _PLACEHOLDER_COMMENT_WORDS
        ):
            _add(
                findings,
                "placeholder-comment-value",
                "a placeholder/comment appears to have been copied into a value",
                "error",
                item,
            )


def _canonical_secret_key(item: EnvValue) -> str:
    if item.key == "DB_PASSWORD" and item.path.name == "auth.env":
        return "AUTH_DB_PASSWORD"
    if item.key == "DB_PASSWORD" and item.path.name == "api.env":
        return "API_DB_PASSWORD"
    return item.key


def _scan_duplicate_secret_values(
    findings: list[DeploymentFinding], values: Iterable[EnvValue]
) -> None:
    by_value: dict[str, list[EnvValue]] = defaultdict(list)
    for item in values:
        if item.key not in _HIGH_VALUE_SECRET_KEYS or item.value.startswith("${"):
            continue
        if not item.value:
            continue
        by_value[item.value].append(item)

    for duplicates in by_value.values():
        distinct_keys = {_canonical_secret_key(item) for item in duplicates}
        if len(distinct_keys) <= 1:
            continue
        first = duplicates[0]
        _add(
            findings,
            "duplicate-secret-value",
            "high-value secrets must be distinct; shared by "
            f"{', '.join(sorted(distinct_keys))}",
            "error",
            first,
        )


def _scan_production_policy(
    findings: list[DeploymentFinding],
    latest: Mapping[str, EnvValue],
) -> None:
    environment = latest.get("ENVIRONMENT")
    strict = latest.get("STRICT_PRODUCTION_MODE")
    production = (
        environment is not None and environment.value.strip().lower() == "production"
    )
    strict_mode = _is_truthy(strict.value if strict else None)
    if not production and not strict_mode:
        return

    for key in ("BACKEND_CORS_ORIGINS", "CORS_ALLOWED_ORIGINS"):
        item = latest.get(key)
        if item and any(token in item.value.lower() for token in _LOCALHOST_TOKENS):
            _add(
                findings,
                "localhost-cors-production",
                "production/strict deployments must not allow localhost CORS origins",
                "error",
                item,
            )

    docs_allowed = _is_truthy(
        latest["SERVE_DOCS_IN_PRODUCTION"].value
        if "SERVE_DOCS_IN_PRODUCTION" in latest
        else None
    )
    if production and not docs_allowed:
        for key in ("SET_DOCS", "SET_OPEN_API", "SET_REDOC"):
            item = latest.get(key)
            if item and _is_truthy(item.value):
                _add(
                    findings,
                    "docs-enabled-production",
                    "production deployments must disable API docs unless "
                    "explicitly opted in",
                    "error",
                    item,
                )

    policy_checks = (
        ("EVENT_SIGNING_ENABLED", "false", "event-signing-disabled"),
        ("TOKEN_STRICT_VALIDATION", "false", "token-strict-validation-disabled"),
        ("ACCESS_REVOCATION_FAILURE_MODE", "fail_open", "revocation-fail-open"),
    )
    for key, insecure_value, code in policy_checks:
        item = latest.get(key)
        if item and item.value.strip().lower() == insecure_value:
            _add(
                findings,
                code,
                "insecure degradation policy is only acceptable outside strict mode",
                "error" if strict_mode else "warning",
                item,
            )

    bind = latest.get("API_BIND_IP")
    break_glass = latest.get("ALLOW_PUBLIC_API_BIND")
    if (
        production
        and bind
        and bind.value.strip() == _PUBLIC_BIND_IP
        and not _is_truthy(break_glass.value if break_glass else None)
    ):
        _add(
            findings,
            "public-api-bind",
            "production deployments must not bind the private service "
            "entrypoint to all interfaces",
            "error",
            bind,
        )


def _scan_images(
    findings: list[DeploymentFinding],
    root: Path,
    values: Iterable[EnvValue],
    latest: Mapping[str, EnvValue],
) -> None:
    if not _is_hardened_or_production(root, latest):
        return
    for item in values:
        if item.key.startswith("COMPOSE_IMAGE_") and item.value.endswith(":latest"):
            _add(
                findings,
                "latest-image",
                "hardened/production compose services must use pinned image "
                "tags or digests",
                "error",
                item,
            )


def _scan_default_credentials(
    findings: list[DeploymentFinding], values: Iterable[EnvValue]
) -> None:
    for item in values:
        normalized = item.value.strip().lower()
        if item.key == "VAULT_DEV_TOKEN" and normalized in _DEFAULT_VAULT_TOKENS:
            _add(
                findings,
                "vault-dev-token-default",
                "Vault dev tokens must be changed from defaults",
                "error",
                item,
            )
        if (
            item.key in {"GF_SECURITY_ADMIN_PASSWORD", "GRAFANA_ADMIN_PASSWORD"}
            and normalized in _DEFAULT_GRAFANA_PASSWORDS
        ):
            _add(
                findings,
                "grafana-admin-password-default",
                "Grafana admin password must be changed from defaults",
                "error",
                item,
            )
        if item.key == "DB_PASSWORD" and normalized in _DEFAULT_ROOT_DB_PASSWORDS:
            _add(
                findings,
                "root-db-password-default",
                "root database password must be changed from defaults",
                "error",
                item,
            )


def scan_deployment(root: str | Path) -> DeploymentPreflightReport:
    """Scan a compose deployment directory for P0 preflight security failures."""
    deployment_root = Path(root).resolve()
    if not deployment_root.exists():
        raise FileNotFoundError(deployment_root)

    values, scanned_files = _collect_values(deployment_root)
    latest = _last_by_key(values)
    findings: list[DeploymentFinding] = []

    _scan_placeholder_values(findings, values)
    _scan_duplicate_secret_values(findings, values)
    _scan_production_policy(findings, latest)
    _scan_images(findings, deployment_root, values, latest)
    _scan_default_credentials(findings, values)

    return DeploymentPreflightReport(
        root=deployment_root, findings=tuple(findings), scanned_files=scanned_files
    )
