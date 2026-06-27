"""Release artifact hygiene scanner for M8 repo worktrees."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

HygieneSeverity = Literal["error", "warning"]

_BLOCKED_ENV_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        "auth.env",
        "media.env",
        "worker.env",
        "api.env",
        "test.env",
        "grafana.env",
    }
)
_EXAMPLE_SUFFIX = ".example"
_BLOCKED_KEY_SUFFIXES: tuple[str, ...] = (".key", ".pem")
_BLOCKED_DB_SUFFIXES: tuple[str, ...] = (".db", ".sqlite", ".sqlite3")
_BLOCKED_REDIS_NAMES: frozenset[str] = frozenset({"dump.rdb"})

_SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".astro",
        ".venv",
        "venv",
    }
)

# Runtime data directory names — must not appear anywhere on a release surface
_BLOCKED_RUNTIME_DIR_NAMES: frozenset[str] = frozenset(
    {"minio", "redis", "media_redis", "db_data", "vault"}
)
# Directories whose "data" subdirectory is a blocked runtime artifact
_BLOCKED_DATA_PARENT_NAMES: frozenset[str] = frozenset({"grafana", "prometheus"})


@dataclass(frozen=True)
class HygieneFinding:
    """A release hygiene issue found in a repo worktree."""

    code: str
    message: str
    severity: HygieneSeverity
    path: Path

    def format(self, root: Path) -> str:
        """Return a compact, root-relative finding description."""
        try:
            location: Path = self.path.relative_to(root)
        except ValueError:
            location = self.path
        return f"{self.severity.upper()} {self.code} {location} - {self.message}"


@dataclass(frozen=True)
class ReleaseHygieneReport:
    """Result object returned by :func:`scan_release_surface`."""

    root: Path
    findings: tuple[HygieneFinding, ...]

    @property
    def errors(self) -> tuple[HygieneFinding, ...]:
        """Return only fatal hygiene findings."""
        return tuple(f for f in self.findings if f.severity == "error")

    @property
    def warnings(self) -> tuple[HygieneFinding, ...]:
        """Return non-fatal hygiene findings."""
        return tuple(f for f in self.findings if f.severity == "warning")

    def assert_no_errors(self) -> None:
        """Assert the worktree contains no fatal release hygiene findings."""
        assert not self.errors, "\n".join(f.format(self.root) for f in self.errors)


def _is_example(path: Path) -> bool:
    return path.name.endswith(_EXAMPLE_SUFFIX)


def _check_file(path: Path) -> HygieneFinding | None:
    if _is_example(path):
        return None
    name = path.name
    if name in _BLOCKED_ENV_NAMES:
        return HygieneFinding(
            code="runtime-env-file",
            message="runtime env file must not appear on a release or build surface",
            severity="error",
            path=path,
        )
    if any(name.endswith(suffix) for suffix in _BLOCKED_KEY_SUFFIXES):
        return HygieneFinding(
            code="private-key-material",
            message=(
                "private key or certificate file must not appear"
                " on a release or build surface"
            ),
            severity="error",
            path=path,
        )
    if name in _BLOCKED_REDIS_NAMES:
        return HygieneFinding(
            code="redis-dump",
            message="Redis persistence dump must not appear on a release or build surface",
            severity="error",
            path=path,
        )
    if any(name.endswith(suffix) for suffix in _BLOCKED_DB_SUFFIXES):
        return HygieneFinding(
            code="database-file",
            message="database file must not appear on a release or build surface",
            severity="error",
            path=path,
        )
    return None


def _is_blocked_dir(entry: Path) -> bool:
    if entry.name in _BLOCKED_RUNTIME_DIR_NAMES:
        return True
    return entry.name == "data" and entry.parent.name in _BLOCKED_DATA_PARENT_NAMES


def _walk(root: Path, findings: list[HygieneFinding]) -> None:
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        findings.append(
            HygieneFinding(
                code="permission-denied",
                message=(
                    "directory is not readable;"
                    " contents cannot be verified as release-clean"
                ),
                severity="warning",
                path=root,
            )
        )
        return

    for entry in entries:
        if entry.is_dir():
            if entry.name in _SKIP_DIR_NAMES:
                continue
            if _is_blocked_dir(entry):
                findings.append(
                    HygieneFinding(
                        code="runtime-data-dir",
                        message=(
                            "runtime data directory must not appear"
                            " on a release or build surface"
                        ),
                        severity="error",
                        path=entry,
                    )
                )
            else:
                _walk(entry, findings)
        elif entry.is_file():
            finding = _check_file(entry)
            if finding is not None:
                findings.append(finding)


def scan_release_surface(root: str | Path) -> ReleaseHygieneReport:
    """Scan a repo worktree for runtime artifacts that must not appear on a release surface."""
    root_path = Path(root).resolve()
    if not root_path.exists():
        raise FileNotFoundError(root_path)
    findings: list[HygieneFinding] = []
    _walk(root_path, findings)
    return ReleaseHygieneReport(root=root_path, findings=tuple(findings))
