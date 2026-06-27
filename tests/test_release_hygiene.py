import os
from pathlib import Path

import pytest

from security_tests_m8.release_hygiene import (
    HygieneFinding,
    ReleaseHygieneReport,
    scan_release_surface,
)


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _codes(root: Path) -> set[str]:
    return {f.code for f in scan_release_surface(root).findings}


# ---------------------------------------------------------------------------
# Missing root
# ---------------------------------------------------------------------------


def test_scan_raises_for_missing_root(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_release_surface(tmp_path / "nonexistent")


# ---------------------------------------------------------------------------
# Clean worktree
# ---------------------------------------------------------------------------


def test_clean_worktree_has_no_findings(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", "# M8")
    _write(tmp_path / ".env.example", "SECRET=changethis")
    _write(tmp_path / "src" / "main.py", "print('hello')")
    _write(tmp_path / "grafana" / "provisioning" / "dashboards.yml", "# config")

    report = scan_release_surface(tmp_path)

    assert report.errors == ()
    assert report.warnings == ()


# ---------------------------------------------------------------------------
# Runtime env files
# ---------------------------------------------------------------------------


def test_dot_env_at_root_blocked(tmp_path: Path) -> None:
    _write(tmp_path / ".env", "SECRET=value")

    assert "runtime-env-file" in _codes(tmp_path)


def test_auth_env_nested_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "stack" / "auth.env", "DB_PASSWORD=secret")

    assert "runtime-env-file" in _codes(tmp_path)


def test_all_named_runtime_env_files_blocked(tmp_path: Path) -> None:
    for name in ("media.env", "worker.env", "api.env", "test.env", "grafana.env"):
        _write(tmp_path / name, "KEY=val")

    assert "runtime-env-file" in _codes(tmp_path)


def test_example_env_files_pass(tmp_path: Path) -> None:
    _write(tmp_path / ".env.example", "SECRET=changethis")
    _write(tmp_path / "auth.env.example", "DB_PASSWORD=changethis")
    _write(tmp_path / "stack" / "media.env.example", "KEY=changethis")

    assert "runtime-env-file" not in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Private key material
# ---------------------------------------------------------------------------


def test_dot_key_file_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "keys" / "private.key", "---BEGIN RSA---")

    assert "private-key-material" in _codes(tmp_path)


def test_dot_pem_file_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "traefik" / "certs" / "local.pem", "---BEGIN CERT---")

    assert "private-key-material" in _codes(tmp_path)


def test_example_pem_file_passes(tmp_path: Path) -> None:
    _write(tmp_path / "cert.pem.example", "---EXAMPLE---")

    assert "private-key-material" not in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Redis dump
# ---------------------------------------------------------------------------


def test_redis_dump_rdb_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "backup" / "dump.rdb")

    assert "redis-dump" in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Database files
# ---------------------------------------------------------------------------


def test_dot_db_file_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "local.db")

    assert "database-file" in _codes(tmp_path)


def test_dot_sqlite_file_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "data" / "store.sqlite")

    # NOTE: "data" here has parent "tmp_path", which is NOT a grafana/prometheus dir,
    # so the data/ dir is recursed into and the sqlite file is found.
    assert "database-file" in _codes(tmp_path)


def test_dot_sqlite3_file_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "app.sqlite3")

    assert "database-file" in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Blocked runtime data directories
# ---------------------------------------------------------------------------


def test_minio_dir_blocked(tmp_path: Path) -> None:
    (tmp_path / "minio").mkdir()

    assert "runtime-data-dir" in _codes(tmp_path)


def test_redis_dir_blocked(tmp_path: Path) -> None:
    (tmp_path / "redis").mkdir()

    assert "runtime-data-dir" in _codes(tmp_path)


def test_media_redis_dir_blocked(tmp_path: Path) -> None:
    (tmp_path / "media_redis").mkdir()

    assert "runtime-data-dir" in _codes(tmp_path)


def test_db_data_dir_blocked(tmp_path: Path) -> None:
    (tmp_path / "db_data").mkdir()

    assert "runtime-data-dir" in _codes(tmp_path)


def test_vault_dir_blocked(tmp_path: Path) -> None:
    (tmp_path / "vault").mkdir()

    assert "runtime-data-dir" in _codes(tmp_path)


def test_grafana_data_subdir_blocked(tmp_path: Path) -> None:
    (tmp_path / "grafana" / "data").mkdir(parents=True)

    assert "runtime-data-dir" in _codes(tmp_path)


def test_prometheus_data_subdir_blocked(tmp_path: Path) -> None:
    (tmp_path / "prometheus" / "data").mkdir(parents=True)

    assert "runtime-data-dir" in _codes(tmp_path)


def test_grafana_non_data_subdir_not_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "grafana" / "provisioning" / "config.yml", "# ok")

    assert "runtime-data-dir" not in _codes(tmp_path)


def test_unrelated_data_dir_not_blocked(tmp_path: Path) -> None:
    # "data/" whose parent is not grafana or prometheus is traversed, not blocked.
    _write(tmp_path / "app" / "data" / "readme.txt", "ok")

    assert "runtime-data-dir" not in _codes(tmp_path)


def test_blocked_runtime_dir_is_not_recursed(tmp_path: Path) -> None:
    # Files inside a blocked dir must not generate additional findings.
    (tmp_path / "redis").mkdir()
    _write(tmp_path / "redis" / "dump.rdb")

    codes = _codes(tmp_path)
    assert "runtime-data-dir" in codes
    assert "redis-dump" not in codes


# ---------------------------------------------------------------------------
# Skip directories (.git, __pycache__, etc.)
# ---------------------------------------------------------------------------


def test_git_dir_skipped(tmp_path: Path) -> None:
    _write(tmp_path / ".git" / "config", "# git internal")
    _write(tmp_path / ".git" / "auth.env", "SECRET=value")  # should be ignored

    assert "runtime-env-file" not in _codes(tmp_path)


def test_pycache_dir_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "__pycache__" / "module.pyc", "")

    assert _codes(tmp_path) == set()


def test_node_modules_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "node_modules" / "pkg" / ".env", "SECRET=value")

    assert "runtime-env-file" not in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Permission-denied directory
# ---------------------------------------------------------------------------


def test_permission_denied_dir_produces_warning(tmp_path: Path) -> None:
    blocked = tmp_path / "restricted"
    blocked.mkdir()
    os.chmod(blocked, 0o000)
    try:
        report = scan_release_surface(tmp_path)
    finally:
        os.chmod(blocked, 0o755)

    codes = {f.code for f in report.warnings}
    assert "permission-denied" in codes


# ---------------------------------------------------------------------------
# Report properties and assert_no_errors
# ---------------------------------------------------------------------------


def test_errors_property_filters_by_severity(tmp_path: Path) -> None:
    error = HygieneFinding(
        code="runtime-env-file",
        message="msg",
        severity="error",
        path=tmp_path / "auth.env",
    )
    warning = HygieneFinding(
        code="permission-denied",
        message="msg",
        severity="warning",
        path=tmp_path / "locked",
    )
    report = ReleaseHygieneReport(root=tmp_path, findings=(error, warning))

    assert report.errors == (error,)
    assert report.warnings == (warning,)


def test_assert_no_errors_passes_when_clean(tmp_path: Path) -> None:
    report = ReleaseHygieneReport(root=tmp_path, findings=())
    report.assert_no_errors()  # must not raise


def test_assert_no_errors_raises_with_error_findings(tmp_path: Path) -> None:
    finding = HygieneFinding(
        code="runtime-env-file",
        message="blocked",
        severity="error",
        path=tmp_path / "auth.env",
    )
    report = ReleaseHygieneReport(root=tmp_path, findings=(finding,))

    with pytest.raises(AssertionError, match="ERROR runtime-env-file"):
        report.assert_no_errors()


# ---------------------------------------------------------------------------
# HygieneFinding.format()
# ---------------------------------------------------------------------------


def test_format_produces_root_relative_path(tmp_path: Path) -> None:
    finding = HygieneFinding(
        code="runtime-env-file",
        message="blocked",
        severity="error",
        path=tmp_path / "stack" / "auth.env",
    )

    result = finding.format(tmp_path)

    assert result == "ERROR runtime-env-file stack/auth.env - blocked"


def test_format_handles_path_outside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.env"
    finding = HygieneFinding(
        code="runtime-env-file",
        message="blocked",
        severity="error",
        path=outside,
    )

    result = finding.format(tmp_path)

    assert str(outside) in result
    assert "ERROR runtime-env-file" in result
