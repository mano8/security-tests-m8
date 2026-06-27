from __future__ import annotations

from pathlib import Path

from security_tests_m8 import configure
from security_tests_m8.cli import main


def test_preflight_prints_success_summary(capsys, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)

    code = main(
        [
            "preflight",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "Deployment preflight:" in captured.out
    assert "Files scanned: none" in captured.out
    assert "Scan note: no deployment env or compose files matched" in captured.out
    assert "Findings: none" in captured.out
    assert "PASS deployment-preflight - deployment passed" in captured.out
    assert (
        "Reason: scanned files produced no ERROR or WARNING findings." in captured.out
    )
    assert "Required action: none." in captured.out


def test_preflight_prints_failure_summary(capsys, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text(
        "REFRESH_SECRET_KEY=changethis\n", encoding="utf-8"
    )

    code = main(
        [
            "preflight",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 1
    assert "Files scanned (1):" in captured.out
    assert "  - auth.env" in captured.out
    assert "Findings (1):" in captured.out
    assert "  - ERROR placeholder-value auth.env:REFRESH_SECRET_KEY" in captured.out
    assert "FAIL deployment-preflight - deployment did not pass" in captured.out
    assert "Reason: 1 error, 0 warnings found." in captured.out
    assert "Required action: fix every ERROR finding listed above." in captured.out


def test_preflight_formats_paths_outside_root(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    from security_tests_m8 import cli
    from security_tests_m8.deployment import (
        DeploymentFinding,
        DeploymentPreflightReport,
    )

    outside = tmp_path.parent / "outside.env"

    def fake_scan(root: Path) -> DeploymentPreflightReport:
        return DeploymentPreflightReport(
            root=Path(root),
            scanned_files=(outside,),
            findings=(
                DeploymentFinding(
                    code="outside",
                    message="outside path",
                    severity="warning",
                    path=outside,
                ),
            ),
        )

    monkeypatch.setattr(cli, "scan_deployment", fake_scan)

    code = main(["preflight", "--deployment-root", str(tmp_path)])

    captured = capsys.readouterr()
    assert code == 0
    assert outside.as_posix() in captured.out


def test_preflight_prints_warning_pass_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text(
        "ENVIRONMENT=production\nACCESS_REVOCATION_FAILURE_MODE=fail_open\n",
        encoding="utf-8",
    )

    code = main(
        [
            "preflight",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "Findings (1):" in captured.out
    assert (
        "WARNING revocation-fail-open auth.env:ACCESS_REVOCATION_FAILURE_MODE"
        in captured.out
    )
    assert "PASS deployment-preflight - deployment passed with warnings" in captured.out
    assert (
        "Reason: no ERROR findings were found; 1 warning does not fail" in captured.out
    )
    assert "Required action: review every WARNING finding listed above." in captured.out


def test_preflight_prints_strict_warning_failure_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text(
        "ENVIRONMENT=production\nACCESS_REVOCATION_FAILURE_MODE=fail_open\n",
        encoding="utf-8",
    )

    code = main(
        [
            "preflight",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
            "--strict-warnings",
        ]
    )

    captured = capsys.readouterr()
    assert code == 1
    assert "FAIL deployment-preflight - deployment did not pass" in captured.out
    assert (
        "Reason: 0 errors, 1 warning found because --strict-warnings is enabled."
        in captured.out
    )
    assert "Required action: fix every WARNING finding listed above" in captured.out


def test_preflight_uses_deployment_root_from_env_file(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    deployment_root = tmp_path / "deploy"
    deployment_root.mkdir()
    env_file = tmp_path / "test.env"
    env_file.write_text(
        f"LIVE_TEST_DEPLOYMENT_ROOT={deployment_root}\n",
        encoding="utf-8",
    )

    code = main(["preflight", "--env-file", str(env_file)])

    captured = capsys.readouterr()
    assert code == 0
    assert f"Deployment preflight: {deployment_root.resolve()}" in captured.out


def test_preflight_defaults_to_current_directory(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)

    code = main(["preflight", "--env-file", str(tmp_path / "missing.env")])

    captured = capsys.readouterr()
    assert code == 0
    assert f"Deployment preflight: {tmp_path.resolve()}" in captured.out


def test_list_suites_prints_exported_suite_names(capsys) -> None:
    configure(service_base_url="http://service")

    code = main(["list-suites"])

    captured = capsys.readouterr()
    assert code == 0
    assert "AuthAttackSuite" in captured.out
    assert "DeploymentPreflightSuite" in captured.out


def test_run_defaults_to_non_destructive_marker(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_pytest_main(args: list[str]) -> int:
        calls.append(args)
        return 0

    monkeypatch.delenv("LIVE_TEST_ADMIN_EMAIL", raising=False)
    monkeypatch.setattr("security_tests_m8.cli.pytest.main", fake_pytest_main)

    code = main(["run", "--env-file", str(tmp_path / "missing.env")])

    assert code == 0
    assert calls
    assert calls[0][1:3] == ["-m", "live and not destructive"]


def test_run_honors_explicit_marker_selection(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_pytest_main(args: list[str]) -> int:
        calls.append(args)
        return 0

    monkeypatch.setattr("security_tests_m8.cli.pytest.main", fake_pytest_main)

    code = main(
        [
            "run",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--",
            "-m",
            "live_asymmetric",
        ]
    )

    assert code == 0
    assert calls
    assert calls[0][1:] == ["-m", "live_asymmetric"]


def test_run_can_include_destructive_tests(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_pytest_main(args: list[str]) -> int:
        calls.append(args)
        return 0

    monkeypatch.setattr("security_tests_m8.cli.pytest.main", fake_pytest_main)

    code = main(
        [
            "run",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--include-destructive",
        ]
    )

    assert code == 0
    assert calls
    assert calls[0][1:] == []


# ---------------------------------------------------------------------------
# scan-release command
# ---------------------------------------------------------------------------


def test_scan_release_clean_worktree_passes(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)

    code = main(
        [
            "scan-release",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "Release hygiene scan:" in captured.out
    assert "Findings: none" in captured.out
    assert "PASS release-hygiene - worktree is release-clean" in captured.out
    assert "Reason: no blocked release artifacts found." in captured.out
    assert "Required action: none." in captured.out


def test_scan_release_blocked_artifact_fails(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text("SECRET=value\n", encoding="utf-8")

    code = main(
        [
            "scan-release",
            "--env-file",
            str(tmp_path / "missing.env"),
            "--deployment-root",
            str(tmp_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 1
    assert "Findings (1):" in captured.out
    assert "ERROR runtime-env-file" in captured.out
    assert "FAIL release-hygiene - blocked artifacts found" in captured.out
    assert "Reason: 1 error, 0 warnings found." in captured.out
    assert "Required action: remove every ERROR artifact" in captured.out


def test_scan_release_warnings_without_strict_passes(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    from unittest.mock import patch

    from security_tests_m8.release_hygiene import HygieneFinding, ReleaseHygieneReport

    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    mock_report = ReleaseHygieneReport(
        root=tmp_path,
        findings=(
            HygieneFinding(
                code="permission-denied",
                message="not readable",
                severity="warning",
                path=tmp_path / "locked",
            ),
        ),
    )
    with patch("security_tests_m8.cli.scan_release_surface", return_value=mock_report):
        code = main(
            [
                "scan-release",
                "--env-file",
                str(tmp_path / "missing.env"),
                "--deployment-root",
                str(tmp_path),
            ]
        )

    captured = capsys.readouterr()
    assert code == 0
    assert "PASS release-hygiene - passed with warnings" in captured.out
    assert "Reason: no ERROR findings; 1 warning noted." in captured.out
    assert "Required action: review every WARNING finding listed above." in captured.out


def test_scan_release_warnings_with_strict_fails(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    from unittest.mock import patch

    from security_tests_m8.release_hygiene import HygieneFinding, ReleaseHygieneReport

    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    mock_report = ReleaseHygieneReport(
        root=tmp_path,
        findings=(
            HygieneFinding(
                code="permission-denied",
                message="not readable",
                severity="warning",
                path=tmp_path / "locked",
            ),
        ),
    )
    with patch("security_tests_m8.cli.scan_release_surface", return_value=mock_report):
        code = main(
            [
                "scan-release",
                "--env-file",
                str(tmp_path / "missing.env"),
                "--deployment-root",
                str(tmp_path),
                "--strict-warnings",
            ]
        )

    captured = capsys.readouterr()
    assert code == 1
    assert "FAIL release-hygiene - blocked artifacts found" in captured.out
    assert "because --strict-warnings is enabled" in captured.out
    assert "Required action: resolve every WARNING finding" in captured.out
