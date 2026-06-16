from __future__ import annotations

from pathlib import Path

from security_tests_m8.cli import main


def test_preflight_prints_success_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
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
        "Reason: scanned files produced no ERROR or WARNING findings."
        in captured.out
    )
    assert "Required action: none." in captured.out


def test_preflight_prints_failure_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
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


def test_preflight_prints_warning_pass_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text(
        "ENVIRONMENT=production\n"
        "ACCESS_REVOCATION_FAILURE_MODE=fail_open\n",
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
        "Reason: no ERROR findings were found; 1 warning does not fail"
        in captured.out
    )
    assert "Required action: review every WARNING finding listed above." in captured.out


def test_preflight_prints_strict_warning_failure_summary(
    capsys, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("LIVE_TEST_DEPLOYMENT_ROOT", raising=False)
    (tmp_path / "auth.env").write_text(
        "ENVIRONMENT=production\n"
        "ACCESS_REVOCATION_FAILURE_MODE=fail_open\n",
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


def test_run_defaults_to_non_destructive_marker(
    tmp_path: Path, monkeypatch
) -> None:
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


def test_run_honors_explicit_marker_selection(
    tmp_path: Path, monkeypatch
) -> None:
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
