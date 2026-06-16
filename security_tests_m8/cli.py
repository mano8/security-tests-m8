"""Command line interface for security-tests-m8."""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

import pytest

from security_tests_m8._config import configure_from_env, get_config
from security_tests_m8.deployment import scan_deployment


def _strip_separator(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


def _has_marker_expression(args: list[str]) -> bool:
    return "-m" in args or any(arg.startswith("-m=") for arg in args)


def _run(args: argparse.Namespace) -> int:
    configure_from_env(env_file=args.env_file, override_env_file=False)
    pytest_args = _strip_separator(list(args.pytest_args))
    if not args.include_destructive and not _has_marker_expression(pytest_args):
        pytest_args = ["-m", "live and not destructive", *pytest_args]
        print(
            "Live test selection: live and not destructive "
            "(default; use --include-destructive to run destructive tests)"
        )
    elif args.include_destructive:
        print("Live test selection: full packaged suite, including destructive tests")
    with tempfile.TemporaryDirectory(prefix="security-tests-m8-") as tmp:
        test_module = Path(tmp) / "test_full_security.py"
        test_module.write_text(
            "from security_tests_m8.full_security import *  # noqa: F401,F403\n",
            encoding="utf-8",
        )
        return pytest.main([str(test_module), *pytest_args])


def _deployment_root(args: argparse.Namespace) -> Path:
    configure_from_env(env_file=args.env_file, override_env_file=False)
    if args.deployment_root is not None:
        return Path(args.deployment_root).resolve()
    config = get_config()
    if config.deployment_root is not None:
        return config.deployment_root.resolve()
    return Path.cwd().resolve()


def _plural(count: int, noun: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _format_report_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _preflight(args: argparse.Namespace) -> int:
    root = _deployment_root(args)
    report = scan_deployment(root)
    print(f"Deployment preflight: {report.root}")
    if report.scanned_files:
        print(f"Files scanned ({len(report.scanned_files)}):")
        for path in report.scanned_files:
            print(f"  - {_format_report_path(report.root, path)}")
    else:
        print("Files scanned: none")
        print("Scan note: no deployment env or compose files matched the scanner rules")

    if report.findings:
        print(f"Findings ({len(report.findings)}):")
        for finding in report.findings:
            print(f"  - {finding.format(report.root)}")
    else:
        print("Findings: none")

    error_count = len(report.errors)
    warning_count = len(report.warnings)
    fail_for_warnings = args.strict_warnings and warning_count > 0
    if error_count or fail_for_warnings:
        strict_note = (
            " because --strict-warnings is enabled" if fail_for_warnings else ""
        )
        print("FAIL deployment-preflight - deployment did not pass")
        print(
            "Reason: "
            f"{_plural(error_count, 'error')}, "
            f"{_plural(warning_count, 'warning')} found{strict_note}."
        )
        if error_count:
            print("Required action: fix every ERROR finding listed above.")
        elif fail_for_warnings:
            print(
                "Required action: fix every WARNING finding listed above, "
                "or rerun without --strict-warnings."
            )
        return 1

    if warning_count:
        print("PASS deployment-preflight - deployment passed with warnings")
        print(
            "Reason: no ERROR findings were found; "
            f"{_plural(warning_count, 'warning')} does not fail without "
            "--strict-warnings."
        )
        print("Required action: review every WARNING finding listed above.")
    else:
        print("PASS deployment-preflight - deployment passed")
        print("Reason: scanned files produced no ERROR or WARNING findings.")
        print("Required action: none.")
    return 0


def _list_suites(_: argparse.Namespace) -> int:
    from security_tests_m8 import suites

    for name in suites.__all__:
        if name.endswith("Suite"):
            print(name)
    return 0


def _add_env_file_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Live-test env file to load. Default: .env",
    )


def _add_preflight_arguments(parser: argparse.ArgumentParser) -> None:
    _add_env_file_argument(parser)
    parser.add_argument(
        "--deployment-root",
        default=None,
        help=(
            "Deployment directory to scan. Defaults to "
            "LIVE_TEST_DEPLOYMENT_ROOT or cwd."
        ),
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Exit non-zero when warnings are present.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command parser."""
    parser = argparse.ArgumentParser(
        prog="security-tests-m8",
        description="Run reusable FastAPI M8 live security tests.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        description="Run the packaged full live security suite with pytest.",
    )
    _add_env_file_argument(run)
    run.add_argument(
        "--include-destructive",
        action="store_true",
        help=(
            "Run destructive tests that mutate live auth, session, or "
            "rate-limit state. By default CLI run excludes them."
        ),
    )
    run.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help=(
            "Arguments passed through to pytest after '--'. Passing -m "
            "overrides the default non-destructive marker selection."
        ),
    )
    run.set_defaults(func=_run)

    preflight = subparsers.add_parser(
        "preflight",
        description="Scan deployment env and compose files before starting a stack.",
    )
    _add_preflight_arguments(preflight)
    preflight.set_defaults(func=_preflight)

    scan_env = subparsers.add_parser(
        "scan-env",
        description="Alias for preflight.",
    )
    _add_preflight_arguments(scan_env)
    scan_env.set_defaults(func=_preflight)

    list_suites = subparsers.add_parser(
        "list-suites",
        description="List reusable suite classes exported by the package.",
    )
    list_suites.set_defaults(func=_list_suites)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
