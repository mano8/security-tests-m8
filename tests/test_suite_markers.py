"""Every reusable suite must carry its markers on the class, not the module.

A module-level ``pytestmark`` only marks tests collected from that module. The
suites here exist to be *subclassed* from a consumer's own test module — which
is exactly what ``full_security.py`` does — and the subclass is collected from
that other module, where the original module-level mark no longer applies. A
suite that relies on it therefore collects without ``live``/``live_security``
and is silently deselected by any marker expression, including the CLI's default
``-m "live and not destructive"``. The tests never fail; they never run.

This module pins the class-level marks so that regression cannot come back
unnoticed.
"""

from __future__ import annotations

import pytest

from security_tests_m8 import configure


def _suites() -> dict[str, type]:
    configure(service_base_url="http://service")
    from security_tests_m8 import suites

    return {
        name: getattr(suites, name) for name in suites.__all__ if name.endswith("Suite")
    }


def _mark_names(suite: type) -> set[str]:
    return {mark.name for mark in getattr(suite, "pytestmark", [])}


def test_every_exported_suite_declares_class_level_marks() -> None:
    missing = [name for name, suite in _suites().items() if not _mark_names(suite)]

    assert not missing, (
        "These suites carry no class-level pytestmark, so a subclass in another "
        f"module collects unmarked and is silently deselected: {missing}"
    )


def test_every_exported_suite_is_selected_by_the_live_marker() -> None:
    not_live = [
        name for name, suite in _suites().items() if "live" not in _mark_names(suite)
    ]

    assert not not_live, f"Suites missing the 'live' marker: {not_live}"


@pytest.mark.parametrize(
    ("suite_name", "expected"),
    [
        ("ProtectedEndpointSuite", {"live", "live_security"}),
        ("ConfiguredProtectedEndpointsSuite", {"live", "live_security"}),
        ("ServiceInfoDisclosureSuite", {"live", "live_security"}),
        ("ConfiguredServiceInfoDisclosureSuite", {"live", "live_security"}),
        ("MediaInternalExposureSuite", {"live", "live_security"}),
        ("ApiKeyRedisDegradedSuite", {"live", "live_security"}),
        (
            "DeploymentPreflightSuite",
            {"live", "live_security", "live_deployment"},
        ),
        ("CrossServiceTokenSuite", {"live", "live_asymmetric", "require_algorithm"}),
    ],
)
def test_suite_marks_are_exact(suite_name: str, expected: set[str]) -> None:
    assert _mark_names(_suites()[suite_name]) == expected
