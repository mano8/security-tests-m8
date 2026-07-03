"""Unit tests for the live-target availability guard.

These verify the pure detection logic that keeps an unavailable service from ever
surfacing as a security finding: proxy-down signals become skips, while genuine
application responses (including a fail-closed ``503`` and an application ``404``)
are passed through untouched.
"""

from __future__ import annotations

import pytest
import requests

from security_tests_m8 import _availability


def _response(status_code: int, text: str = "") -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = text.encode()
    return response


@pytest.mark.parametrize("status", [502, 504])
def test_gateway_down_statuses_are_unavailable(status: int) -> None:
    reason = _availability.unavailable_reason(_response(status))
    assert reason is not None
    assert str(status) in reason


def test_traefik_no_route_404_is_unavailable() -> None:
    reason = _availability.unavailable_reason(_response(404, "404 page not found\n"))
    assert reason is not None
    assert "no route" in reason


def test_application_404_json_is_not_unavailable() -> None:
    assert _availability.unavailable_reason(_response(404, '{"detail":"Not Found"}')) is None


def test_long_body_mentioning_phrase_is_not_unavailable() -> None:
    body = "Our custom error page: 404 page not found. " + "x" * 100
    assert _availability.unavailable_reason(_response(404, body)) is None


@pytest.mark.parametrize("status", [200, 401, 403, 503])
def test_real_security_statuses_are_not_unavailable(status: int) -> None:
    # 503 in particular must pass through: fail-closed suites assert it as secure.
    assert _availability.unavailable_reason(_response(status)) is None


def test_skip_if_unavailable_skips_only_when_down() -> None:
    _availability.skip_if_unavailable(_response(403), target="svc")  # no skip
    with pytest.raises(pytest.skip.Exception):
        _availability.skip_if_unavailable(_response(502), target="svc")


def test_guard_flag_toggles() -> None:
    assert _availability.guard_active() is False
    _availability.set_guard_active(True)
    try:
        assert _availability.guard_active() is True
    finally:
        _availability.set_guard_active(False)
    assert _availability.guard_active() is False
