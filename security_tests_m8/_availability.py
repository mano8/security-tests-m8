"""Treat live-target unavailability as a skip — never as a security finding.

A live security assertion only means something when the target actually answers.
When the reverse proxy has no route to the backend (Traefik replies with a bare
``404 page not found``), a gateway error occurs (``502``/``504``), or the host is
unreachable (connection refused / timeout), the response says nothing about the
strength of the auth boundary. Failing such a run raises a *false* CRITICAL
alarm — e.g. an "alg=none accepted" message produced by a Traefik 404 rather than
by any real weakness. The honest outcome is to skip.

The guard is armed only for the *call* phase of a live test (see
``plugin.pytest_runtest_call``). Preflight and fixture setup keep their own
explicit error handling and are never silently turned into skips.

``503`` is deliberately NOT treated as unavailability: several suites assert
``503`` as the *secure* fail-closed response (API-key verification while Redis is
down), so it is a real security signal rather than noise.
"""

from __future__ import annotations

import pytest
import requests

# Gateway statuses that only ever mean "the proxy could not reach the backend".
# 503 is excluded on purpose — it is an expected fail-closed security response.
_GATEWAY_DOWN_STATUSES = frozenset({502, 504})

# Traefik's plaintext body when no router matches the requested host/path.
_PROXY_404_MARKER = "404 page not found"

_guard_active = False


def set_guard_active(active: bool) -> None:
    """Arm or disarm the live-request availability guard."""
    global _guard_active
    _guard_active = active


def guard_active() -> bool:
    """Return whether the availability guard is currently armed."""
    return _guard_active


def unavailable_reason(response: requests.Response) -> str | None:
    """Return a human reason if *response* proves the target was unreachable.

    Returns ``None`` for every genuine application response — including an
    application ``404`` (JSON body) and a fail-closed ``503`` — so real security
    outcomes are never masked.
    """
    status = response.status_code
    if status in _GATEWAY_DOWN_STATUSES:
        return f"gateway HTTP {status} — backend unreachable behind the proxy"
    if status == 404:
        body = (response.text or "").strip().lower()
        # Guard against matching an application error page that merely mentions
        # the phrase: Traefik's no-route body is short and nothing else.
        if _PROXY_404_MARKER in body and len(body) <= 64:
            return "reverse proxy returned '404 page not found' — no route to backend"
    return None


def connection_error_reason(exc: requests.RequestException) -> str:
    """Return a human reason describing a failed connection to a live target."""
    return f"target unreachable — {type(exc).__name__}: {exc}"


def skip_unavailable(reason: str) -> None:
    """Skip the current test because the live target was unavailable."""
    pytest.skip(f"Live target unavailable — {reason}; not a security result")


def skip_if_unavailable(
    response: requests.Response, *, target: str = "target service"
) -> None:
    """Explicit helper: skip when *response* proves *target* was unavailable.

    The central guard already covers every live request, so suites rarely need
    this; it exists for call sites that want to state the intent locally.
    """
    reason = unavailable_reason(response)
    if reason is not None:
        skip_unavailable(f"{target}: {reason}")
