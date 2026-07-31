"""Unit-layer signature-bypass regression check (3.9).

The live superuser-probe canary tests (`test_b04b_*`, `test_b02b_*`,
`test_b04b_forged_token_with_committed_key_rejected_by_probe`,
`test_h01b_*`) assert that a canonical forged (`is_superuser=True`,
`role="superadmin"`) token is rejected by
`GET {API_PREFIX}/security/superuser-probe`. Against a live stack that
assertion only proves something if the suite is actually capable of *failing*
when the token is wrongly accepted.

This module proves that capability without a live exploitable mode: it
monkeypatches the HTTP layer with a deliberately permissive fake validator —
one that always answers as if the forged token's signature were accepted —
and asserts the same suite methods now raise ``AssertionError``. This is a
mutation-test fixture at the unit layer only; no real service is contacted
and no live signing bypass is introduced anywhere.

Imports of ``security_tests_m8.suites`` are deferred into each test function
(after ``configure(service_base_url=...)``) because importing the package
evaluates every suite's class-level URL attributes, including
``CrossServiceTokenSuite``'s, which otherwise raises ``LookupError`` without a
configured service base URL — the same reason ``configure()`` precedes
``list-suites`` in ``tests/test_cli.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from security_tests_m8 import configure


class _BypassedResponse:
    """Fake HTTP response simulating an accepted (bypassed) forged token."""

    status_code = 200

    def json(self) -> dict[str, object]:
        return {"authorized": True}


def _bypassed_get(*_args: Any, **_kwargs: Any) -> _BypassedResponse:
    return _BypassedResponse()


@pytest.fixture(autouse=True)
def _configured_service_url() -> None:
    configure(service_base_url="http://service")


def test_universal_probe_canary_fails_when_signature_check_is_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If alg=none were wrongly accepted, the probe-canary assertion must fail."""
    from security_tests_m8.suites import universal

    monkeypatch.setattr(universal.requests, "get", _bypassed_get)
    suite = universal.JWTStructuralSuite()
    with pytest.raises(AssertionError):
        suite.test_b04b_alg_none_forged_superuser_rejected_by_probe()


def test_algorithms_alg_confusion_probe_canary_fails_when_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If HS256/pubkey confusion were wrongly accepted, the assertion must fail."""
    from security_tests_m8.suites import algorithms

    monkeypatch.setattr(algorithms.requests, "get", _bypassed_get)
    suite = algorithms.AsymmetricJWTSuite()
    with pytest.raises(AssertionError):
        suite.test_b02b_algorithm_confusion_hs256_pubkey_rejected_by_probe(
            public_key_pem="irrelevant-pem"
        )


def test_algorithms_committed_key_probe_canary_fails_when_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a repo-key forgery were wrongly accepted, the assertion must fail."""
    from security_tests_m8.suites import algorithms

    monkeypatch.setattr(algorithms.requests, "get", _bypassed_get)
    suite = algorithms.AsymmetricJWTSuite()
    with pytest.raises(AssertionError):
        suite.test_b04b_forged_token_with_committed_key_rejected_by_probe(
            committed_key_forge=lambda **_kwargs: "stub-token"
        )


def test_algorithms_hs256_wrong_secret_probe_canary_fails_when_bypassed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a wrong-secret HS256 token were wrongly accepted, the assertion must fail."""
    from security_tests_m8.suites import algorithms

    monkeypatch.setattr(algorithms.requests, "get", _bypassed_get)
    suite = algorithms.HS256Suite()
    with pytest.raises(AssertionError):
        suite.test_h01b_wrong_secret_forged_superuser_rejected_by_probe()
