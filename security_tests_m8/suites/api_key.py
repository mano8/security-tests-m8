"""
Live Security Test Suite — API-key rate limiting during Redis outage (plan 11.3)
================================================================================
Target:  the auth service ``/profile/api-keys/verify`` endpoint
         (``LIVE_TEST_AUTH_BASE``) while Redis is deliberately unavailable.

API-key verification is rate limited through Redis. When Redis is down a
production/strict stack must **fail closed** — a valid key is refused with
``503 Service Unavailable`` rather than accepted without minute/hour/day limits
(which would silently drop the abuse controls). fa-auth-m8 makes strict API-key
rate limiting inherit ``ENVIRONMENT=production`` / ``STRICT_PRODUCTION_MODE`` /
``AUTH_STRICT_MODE`` (plan 11.3). Non-strict development stacks may fail open,
so this suite is **opt-in** and only asserts fail-closed behaviour when the
operator declares strict posture.

This complements the Redis-healthy API-key checks in ``ApiKeySuite`` (M03/M04),
which are ``require_redis`` and skip when Redis is down. This suite is their
mirror image: it runs *only* while Redis is degraded.

To run this suite:
  1. Bring up the target stack in strict posture with Redis stopped
     (or its circuit breaker open).
  2. Set ``LIVE_TEST_API_KEY`` to a known-valid plaintext key (minted before the
     outage — a stateful stack may be unable to log in to mint one during it).
  3. Set ``LIVE_TEST_API_KEY_STRICT_RATE_LIMIT=true`` to declare that fail-closed
     is expected, and ``LIVE_TEST_HEALTH_DETAIL_CREDENTIAL`` so the harness can
     read the degraded Redis state from ``/health`` detail.

    pytest -k ApiKeyRedisDegraded -v --no-cov

OPERATOR NOTE: if N01 fails because verify returned 200, the stack is accepting
valid API keys without rate limiting during the Redis outage. Confirm strict
posture (``API_KEY_STRICT_RATE_LIMIT`` inherits production/strict) so degraded
verification returns 503.
"""

from __future__ import annotations

import pytest
import requests

from security_tests_m8._config import get_config
from security_tests_m8._detection import detect_stack

pytestmark = [pytest.mark.live, pytest.mark.live_security]

_FIX = (
    "Fix: in production/strict, API-key rate limiting must fail closed when Redis "
    "is unavailable — return 503 instead of accepting the key. Ensure "
    "API_KEY_STRICT_RATE_LIMIT inherits production/strict mode (plan 11.3)."
)


def _guarded_verify_response() -> requests.Response:
    """Skip unless opted in + Redis is degraded, then probe the verify endpoint."""
    config = get_config()
    if not config.expect_api_key_fail_closed():
        pytest.skip(
            "Opt-in: set LIVE_TEST_API_KEY_STRICT_RATE_LIMIT=true to assert "
            "fail-closed API-key verification during a Redis outage"
        )
    headers = config.api_key_verify_headers()
    if not headers:
        pytest.skip(
            "Set LIVE_TEST_API_KEY to a known-valid plaintext key (minted before "
            "the Redis outage) to run the degraded API-key verification check"
        )
    stack = detect_stack()
    if not stack.reachable:
        pytest.skip("Live stack not reachable; start a stack or configure URLs")
    if not stack.detail_available:
        pytest.skip(
            "Redis status unknown — health detail unavailable; set "
            "LIVE_TEST_HEALTH_DETAIL_CREDENTIAL so the harness can confirm Redis "
            "is degraded before asserting fail-closed behaviour"
        )
    if stack.redis_ok:
        pytest.skip(
            "Redis is healthy; stop Redis (or open its circuit breaker) to exercise "
            "the degraded API-key path. Redis-healthy limits are covered by "
            "ApiKeySuite M03/M04"
        )
    return requests.get(
        f"{config.auth_base_url}/profile/api-keys/verify",
        headers=headers,
        timeout=config.timeout,
    )


class ApiKeyRedisDegradedSuite:
    """Category N — API-key verification must fail closed during a Redis outage."""

    @pytest.fixture
    def degraded_verify(self) -> requests.Response:
        """Verify a valid API key while Redis is degraded (opt-in; else skip)."""
        return _guarded_verify_response()

    def test_n01_valid_api_key_fails_closed_when_redis_degraded(
        self, degraded_verify: requests.Response
    ) -> None:
        """SECURITY PASS: valid API key is refused with 503 when Redis is down."""
        assert degraded_verify.status_code == 503, (
            "[SECURITY FAIL-N01] A valid API key returned "
            f"{degraded_verify.status_code} while Redis is degraded, expected 503. "
            f"{_FIX}"
        )

    def test_n02_degraded_verify_never_silently_allows(
        self, degraded_verify: requests.Response
    ) -> None:
        """SECURITY PASS: degraded verify never returns 200 with rate-limit headers.

        A 200 during the outage means the key was accepted without limits, and
        rate-limit headers would advertise a limit that Redis can no longer
        enforce. Both are silent loss of abuse controls.
        """
        assert degraded_verify.status_code != 200, (
            "[SECURITY FAIL-N02] API-key verification returned 200 during a Redis "
            "outage — the key was accepted without rate limiting. " + _FIX
        )
        lowered = {key.lower() for key in degraded_verify.headers}
        assert "x-ratelimit-limit" not in lowered, (
            "[SECURITY FAIL-N02] Degraded API-key verification advertised "
            "X-RateLimit-Limit while Redis cannot enforce it. " + _FIX
        )
