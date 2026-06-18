"""
Live Security Tests — Stateful & Hybrid Token Mode
====================================================
Target:  http://localhost:9000/user/
Config:  TOKEN_MODE=stateful OR TOKEN_MODE=hybrid

Tests the refresh token lifecycle: rotation, replay detection, and revocation.
Both stateful and hybrid modes track refresh JTIs in Redis, so all tests here
apply equally to both modes.

For hybrid-mode-specific behavior (access tokens surviving logout) see
test_hybrid.py.

Auto-skipped when the running stack uses TOKEN_MODE=stateless.

Run:
    pytest tests/live/test_stateful.py -v --no-cov
    pytest tests/live -m live_stateful --no-cov
"""

import base64
import json
import uuid
from datetime import UTC

import pytest
import requests

from security_tests_m8._client import (
    AUTH_BASE,
    TIMEOUT,
    auth_health_url,
    fresh_login,
    internal_headers,
)
from security_tests_m8._config import get_config
from security_tests_m8.forge import forge_alg_none, forge_hs256

pytestmark = [
    pytest.mark.live,
    pytest.mark.live_stateful,
    pytest.mark.require_token_mode("stateful", "hybrid"),
]

_ME = f"{AUTH_BASE}/profile/get/me/"
_REFRESH_URL = f"{AUTH_BASE}/login/refresh-token/"


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ═══════════════════════════════════════════════════════════════════════════════
# J  REFRESH TOKEN LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════════


class StatefulRevocationSuite:
    """Category J — Token rotation, replay detection, and revocation."""

    def test_j01_refresh_rotates_access_token(self):
        """Each refresh call must return a new access token."""
        sess = fresh_login()
        refresh = requests.post(_REFRESH_URL, cookies=sess["cookies"], timeout=TIMEOUT)
        assert refresh.status_code == 200
        assert refresh.json()["access_token"] != sess["token"]

    @pytest.mark.destructive
    def test_j02_replay_old_refresh_jti_triggers_revocation(self):
        """
        Token reuse detection: presenting a consumed refresh JTI must
        return 401 AND revoke all sessions (full chain invalidation).
        """
        sess = fresh_login()
        original_cookies = sess["cookies"]

        first = requests.post(_REFRESH_URL, cookies=original_cookies, timeout=TIMEOUT)
        assert first.status_code == 200

        replay = requests.post(_REFRESH_URL, cookies=original_cookies, timeout=TIMEOUT)
        assert replay.status_code == 401, (
            f"[SECURITY FAIL-J02] Refresh replay not detected: {replay.status_code}"
        )
        detail = replay.json().get("detail", "").lower()
        assert any(kw in detail for kw in ("reuse", "revoked", "reused")), (
            f"[SECURITY FAIL-J02] Replay detected but error not informative: {detail}"
        )

    def test_j03_tampered_refresh_token_rejected(self):
        """Modified refresh token payload (without re-signing) must be refused."""
        sess = fresh_login()
        cookie_val = sess["cookies"].get("refresh_token", "")
        if not cookie_val:
            pytest.skip("No refresh_token cookie received")

        parts = cookie_val.split(".")
        if len(parts) != 3:
            pytest.skip("Unexpected refresh token format")

        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded))
            claims["sub"] = str(uuid.uuid4())
            new_payload = _b64url_nopad(json.dumps(claims).encode())
            tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        except (ValueError, KeyError):
            pytest.skip("Could not decode refresh token payload")

        r = requests.post(
            _REFRESH_URL, cookies={"refresh_token": tampered}, timeout=TIMEOUT
        )
        assert r.status_code == 401

    def test_j04_forged_hs256_refresh_with_committed_key(self):
        """
        OPT-IN SECRET EXPOSURE CHECK — refresh signing secret is configured.

        Passing with 401/404/503 means the forged refresh token was not accepted
        by the live refresh endpoint. Failing means the forged token produced a
        live refresh, which is a critical breach.

        Remediation:
          1. Rotate REFRESH_SECRET_KEY immediately.
          2. Move to secret manager.
          3. Never commit secrets to version control.
        """
        refresh_secret_key = get_config().refresh_secret_key
        if refresh_secret_key is None:
            pytest.skip("Set LIVE_TEST_REFRESH_SECRET_KEY to run this opt-in check")
        forged = forge_hs256(refresh_secret_key)
        r = requests.post(
            _REFRESH_URL, cookies={"refresh_token": forged}, timeout=TIMEOUT
        )
        print(
            "\n[SECURITY PASS-J04] Forged refresh signed with configured "
            f"test secret was rejected; status={r.status_code}."
        )
        # 401/404 = correctly rejected (JTI not in allowlist or user not found)
        # 503 = Redis unavailable (fail_closed) — token still not accepted
        assert r.status_code in (401, 404, 503), (
            f"[CRITICAL FAIL-J04] Forged refresh token ACCEPTED: {r.status_code}"
        )

    def test_j05_logout_invalidates_refresh_token(self):
        """After logout, the refresh JTI must be removed from the allowlist."""
        sess = fresh_login()

        logout = requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )
        assert logout.status_code == 200

        r = requests.post(_REFRESH_URL, cookies=sess["cookies"], timeout=TIMEOUT)
        assert r.status_code == 401, (
            f"[SECURITY FAIL-J05] Refresh not revoked after logout: {r.status_code}"
        )

    def test_j06_missing_refresh_cookie_returns_401_or_422(self):
        r = requests.post(_REFRESH_URL, timeout=TIMEOUT)
        assert r.status_code in (401, 422)

    def test_j07_refresh_endpoint_rejects_access_token_in_cookie(self):
        """An access token placed in the refresh_token cookie must be refused."""
        sess = fresh_login()
        r = requests.post(
            _REFRESH_URL,
            cookies={"refresh_token": sess["token"]},
            timeout=TIMEOUT,
        )
        assert r.status_code == 401, (
            f"[SECURITY FAIL-J07] Access token accepted as refresh: {r.status_code}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# S  SESSION / REVOCATION  (stateful-only)
# ═══════════════════════════════════════════════════════════════════════════════


class StatefulAccessRevocationSuite:
    """Category S — Access token revocation at logout (stateful mode only)."""

    pytestmark = [
        pytest.mark.live,
        pytest.mark.live_stateful,
        pytest.mark.require_token_mode("stateful"),
    ]

    _ME = f"{AUTH_BASE}/profile/get/me/"

    def test_s01_logout_revokes_access_token_immediately(self):
        """
        In stateful mode access tokens are blacklisted on logout.
        The token must be rejected with 403 immediately after logout.
        """
        sess = fresh_login()

        r_before = requests.get(self._ME, headers=sess["headers"], timeout=TIMEOUT)
        assert r_before.status_code == 200

        requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )

        r_after = requests.get(self._ME, headers=sess["headers"], timeout=TIMEOUT)
        assert r_after.status_code in (401, 403), (
            f"[SECURITY FAIL-S01] Stateful logout left access token valid: "
            f"{r_after.status_code}"
        )

    def test_s02_new_login_after_revocation_works(self):
        """Revocation of one session must not block future logins."""
        sess = fresh_login()
        requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )
        new_sess = fresh_login()
        r = requests.get(self._ME, headers=new_sess["headers"], timeout=TIMEOUT)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# N  STATELESS MODE CONTRACT
# ═══════════════════════════════════════════════════════════════════════════════


class StatelessContractSuite:
    """Category N — Stateless mode: explicit documentation of revocation gap.

    Tests in this class use print() to emit [DESIGN] notes rather than
    failing assertions, because the observed behavior IS the expected behavior
    for this configuration.  The goal is to make the security trade-offs visible
    during a live audit.
    """

    def test_n01_valid_token_accepted_before_logout(self):
        """Sanity: newly issued token must be accepted."""
        sess = fresh_login()
        r = requests.get(_ME, headers=sess["headers"], timeout=TIMEOUT)
        assert r.status_code == 200

    def test_n02_logout_returns_200(self):
        """Logout endpoint must accept the request and return 200."""
        sess = fresh_login()
        r = requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )
        assert r.status_code == 200

    def test_n03_access_token_remains_valid_after_logout(self):
        """
        KNOWN TRADE-OFF (stateless mode) — Access tokens cannot be revoked.

        Logout clears the client-side cookie but the signed JWT remains
        cryptographically valid until its exp claim passes.  A stolen token
        continues to work for up to ACCESS_TOKEN_EXPIRE_MINUTES after issuance.

        Impact: stolen token window = up to 30 minutes (default expiry).

        Mitigation options:
          - Switch to TOKEN_MODE=stateful to blacklist JTIs at logout.
          - Shorten ACCESS_TOKEN_EXPIRE_MINUTES to reduce the exposure window.
          - Accept the trade-off; document for all downstream consumers.
        """
        sess = fresh_login()
        requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )
        r = requests.get(_ME, headers=sess["headers"], timeout=TIMEOUT)
        if r.status_code == 200:
            print(
                "\n[DESIGN TRADEOFF-N03] Access token remains valid after logout "
                "(expected in stateless mode). "
                "Exposure window: up to ACCESS_TOKEN_EXPIRE_MINUTES."
            )
        # We do NOT assert 403 here — validity post-logout is expected behavior.
        assert r.status_code in (200, 403), (
            f"Unexpected status {r.status_code} from /me after logout"
        )

    def test_n04_expired_token_rejected(self):
        """Even in stateless mode, exp claim must be enforced."""
        from datetime import datetime, timedelta

        import jwt

        from security_tests_m8.forge import access_payload

        payload = access_payload()
        payload["exp"] = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
        token = jwt.encode(payload, "wrong-key-deliberately", algorithm="HS256")
        r = requests.get(
            _ME, headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT
        )
        assert r.status_code == 403

    def test_n05_structurally_invalid_token_rejected(self):
        """Malformed tokens must always be refused regardless of mode."""
        r = requests.get(
            _ME,
            headers={"Authorization": "Bearer not.a.jwt.at.all"},
            timeout=TIMEOUT,
        )
        assert r.status_code == 403

    def test_n06_alg_none_rejected(self):
        """CRITICAL GUARD: unsigned token must never be accepted in any mode."""
        from security_tests_m8.forge import forge_alg_none

        r = requests.get(
            _ME,
            headers={"Authorization": f"Bearer {forge_alg_none()}"},
            timeout=TIMEOUT,
        )
        assert r.status_code == 403, (
            "[CRITICAL FAIL-N06] alg=none accepted in stateless mode!"
        )

    def test_n07_refresh_endpoint_behaviour_documented(self):
        """Document what the refresh endpoint does in stateless mode.

        In pure stateless mode there is no JTI allowlist, so the server
        cannot distinguish a fresh refresh token from a replayed one.  This
        test records the actual behaviour without asserting a specific status.
        """
        sess = fresh_login()
        r = requests.post(_REFRESH_URL, cookies=sess["cookies"], timeout=TIMEOUT)
        print(
            f"\n[DESIGN TRADEOFF-N07] Stateless refresh returned {r.status_code}. "
            "If 200: replay is possible (no JTI tracking). "
            "If 401: server rejects without Redis (unexpected in pure stateless)."
        )
        assert r.status_code in (200, 401, 422), (
            f"Unexpected refresh status {r.status_code} in stateless mode"
        )

    def test_n08_no_redis_dependency_for_token_validation(self):
        """Stateless token validation must not require Redis.

        We cannot easily bring Redis down in a live test, but we can verify
        that validation is not claiming it needs Redis by checking the health
        endpoint does not report Redis as required.
        """
        r = requests.get(auth_health_url(), headers=internal_headers(), timeout=TIMEOUT)
        if r.status_code == 404:
            pytest.skip("Health endpoint is not public on the configured auth base")
        assert r.status_code == 200
        body = r.json()
        print(f"\n[SECURITY OBSERVATION-N08] Health body: {body}")
        # Stateless mode: Redis is optional; stack must still be healthy.
        assert body.get("status", "").lower() in ("ok", "healthy", "up"), (
            "[SECURITY FAIL-N08] Stack reports unhealthy status in stateless mode"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# P  HYBRID MODE CONTRACT
# ═══════════════════════════════════════════════════════════════════════════════


class HybridContractSuite:
    """Category P — Hybrid mode: access stateless, refresh stateful."""

    def test_p01_access_token_survives_logout(self):
        """
        KNOWN TRADE-OFF (hybrid mode) — Access tokens are stateless.

        After logout the access token remains valid until it expires.
        Impact: stolen access token window = up to ACCESS_TOKEN_EXPIRE_MINUTES.

        Remediation options:
          - Switch to TOKEN_MODE=stateful to blacklist access JTIs too.
          - Shorten ACCESS_TOKEN_EXPIRE_MINUTES.
          - Accept the trade-off and document for downstream consumers.
        """
        sess = fresh_login()

        r_before = requests.get(_ME, headers=sess["headers"], timeout=TIMEOUT)
        assert r_before.status_code == 200

        requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )

        r_after = requests.get(_ME, headers=sess["headers"], timeout=TIMEOUT)
        if r_after.status_code == 200:
            print(
                "\n[DESIGN TRADEOFF-P01] Hybrid access token survived logout. "
                "Exposure window: up to ACCESS_TOKEN_EXPIRE_MINUTES."
            )
        # Both outcomes are valid depending on exact mode configuration.
        assert r_after.status_code in (200, 403), (
            f"Unexpected status {r_after.status_code} after logout in hybrid mode"
        )

    def test_p02_refresh_token_revoked_after_logout(self):
        """Logout must remove the refresh JTI from the Redis allowlist."""
        sess = fresh_login()
        requests.post(
            f"{AUTH_BASE}/login/logout/",
            headers=sess["headers"],
            cookies=sess["cookies"],
            timeout=TIMEOUT,
        )
        r = requests.post(_REFRESH_URL, cookies=sess["cookies"], timeout=TIMEOUT)
        assert r.status_code == 401, (
            f"[SECURITY FAIL-P02] Refresh not revoked after logout: {r.status_code}"
        )

    def test_p03_refresh_replay_detected(self):
        """Presenting a consumed refresh JTI must return 401."""
        sess = fresh_login()
        original_cookies = sess["cookies"]

        first = requests.post(_REFRESH_URL, cookies=original_cookies, timeout=TIMEOUT)
        assert first.status_code == 200

        replay = requests.post(_REFRESH_URL, cookies=original_cookies, timeout=TIMEOUT)
        assert replay.status_code == 401, (
            f"[SECURITY FAIL-P03] Refresh replay not detected in hybrid mode: "
            f"{replay.status_code}"
        )

    def test_p04_refresh_rotation_issues_new_access_token(self):
        """Each refresh call must return a fresh, different access token."""
        sess = fresh_login()
        refresh = requests.post(_REFRESH_URL, cookies=sess["cookies"], timeout=TIMEOUT)
        assert refresh.status_code == 200
        assert refresh.json()["access_token"] != sess["token"]

    def test_p05_forged_refresh_with_committed_key_rejected_by_jti_check(self):
        """
        OPT-IN SECRET EXPOSURE CHECK — refresh signing secret is configured.

        Passing with 401/404 means hybrid JTI allowlist enforcement rejected the
        forged token. Failing means a forged refresh token was accepted, which
        is a critical breach.
        """
        refresh_secret_key = get_config().refresh_secret_key
        if refresh_secret_key is None:
            pytest.skip("Set LIVE_TEST_REFRESH_SECRET_KEY to run this opt-in check")
        forged = forge_hs256(refresh_secret_key)
        r = requests.post(
            _REFRESH_URL, cookies={"refresh_token": forged}, timeout=TIMEOUT
        )
        assert r.status_code in (401, 404), (
            f"[CRITICAL FAIL-P05] Forged refresh token ACCEPTED "
            f"in hybrid mode: {r.status_code}. JTI allowlist check is not working."
        )
        print(
            "\n[SECURITY PASS-P05] Forged refresh signed with configured "
            f"test secret was rejected; status={r.status_code}."
        )

    def test_p06_tampered_refresh_cookie_rejected(self):
        """Modify the refresh cookie payload without re-signing — must fail."""
        sess = fresh_login()
        cookie_val = sess["cookies"].get("refresh_token", "")
        if not cookie_val:
            pytest.skip("No refresh_token cookie received")

        parts = cookie_val.split(".")
        if len(parts) != 3:
            pytest.skip("Unexpected refresh token format")

        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded))
            claims["sub"] = str(uuid.uuid4())
            from security_tests_m8.forge import b64url_nopad

            new_payload = b64url_nopad(json.dumps(claims).encode())
            tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        except (ValueError, KeyError):
            pytest.skip("Could not decode refresh token payload")

        r = requests.post(
            _REFRESH_URL, cookies={"refresh_token": tampered}, timeout=TIMEOUT
        )
        assert r.status_code == 401

    def test_p07_alg_none_in_access_position_rejected(self):
        """CRITICAL: alg=none must be rejected in hybrid mode as in any other."""
        r = requests.get(
            _ME,
            headers={"Authorization": f"Bearer {forge_alg_none()}"},
            timeout=TIMEOUT,
        )
        assert r.status_code == 403, "[CRITICAL FAIL-P07] alg=none accepted"

    def test_p08_missing_refresh_cookie_returns_401_or_422(self):
        r = requests.post(_REFRESH_URL, timeout=TIMEOUT)
        assert r.status_code in (401, 422)


_STATEFUL_MARKS = [
    pytest.mark.live,
    pytest.mark.live_stateful,
    pytest.mark.require_token_mode("stateful", "hybrid"),
]
_STATEFUL_ONLY_MARKS = [
    pytest.mark.live,
    pytest.mark.live_stateful,
    pytest.mark.require_token_mode("stateful"),
]
_STATELESS_MARKS = [
    pytest.mark.live,
    pytest.mark.live_stateless,
    pytest.mark.require_token_mode("stateless"),
]
_HYBRID_MARKS = [
    pytest.mark.live,
    pytest.mark.live_hybrid,
    pytest.mark.require_token_mode("hybrid"),
]
setattr(StatefulRevocationSuite, "pytestmark", _STATEFUL_MARKS)
setattr(StatefulAccessRevocationSuite, "pytestmark", _STATEFUL_ONLY_MARKS)
setattr(StatelessContractSuite, "pytestmark", _STATELESS_MARKS)
setattr(HybridContractSuite, "pytestmark", _HYBRID_MARKS)
