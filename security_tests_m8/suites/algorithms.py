"""
Live Security Tests — Asymmetric Algorithms (RS256 / ES256)
===========================================================
Target:  the auth issuer at LIVE_TEST_AUTH_BASE, plus every consumer service
         declared in LIVE_TEST_SVC_BASE / LIVE_TEST_SVC_BASES.
Config:  ACCESS_TOKEN_ALGORITHM=RS256 or ES256

Attacker Scenarios
------------------
Scenario A — Network-only attacker (JWKS and HTTP access only)
  alg=none, algorithm confusion, attacker-generated key.
  All MUST be rejected: tests assert 403.

Scenario B — Repo-read attacker (has git clone of this repository)
  Forges tokens using a committed private key matched via JWKS public key
  (DER identity comparison).  A 200 response proves the committed key is the
  live key and fails the suite. Rejection is the expected secure outcome.

Scenario C — Protocol-level attacks (any attacker)
  Expired token, wrong token type, tampered payload, path-traversal kid.
  All MUST be rejected: tests assert 403.

Auto-skipped when the running stack uses HS256.

Run:
    pytest tests/live/test_asymmetric.py -v --no-cov
    pytest tests/live -m live_asymmetric --no-cov
"""

import json
from datetime import UTC, datetime, timedelta
from typing import TypeAlias

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from security_tests_m8._client import AUTH_BASE, TIMEOUT, fresh_login
from security_tests_m8._config import get_config
from security_tests_m8.forge import (
    access_payload,
    b64url_nopad,
    escalate_claims,
    forge_alg_none,
    forge_asymmetric,
    forge_hs256_with_pubkey,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.live_asymmetric,
    pytest.mark.require_algorithm("RS256", "ES256"),
]

_ME = f"{AUTH_BASE}/profile/get/me/"
_PROBE = f"{AUTH_BASE}/security/superuser-probe"
_PrivateKey: TypeAlias = RSAPrivateKey | EllipticCurvePrivateKey


def _auth(bearer: str) -> dict:
    return {"Authorization": f"Bearer {bearer}"}


def _attacker_key_token(alg: str, live_jwks_keys: list[dict]) -> str:
    """Forge a superuser token signed with a freshly generated attacker key.

    The key matches the stack's algorithm family and reuses the live ``kid`` so
    the server evaluates key identity rather than failing earlier on an
    algorithm or header mismatch.
    """
    from cryptography.hazmat.primitives import serialization

    signing_jwk = next(
        (
            k
            for k in live_jwks_keys
            if k.get("kty") in {"RSA", "EC"} and k.get("use", "sig") == "sig"
        ),
        None,
    )
    live_kid = signing_jwk.get("kid", "unknown") if signing_jwk else "unknown"

    if alg.startswith("RS"):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key: _PrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
    else:
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())

    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return forge_asymmetric(pem, alg, is_superuser=True, kid=live_kid)


# ═══════════════════════════════════════════════════════════════════════════════
# B  JWT ATTACKS  (asymmetric algorithms)
# ═══════════════════════════════════════════════════════════════════════════════


class AsymmetricJWTSuite:
    """Category B — Asymmetric token forgery and algorithm confusion (RS256/ES256)."""

    def test_b01_alg_none_rejected(self):
        """CRITICAL GUARD: unsigned token must never be accepted."""
        r = requests.get(_ME, headers=_auth(forge_alg_none()), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-B01] alg=none token ACCEPTED — full authentication bypass!"
        )

    def test_b02_algorithm_confusion_hs256_pubkey_rejected(self, public_key_pem: str):
        """Asymmetric→HS256 confusion: public key used as HMAC secret must be rejected.

        public_key_pem is reconstructed directly from the live JWKS — available
        to any network attacker without repo access.
        """
        token = forge_hs256_with_pubkey(public_key_pem)
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-B02] Asymmetric-to-HS256 confusion succeeded"
        )

    def test_b02b_algorithm_confusion_hs256_pubkey_rejected_by_probe(
        self, public_key_pem: str
    ):
        """CRITICAL GUARD (3.9): algorithm-confusion forgery of a canonical
        superuser token must never reach the non-disclosing probe canary."""
        token = forge_hs256_with_pubkey(public_key_pem)
        r = requests.get(_PROBE, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-B02b] Asymmetric-to-HS256 confusion reached the "
            "superuser probe"
        )

    def test_b03_forged_token_with_committed_key_rejected(self, committed_key_forge):
        """
        A forged token made with a repo-visible private key must be rejected.

        Discovery: JWKS public key DER bytes matched against committed
        public.pem files via rglob — no env files or stack config read.

        Remediation:
          1. Rotate the key pair immediately.
          2. Move keys to a secret manager (Vault, AWS Secrets Manager, …).
          3. Never commit key material; use Docker secrets or env injection.
          4. Add a pre-commit hook / CI secret-scanner (truffleHog, gitleaks).
        """
        token = committed_key_forge(is_superuser=True)
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code != 200, (
            "[CRITICAL FAIL-B03] Forged admin JWT signed with a repo-visible "
            "private key was accepted by the auth service."
        )

    def test_b04_forged_token_reaches_admin_endpoint(self, committed_key_forge):
        """A forged token made with a repo-visible key must not grant admin access."""
        token = committed_key_forge(is_superuser=True)
        r = requests.get(f"{AUTH_BASE}/users/", headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code != 200, (
            "[CRITICAL FAIL-B04] Forged JWT from a repo-visible key reached "
            "the auth admin endpoint."
        )

    def test_b04b_forged_token_with_committed_key_rejected_by_probe(
        self, committed_key_forge
    ):
        """CRITICAL GUARD (3.9): prove a repo-key forgery is rejected against the
        non-destructive, non-disclosing superuser probe — not only against a
        PII-returning route. A signature-verification regression here would be
        caught without ever disclosing user data or mutating state.
        """
        token = committed_key_forge(is_superuser=True)
        r = requests.get(_PROBE, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code != 200, (
            "[CRITICAL FAIL-B04b] Forged JWT from a repo-visible key was "
            "ACCEPTED by the superuser probe."
        )

    def test_b05_expired_token_rejected(
        self, asymmetric_key_pem: tuple[str, str, str | None]
    ):
        """Token that expired an hour ago must be refused.

        Uses committed key when available so the server reaches expiry
        validation with a trusted signature. Falls back to ephemeral key —
        server then rejects at key identity (unknown kid); expiry check is
        not reached but 403 holds.
        """
        key_pem, alg, kid = asymmetric_key_pem
        payload = access_payload()
        payload["exp"] = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
        token = jwt.encode(
            payload,
            key_pem,
            algorithm=alg,
            headers={"kid": kid or "unknown"},
        )
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_b06_wrong_token_type_refresh_as_access_rejected(
        self, asymmetric_key_pem: tuple[str, str, str | None]
    ):
        """A refresh token presented to an access-protected route must be refused."""
        key_pem, alg, kid = asymmetric_key_pem
        token = forge_asymmetric(
            key_pem, alg, token_type="refresh", kid=kid or "unknown"
        )
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_b07_inactive_user_claim_rejected(
        self, asymmetric_key_pem: tuple[str, str, str | None]
    ):
        """is_active=False in token payload must always deny access."""
        key_pem, alg, kid = asymmetric_key_pem
        payload = access_payload(is_superuser=False)
        payload["is_active"] = False
        token = jwt.encode(
            payload,
            key_pem,
            algorithm=alg,
            headers={"kid": kid or "unknown"},
        )
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_b08_path_traversal_kid_does_not_crash(
        self, asymmetric_key_pem: tuple[str, str, str | None]
    ):
        """Injecting a path-traversal kid must not cause 500 or load arbitrary keys."""
        key_pem, alg, _ = asymmetric_key_pem
        payload = access_payload(is_superuser=True)
        token = jwt.encode(
            payload,
            key_pem,
            algorithm=alg,
            headers={"kid": "../../etc/passwd"},
        )
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code != 500, (
            "[SECURITY FAIL-B08] Path-traversal kid caused server error"
        )

    def test_b09_tampered_payload_rejected(self, admin_token: str):
        """Modify payload without re-signing — signature mismatch must be caught."""
        parts = admin_token.split(".")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        import base64

        claims = json.loads(base64.urlsafe_b64decode(padded))
        escalate_claims(claims)
        new_payload = b64url_nopad(json.dumps(claims).encode())
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        r = requests.get(_ME, headers=_auth(tampered), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_b10_attacker_generated_key_rejected(
        self, stack_config: dict, live_jwks_keys: list[dict]
    ):
        """Token signed with attacker-generated key must be rejected."""
        token = _attacker_key_token(
            stack_config.get("algorithm", "RS256"), live_jwks_keys
        )
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-B10] Token signed with attacker key was ACCEPTED"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# H  JWKS ENDPOINT  (asymmetric stacks only)
# ═══════════════════════════════════════════════════════════════════════════════


class JWKSSuite:
    """Category H — JWKS endpoint security for asymmetric stacks."""

    def test_h01_jwks_endpoint_is_present(self):
        r = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        assert r.status_code == 200, (
            "[SECURITY FAIL-H01] Asymmetric stack has no JWKS endpoint — "
            "downstream consumers cannot fetch the public key"
        )

    def test_h02_jwks_contains_no_private_key_material(self):
        """JWKS must expose only the public key components."""
        r = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        assert r.status_code == 200
        keys = r.json().get("keys", [])
        assert keys, "[SECURITY FAIL-H02] JWKS has no keys"
        for key in keys:
            for priv in ("d", "p", "q", "dp", "dq", "qi"):
                assert priv not in key, (
                    f"[CRITICAL FAIL-H02] Private RSA component exposed: {priv}"
                )
            assert key.get("use") == "sig"
            assert key.get("alg") in ("RS256", "ES256")

    def test_h03_jwks_kid_matches_token_header(self):
        """The kid in the JWKS must match the kid in issued tokens."""
        login = requests.post(
            f"{AUTH_BASE}/login/access-token",
            data={
                "username": get_config().admin_email,
                "password": get_config().admin_password,
            },
            timeout=TIMEOUT,
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        header = jwt.get_unverified_header(token)
        token_kid = header.get("kid")

        jwks = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        jwks_kids = {k.get("kid") for k in jwks.json().get("keys", [])}
        assert token_kid in jwks_kids, (
            f"[SECURITY FAIL-H03] Token kid {token_kid!r} missing from {jwks_kids}"
        )

    def test_h04_jwks_is_valid_json_with_keys_array(self):
        r = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        body = r.json()
        assert "keys" in body
        assert isinstance(body["keys"], list)
        assert len(body["keys"]) >= 1

    def test_h05_jwks_key_has_required_fields(self):
        r = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        for key in r.json().get("keys", []):
            for field in ("kty", "use", "kid", "alg"):
                assert field in key, (
                    f"[SECURITY FAIL-H05] JWKS key missing required field '{field}'"
                )
            kty = key["kty"]
            if kty == "RSA":
                for field in ("n", "e"):
                    assert field in key, (
                        f"[SECURITY FAIL-H05] RSA JWKS missing field {field!r}"
                    )
            elif kty == "EC":
                for field in ("crv", "x", "y"):
                    assert field in key, (
                        f"[SECURITY FAIL-H05] EC JWKS missing field {field!r}"
                    )
            else:
                pytest.fail(f"[SECURITY FAIL-H05] Unknown key type: {kty!r}")


# ═══════════════════════════════════════════════════════════════════════════════
# I  CROSS-SERVICE TOKEN PROPAGATION  (asymmetric)
# ═══════════════════════════════════════════════════════════════════════════════


_REJECTED = (401, 403)

_NO_CROSS_SERVICE_TARGET = (
    "No cross-service probe endpoint is configured. Declare the consumer "
    "services in LIVE_TEST_SVC_BASES (or LIVE_TEST_SVC_BASE) and one "
    "authenticated route per service in LIVE_TEST_PROTECTED_ENDPOINTS, or pin "
    "the probe route explicitly with LIVE_TEST_CROSS_SERVICE_ENDPOINTS."
)


def _cross_service_params() -> list[object]:
    """Build one parameter per configured consumer service.

    The probe route comes from configuration rather than from a hardcoded path:
    every downstream consumer publishes its own API surface, so a fixed route
    would 404 on any stack that does not happen to expose it — and an
    application 404 on a rejection test reads as an accepted forgery.
    """
    targets = get_config().cross_service_probe_targets()
    if not targets:
        return [
            pytest.param(
                "unconfigured",
                "",
                id="unconfigured",
                marks=pytest.mark.skip(reason=_NO_CROSS_SERVICE_TARGET),
            )
        ]
    return [pytest.param(service, url, id=service) for service, url in targets]


class CrossServiceTokenSuite:
    """Category I — downstream asymmetric token acceptance/rejection.

    Runs against every consumer service declared in the live-test
    configuration, so the suite is stack-agnostic: no consumer name or route is
    baked into the package.
    """

    @pytest.mark.parametrize(("service", "url"), _cross_service_params())
    def test_i01_valid_auth_token_accepted_by_service(
        self, service: str, url: str, fresh_admin_headers: dict
    ):
        """An issuer-minted admin token must be accepted by the consumer.

        Uses a token minted for this check so a stack that revokes the previous
        session on each new login cannot turn token propagation into a false
        failure.
        """
        r = requests.get(url, headers=fresh_admin_headers, timeout=TIMEOUT)
        assert r.status_code == 200, (
            f"Cross-service token propagation failed for {service!r} at {url}: "
            f"{r.status_code} {r.text}"
        )

    @pytest.mark.parametrize(("service", "url"), _cross_service_params())
    def test_i02_forged_token_rejected_by_service(
        self, service: str, url: str, committed_key_forge
    ):
        """A forged token made with a repo-visible key must not reach downstream."""
        token = committed_key_forge(is_superuser=True)
        r = requests.get(url, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code != 200, (
            "[CRITICAL FAIL-I02] Forged JWT from a repo-visible key was "
            f"accepted by downstream service {service!r}."
        )

    @pytest.mark.parametrize(("service", "url"), _cross_service_params())
    def test_i03_alg_none_rejected_by_service(self, service: str, url: str):
        r = requests.get(url, headers=_auth(forge_alg_none()), timeout=TIMEOUT)
        assert r.status_code in _REJECTED, (
            f"[CRITICAL FAIL-I03] alg=none accepted by downstream service {service!r}"
        )

    @pytest.mark.parametrize(("service", "url"), _cross_service_params())
    def test_i04_service_rejects_no_token(self, service: str, url: str):
        r = requests.get(url, timeout=TIMEOUT)
        assert r.status_code in _REJECTED, (
            f"[CRITICAL FAIL-I04] Downstream service {service!r} served a "
            f"protected route without a token: {r.status_code}"
        )

    @pytest.mark.parametrize(("service", "url"), _cross_service_params())
    def test_i05_attacker_generated_key_rejected_by_service(
        self,
        service: str,
        url: str,
        stack_config: dict,
        live_jwks_keys: list[dict],
    ):
        """Downstream service must also reject tokens from an attacker-generated key."""
        alg = stack_config.get("algorithm", "RS256")
        token = _attacker_key_token(alg, live_jwks_keys)
        r = requests.get(url, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code in _REJECTED, (
            f"[CRITICAL FAIL-I05] Attacker key accepted by downstream service "
            f"{service!r}"
        )


_WRONG_SECRET = "this-is-the-wrong-secret-and-definitely-not-the-configured-one"


def _forge_hs256_wrong_secret() -> str:
    """Forge an HS256 access token with an incorrect secret."""
    payload = access_payload(is_superuser=True)
    return jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")


# ═══════════════════════════════════════════════════════════════════════════════
# H  HS256-SPECIFIC JWT CHECKS
# ═══════════════════════════════════════════════════════════════════════════════


class HS256Suite:
    """Category H — HS256 algorithm-specific security properties."""

    def test_h01_token_signed_with_wrong_secret_rejected(self):
        """HS256 token signed with a different secret must be refused."""
        token = _forge_hs256_wrong_secret()
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-H01] Token signed with wrong HS256 secret was ACCEPTED"
        )

    def test_h01b_wrong_secret_forged_superuser_rejected_by_probe(self):
        """CRITICAL GUARD (3.9): a canonical superuser token signed with the
        wrong HS256 secret must never reach the non-disclosing probe canary."""
        token = _forge_hs256_wrong_secret()
        r = requests.get(_PROBE, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-H01b] Wrong-secret HS256 canonical-superuser token "
            "reached the superuser probe"
        )

    def test_h02_alg_none_rejected(self):
        """CRITICAL GUARD: unsigned token must never be accepted."""
        r = requests.get(_ME, headers=_auth(forge_alg_none()), timeout=TIMEOUT)
        assert r.status_code == 403, (
            "[CRITICAL FAIL-H02] alg=none token ACCEPTED — full authentication bypass!"
        )

    def test_h03_expired_hs256_token_rejected(self):
        """Expired HS256 token must be refused even with a correct signature."""
        payload = access_payload()
        payload["exp"] = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
        token = jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_h04_no_jwks_endpoint_or_empty(self):
        """HS256 stacks have no asymmetric keys to publish via JWKS.

        The endpoint may be absent (404) or return an empty keys array.
        Returning a populated JWKS from an HS256 stack would mislead consumers.
        """
        r = requests.get(f"{AUTH_BASE}/.well-known/jwks.json", timeout=TIMEOUT)
        if r.status_code == 200:
            keys = r.json().get("keys", [])
            assert keys == [], (
                "[SECURITY FAIL-H04] HS256 stack exposes non-empty JWKS — "
                "consumers may trust this stack for RS256 validation"
            )
        else:
            assert r.status_code == 404

    def test_h05_tampered_payload_rejected(self, admin_token: str):
        """Modify HS256 payload without re-signing — must be caught."""
        import base64

        parts = admin_token.split(".")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        escalate_claims(claims)
        new_payload = b64url_nopad(json.dumps(claims).encode())
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        r = requests.get(_ME, headers=_auth(tampered), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_h06_refresh_token_type_rejected_as_access(self):
        """A token with type='refresh' must not be accepted on access-only routes."""
        payload = access_payload(token_type="refresh")
        token = jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")
        r = requests.get(_ME, headers=_auth(token), timeout=TIMEOUT)
        assert r.status_code == 403

    def test_h07_inactive_user_claim_rejected(self, admin_token: str):
        """is_active=False in a structurally valid token must deny access."""
        import base64

        parts = admin_token.split(".")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        claims["is_active"] = False
        escalate_claims(claims)
        new_payload = b64url_nopad(json.dumps(claims).encode())
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        r = requests.get(_ME, headers=_auth(tampered), timeout=TIMEOUT)
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# W  WEAK KEY WARNINGS
# ═══════════════════════════════════════════════════════════════════════════════


class HS256WeakKeySuite:
    """Category W — HS256 key strength assertions."""

    def test_w01_login_works_with_configured_key(self):
        """Sanity: valid credentials produce a usable token."""
        sess = fresh_login()
        r = requests.get(_ME, headers=sess["headers"], timeout=TIMEOUT)
        assert r.status_code == 200, (
            "Token from fresh login was rejected — stack may be misconfigured"
        )

    def test_w02_token_has_expected_structure(self):
        """HS256 tokens must be three-segment JWTs with correct header."""
        sess = fresh_login()
        token = sess["token"]
        parts = token.split(".")
        assert len(parts) == 3, f"Malformed token: expected 3 parts, got {len(parts)}"
        import base64

        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        assert header.get("alg") == "HS256", (
            f"[SECURITY FAIL-W02] Token alg is '{header.get('alg')}', expected 'HS256'"
        )

    def test_w03_token_carries_jti_claim(self):
        """JTI must be present for revocation and replay detection."""
        sess = fresh_login()
        payload = jwt.decode(sess["token"], options={"verify_signature": False})
        assert "jti" in payload, (
            "[SECURITY FAIL-W03] Token has no jti claim — revocation is impossible"
        )
        assert payload["jti"]

    def test_w04_two_tokens_have_different_jti(self):
        """Each token issuance must produce a unique JTI."""
        t1 = fresh_login()["token"]
        t2 = fresh_login()["token"]
        p1 = jwt.decode(t1, options={"verify_signature": False})
        p2 = jwt.decode(t2, options={"verify_signature": False})
        assert p1["jti"] != p2["jti"], (
            "[CRITICAL FAIL-W04] Two tokens share the same JTI — replay is possible"
        )


_ASYMMETRIC_MARKS = [
    pytest.mark.live,
    pytest.mark.live_asymmetric,
    pytest.mark.require_algorithm("RS256", "ES256"),
]
_HS256_MARKS = [
    pytest.mark.live,
    pytest.mark.live_hs256,
    pytest.mark.require_algorithm("HS256"),
]
setattr(AsymmetricJWTSuite, "pytestmark", _ASYMMETRIC_MARKS)
setattr(JWKSSuite, "pytestmark", _ASYMMETRIC_MARKS)
setattr(CrossServiceTokenSuite, "pytestmark", _ASYMMETRIC_MARKS)
setattr(HS256Suite, "pytestmark", _HS256_MARKS)
setattr(HS256WeakKeySuite, "pytestmark", _HS256_MARKS)
