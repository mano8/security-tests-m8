import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from security_tests_m8.forge import (
    CANONICAL_SUPERUSER_ROLE,
    DEFAULT_ROLE,
    access_payload,
    canonical_role_for,
    escalate_claims,
    forge_alg_none,
    forge_asymmetric,
    forge_es256,
    forge_hs256,
    forge_hs256_with_pubkey,
    forge_rs256,
    resolve_claim_pair,
)


def _decode_segment(segment: str) -> dict[str, object]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def test_access_payload_contains_security_claims() -> None:
    payload = access_payload(is_superuser=True, iss="issuer", aud="audience")

    assert payload["is_superuser"] is True
    assert payload["type"] == "access"
    assert payload["iss"] == "issuer"
    assert payload["aud"] == "audience"
    assert payload["jti"]
    assert isinstance(payload["exp"], int)
    assert isinstance(payload["iat"], int)
    assert payload["exp"] > payload["iat"]


def test_canonical_role_for_pairs_flag_with_role() -> None:
    assert canonical_role_for(True) == CANONICAL_SUPERUSER_ROLE
    assert canonical_role_for(False) == DEFAULT_ROLE


def test_access_payload_is_canonical_by_default() -> None:
    default = access_payload()
    superuser = access_payload(is_superuser=True)
    plain = access_payload(is_superuser=False)

    assert (default["is_superuser"], default["role"]) == (False, DEFAULT_ROLE)
    assert (superuser["is_superuser"], superuser["role"]) == (
        True,
        CANONICAL_SUPERUSER_ROLE,
    )
    assert (plain["is_superuser"], plain["role"]) == (False, DEFAULT_ROLE)


def test_access_payload_derives_flag_from_role() -> None:
    superuser = access_payload(role="SuperAdmin ")
    reader = access_payload(role="user")

    assert superuser["is_superuser"] is True
    assert superuser["role"] == "SuperAdmin "
    assert reader["is_superuser"] is False


def test_access_payload_accepts_consistent_explicit_pair() -> None:
    payload = access_payload(is_superuser=True, role=CANONICAL_SUPERUSER_ROLE)

    assert payload["is_superuser"] is True
    assert payload["role"] == CANONICAL_SUPERUSER_ROLE


def test_access_payload_rejects_inconsistent_pair_without_opt_in() -> None:
    with pytest.raises(ValueError, match="Inconsistent privilege claims"):
        access_payload(is_superuser=True, role="user")


def test_access_payload_inconsistent_pair_requires_explicit_opt_in() -> None:
    payload = access_payload(
        is_superuser=True, role="user", allow_inconsistent_claims=True
    )

    assert payload["is_superuser"] is True
    assert payload["role"] == "user"


def test_resolve_claim_pair_returns_derived_pair() -> None:
    assert resolve_claim_pair() == (False, DEFAULT_ROLE)
    assert resolve_claim_pair(is_superuser=True) == (True, CANONICAL_SUPERUSER_ROLE)
    assert resolve_claim_pair(role="admin") == (False, "admin")


def test_escalate_claims_sets_canonical_pair() -> None:
    claims: dict[str, object] = {"is_superuser": False, "role": "user"}

    assert escalate_claims(claims) is claims
    assert claims["is_superuser"] is True
    assert claims["role"] == CANONICAL_SUPERUSER_ROLE
    assert escalate_claims(claims, is_superuser=False)["role"] == DEFAULT_ROLE


def test_forge_alg_none_has_unsigned_header_and_empty_signature() -> None:
    token = forge_alg_none(is_superuser=True)
    header, payload, signature = token.split(".")

    assert _decode_segment(header)["alg"] == "none"
    assert _decode_segment(payload)["is_superuser"] is True
    assert signature == ""


def test_forge_alg_none_defaults_to_canonical_superuser_claims() -> None:
    claims = _decode_segment(forge_alg_none().split(".")[1])

    assert claims["is_superuser"] is True
    assert claims["role"] == CANONICAL_SUPERUSER_ROLE


def test_forge_hs256_refresh_token_decodes_with_secret() -> None:
    token = forge_hs256("unit-test-secret-with-at-least-32-bytes", sub="subject")
    payload = jwt.decode(
        token, "unit-test-secret-with-at-least-32-bytes", algorithms=["HS256"]
    )

    assert payload["sub"] == "subject"
    assert payload["type"] == "refresh"
    assert payload["jti"]


def _rsa_private_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _ec_private_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_hs256_public_key_confusion_shape() -> None:
    token = forge_hs256_with_pubkey("not-a-real-public-key", email="x@example.com")
    header, payload, signature = token.split(".")
    claims = _decode_segment(payload)

    assert _decode_segment(header)["alg"] == "HS256"
    assert claims["email"] == "x@example.com"
    assert (claims["is_superuser"], claims["role"]) == (True, CANONICAL_SUPERUSER_ROLE)
    assert signature


def test_forge_rs256_and_dispatch_with_overrides() -> None:
    key_pem = _rsa_private_pem()

    token = forge_rs256(key_pem, kid="kid-1", role="admin")
    dispatched = forge_asymmetric(key_pem, "RS256", kid="kid-2")

    assert jwt.get_unverified_header(token)["kid"] == "kid-1"
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["role"] == "admin"
    assert claims["is_superuser"] is False
    assert jwt.get_unverified_header(dispatched)["kid"] == "kid-2"
    assert (
        jwt.decode(dispatched, options={"verify_signature": False})["role"]
        == CANONICAL_SUPERUSER_ROLE
    )


def test_asymmetric_forge_privilege_overrides_stay_canonical() -> None:
    key_pem = _rsa_private_pem()

    token = forge_asymmetric(key_pem, "RS256", is_superuser=True)
    inconsistent = forge_asymmetric(
        key_pem,
        "RS256",
        is_superuser=True,
        role="user",
        allow_inconsistent_claims=True,
    )

    assert (
        jwt.decode(token, options={"verify_signature": False})["role"]
        == CANONICAL_SUPERUSER_ROLE
    )
    assert jwt.decode(inconsistent, options={"verify_signature": False})["role"] == (
        "user"
    )


def test_asymmetric_forge_rejects_inconsistent_override_pair() -> None:
    key_pem = _rsa_private_pem()

    with pytest.raises(ValueError, match="Inconsistent privilege claims"):
        forge_asymmetric(key_pem, "RS256", is_superuser=True, role="user")


def test_forge_es256_and_dispatch() -> None:
    key_pem = _ec_private_pem()

    token = forge_es256(key_pem, kid="kid-1")
    dispatched = forge_asymmetric(key_pem, "ES256", kid="kid-2")

    assert jwt.get_unverified_header(token)["alg"] == "ES256"
    assert jwt.get_unverified_header(dispatched)["kid"] == "kid-2"
    assert (
        jwt.decode(token, options={"verify_signature": False})["role"]
        == CANONICAL_SUPERUSER_ROLE
    )


def test_forge_asymmetric_rejects_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported asymmetric algorithm"):
        forge_asymmetric("key", "HS256")
