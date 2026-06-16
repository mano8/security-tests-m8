import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from security_tests_m8.forge import (
    access_payload,
    forge_alg_none,
    forge_asymmetric,
    forge_es256,
    forge_hs256,
    forge_hs256_with_pubkey,
    forge_rs256,
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


def test_forge_alg_none_has_unsigned_header_and_empty_signature() -> None:
    token = forge_alg_none(is_superuser=True)
    header, payload, signature = token.split(".")

    assert _decode_segment(header)["alg"] == "none"
    assert _decode_segment(payload)["is_superuser"] is True
    assert signature == ""


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

    assert _decode_segment(header)["alg"] == "HS256"
    assert _decode_segment(payload)["email"] == "x@example.com"
    assert signature


def test_forge_rs256_and_dispatch_with_overrides() -> None:
    key_pem = _rsa_private_pem()

    token = forge_rs256(key_pem, kid="kid-1", role="admin")
    dispatched = forge_asymmetric(key_pem, "RS256", kid="kid-2")

    assert jwt.get_unverified_header(token)["kid"] == "kid-1"
    assert jwt.decode(token, options={"verify_signature": False})["role"] == "admin"
    assert jwt.get_unverified_header(dispatched)["kid"] == "kid-2"


def test_forge_es256_and_dispatch() -> None:
    key_pem = _ec_private_pem()

    token = forge_es256(key_pem, kid="kid-1")
    dispatched = forge_asymmetric(key_pem, "ES256", kid="kid-2")

    assert jwt.get_unverified_header(token)["alg"] == "ES256"
    assert jwt.get_unverified_header(dispatched)["kid"] == "kid-2"


def test_forge_asymmetric_rejects_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported asymmetric algorithm"):
        forge_asymmetric("key", "HS256")
