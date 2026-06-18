"""Token-crafting helpers for adversarial live tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

import jwt

_FALLBACK_KID = "unknown"
DEFAULT_ACCESS_CLAIM_TYPE = "access"


def b64url_nopad(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def access_payload(
    *,
    is_superuser: bool = False,
    is_active: bool = True,
    email: str = "forged@example.invalid",
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    iss: str | None = None,
    aud: str | None = None,
) -> dict[str, object]:
    """Return a minimal but plausible access token payload."""
    now = int(datetime.now(UTC).timestamp())
    payload: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "email": email,
        "is_superuser": is_superuser,
        "is_active": is_active,
        "role": "user",
        "full_name": "Live Security Test",
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "type": token_type,
    }
    if iss is not None:
        payload["iss"] = iss
    if aud is not None:
        payload["aud"] = aud
    return payload


def forge_alg_none(is_superuser: bool = True, **payload_kw: object) -> str:
    """Craft an unsigned JWT claiming arbitrary privileges."""
    header = b64url_nopad(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = access_payload(is_superuser=is_superuser)
    claims.update(payload_kw)
    payload = b64url_nopad(json.dumps(claims).encode())
    return f"{header}.{payload}."


def forge_hs256_with_pubkey(public_key_pem: str, **payload_kw: object) -> str:
    """Sign a JWT with a public key as the HS256 secret."""
    header = b64url_nopad(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = access_payload(is_superuser=True)
    claims.update(payload_kw)
    payload = b64url_nopad(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url_nopad(sig)}"


def _payload_with_overrides(
    *,
    is_superuser: bool,
    token_type: str,
    iss: str | None,
    aud: str | None,
    payload_kw: dict[str, object],
) -> dict[str, object]:
    claims = access_payload(
        is_superuser=is_superuser,
        token_type=token_type,
        iss=iss,
        aud=aud,
    )
    claims.update(payload_kw)
    return claims


def forge_rs256(
    key_pem: str,
    *,
    is_superuser: bool = True,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    kid: str = _FALLBACK_KID,
    iss: str | None = None,
    aud: str | None = None,
    **payload_kw: object,
) -> str:
    """Forge a cryptographically valid RS256 token."""
    return jwt.encode(
        _payload_with_overrides(
            is_superuser=is_superuser,
            token_type=token_type,
            iss=iss,
            aud=aud,
            payload_kw=payload_kw,
        ),
        key_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


def forge_es256(
    key_pem: str,
    *,
    is_superuser: bool = True,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    kid: str = _FALLBACK_KID,
    iss: str | None = None,
    aud: str | None = None,
    **payload_kw: object,
) -> str:
    """Forge a cryptographically valid ES256 token."""
    return jwt.encode(
        _payload_with_overrides(
            is_superuser=is_superuser,
            token_type=token_type,
            iss=iss,
            aud=aud,
            payload_kw=payload_kw,
        ),
        key_pem,
        algorithm="ES256",
        headers={"kid": kid},
    )


def forge_asymmetric(
    key_pem: str,
    alg: str,
    *,
    is_superuser: bool = True,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    kid: str = _FALLBACK_KID,
    iss: str | None = None,
    aud: str | None = None,
    **payload_kw: object,
) -> str:
    """Dispatch RS256/ES256 forgery based on detected algorithm."""
    if alg.startswith("RS"):
        return forge_rs256(
            key_pem,
            is_superuser=is_superuser,
            token_type=token_type,
            kid=kid,
            iss=iss,
            aud=aud,
            **payload_kw,
        )
    if alg.startswith("ES"):
        return forge_es256(
            key_pem,
            is_superuser=is_superuser,
            token_type=token_type,
            kid=kid,
            iss=iss,
            aud=aud,
            **payload_kw,
        )
    raise ValueError(f"Unsupported asymmetric algorithm: {alg!r}")


def forge_hs256(secret: str, *, sub: str | None = None) -> str:
    """Forge an HS256 refresh token signed with the given secret."""
    payload = {
        "sub": sub or str(uuid.uuid4()),
        "exp": int((datetime.now(UTC) + timedelta(hours=24)).timestamp()),
        "jti": str(uuid.uuid4()),
        "type": "refresh",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


Algorithm = Literal["RS256", "ES256", "HS256"]
