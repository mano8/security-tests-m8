"""Vendored copy of the SDK-owned canonical authorization fixture matrix (§5.5).

``auth-sdk-m8`` is the single canonical owner of the shared role/flag/
decision/event/introspection fixture matrix. This harness stays SDK-free by
design (it must never import or install ``auth-sdk-m8`` at runtime — the only
coupling to the SDK is the canonical role strings it forges), so instead of
consuming the matrix as installed package data like ``fastapi-m8`` and
``fa-auth-m8`` do, it **vendors** the identical JSON: checked in here with its
own schema-version and checksum metadata, verified the same way on load.

The vendored file is a byte-identical copy of
``auth-sdk-m8/auth_sdk_m8/testing/authorization_matrix.json`` as of the
``sdk_version`` it declares. Re-copy it (never hand-edit) whenever the SDK
regenerates its fixture matrix, and re-run
``tests/test_fixture_matrix.py`` — CI fails on drift or a hand-edit exactly
like it does in the SDK and its other consumers.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any, Final

#: Schema version of the vendored fixture matrix this harness release speaks.
FIXTURE_MATRIX_SCHEMA_VERSION: Final[str] = "2"

_DATA_PACKAGE: Final[str] = "security_tests_m8.testing"
_DATA_FILENAME: Final[str] = "authorization_matrix.json"
_CHECKSUM_KEY: Final[str] = "checksum_sha256"


class UnsupportedFixtureMatrixSchemaVersionError(ValueError):
    """Raised when the vendored fixture matrix declares an unknown version.

    Carries only a bounded reason code — never the payload.
    """


class FixtureChecksumMismatchError(ValueError):
    """Raised when the vendored fixture matrix content does not match its
    checksum (hand-edited or a partial/stale copy from the SDK).

    Carries only a bounded reason code — never the payload.
    """


def _compute_checksum(payload: dict[str, Any]) -> str:
    """Deterministic sha256 over every field except the checksum itself.

    Identical algorithm to ``auth_sdk_m8.testing._compute_checksum`` — the
    vendored copy must verify against the exact same digest the SDK computed.
    """
    body = {k: v for k, v in payload.items() if k != _CHECKSUM_KEY}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_and_verify_fixture_matrix(raw: str) -> dict[str, Any]:
    """Parse *raw* JSON and enforce the schema-version/checksum guards.

    Raises:
        UnsupportedFixtureMatrixSchemaVersionError: If *raw* declares a schema
            version this harness release does not implement.
        FixtureChecksumMismatchError: If *raw*'s content does not match its
            declared checksum (hand-edited or a stale partial copy).
    """
    payload: dict[str, Any] = json.loads(raw)

    schema_version = payload.get("schema_version")
    if schema_version != FIXTURE_MATRIX_SCHEMA_VERSION:
        raise UnsupportedFixtureMatrixSchemaVersionError(
            "unsupported_fixture_matrix_schema_version"
        )

    declared_checksum = payload.get(_CHECKSUM_KEY)
    actual_checksum = _compute_checksum(payload)
    if declared_checksum != actual_checksum:
        raise FixtureChecksumMismatchError("fixture_matrix_checksum_mismatch")

    return payload


def load_authorization_fixture_matrix() -> dict[str, Any]:
    """Load, checksum-verify, and return the vendored fixture matrix.

    Returns:
        The parsed fixture matrix — the same shape
        ``auth_sdk_m8.testing.load_authorization_fixture_matrix()`` returns.

    Raises:
        UnsupportedFixtureMatrixSchemaVersionError: If the vendored file
            declares a schema version this harness release does not
            implement.
        FixtureChecksumMismatchError: If the vendored file's content does not
            match its declared checksum.
    """
    raw = resources.files(_DATA_PACKAGE).joinpath(_DATA_FILENAME).read_text("utf-8")
    return _parse_and_verify_fixture_matrix(raw)


__all__ = [
    "FIXTURE_MATRIX_SCHEMA_VERSION",
    "FixtureChecksumMismatchError",
    "UnsupportedFixtureMatrixSchemaVersionError",
    "load_authorization_fixture_matrix",
]
