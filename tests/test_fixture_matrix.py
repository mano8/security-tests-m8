"""Tests for the vendored authorization fixture matrix (§5.5, FIXTURE-01, Phase 5).

The harness stays SDK-free by design — it never imports or installs
``auth-sdk-m8`` at runtime — so it **vendors** a checked-in copy of the same
checksummed JSON ``auth-sdk-m8`` publishes, instead of consuming it as
installed package data like ``fastapi-m8`` and ``fa-auth-m8`` do. This module
proves the vendored copy's schema-version/checksum guards are load-bearing
(the CI gate against contract drift or a hand-edit) and that the harness's own
canonical-claim forging (``security_tests_m8.forge``) agrees with the
fixture's role/flag truth table.
"""

from __future__ import annotations

import copy
import json

import pytest

from security_tests_m8.forge import (
    CANONICAL_SUPERUSER_ROLE,
    DEFAULT_ROLE,
    resolve_claim_pair,
)
from security_tests_m8.testing import (
    FIXTURE_MATRIX_SCHEMA_VERSION,
    FixtureChecksumMismatchError,
    UnsupportedFixtureMatrixSchemaVersionError,
    load_authorization_fixture_matrix,
)


@pytest.fixture(scope="module")
def matrix() -> dict:
    return load_authorization_fixture_matrix()


class TestSchemaVersionAndChecksumGuards:
    def test_loader_returns_declared_schema_version(self, matrix: dict) -> None:
        assert matrix["schema_version"] == FIXTURE_MATRIX_SCHEMA_VERSION

    def test_unknown_schema_version_is_rejected(self, matrix: dict) -> None:
        from security_tests_m8.testing import (
            _compute_checksum,
            _parse_and_verify_fixture_matrix,
        )

        tampered = copy.deepcopy(matrix)
        tampered["schema_version"] = "999"
        tampered["checksum_sha256"] = _compute_checksum(tampered)

        with pytest.raises(UnsupportedFixtureMatrixSchemaVersionError):
            _parse_and_verify_fixture_matrix(json.dumps(tampered))

    def test_tampered_content_fails_checksum_verification(self, matrix: dict) -> None:
        from security_tests_m8.testing import _parse_and_verify_fixture_matrix

        tampered = copy.deepcopy(matrix)
        tampered["role_flag_matrix"][0]["has_superuser_privileges"] = True

        with pytest.raises(FixtureChecksumMismatchError):
            _parse_and_verify_fixture_matrix(json.dumps(tampered))

    def test_checksum_matches_recomputation(self, matrix: dict) -> None:
        from security_tests_m8.testing import _compute_checksum

        assert matrix["checksum_sha256"] == _compute_checksum(matrix)


class TestForgeAgreesWithTheCanonicalRoleFlagMatrix:
    """The harness's own two-role forging must agree with the SDK's truth table.

    The forge module only ever mints ``DEFAULT_ROLE``/``CANONICAL_SUPERUSER_ROLE``
    (3.9) — a deliberately narrower surface than the SDK's full five-role
    hierarchy — but for those two roles its canonical pairing must exactly
    match the fixture matrix's ``consistent``/``has_superuser_privileges``
    columns, or a forged "canonical" token would not actually match what the
    real stack accepts.
    """

    def _row(self, matrix: dict, *, role: str, is_superuser: bool) -> dict:
        for row in matrix["role_flag_matrix"]:
            if row["role"] == role and row["is_superuser"] is is_superuser:
                return row
        raise AssertionError(
            f"no fixture row for role={role!r} is_superuser={is_superuser!r}"
        )

    def test_default_role_pairing_is_canonical(self, matrix: dict) -> None:
        flag, role = resolve_claim_pair(is_superuser=False)
        assert (flag, role) == (False, DEFAULT_ROLE)
        row = self._row(matrix, role=role, is_superuser=flag)
        assert row["consistent"] is True
        assert row["has_superuser_privileges"] is False

    def test_superuser_role_pairing_is_canonical(self, matrix: dict) -> None:
        flag, role = resolve_claim_pair(is_superuser=True)
        assert (flag, role) == (True, CANONICAL_SUPERUSER_ROLE)
        row = self._row(matrix, role=role, is_superuser=flag)
        assert row["consistent"] is True
        assert row["has_superuser_privileges"] is True

    def test_default_role_with_superuser_flag_is_the_inconsistent_row(
        self, matrix: dict
    ) -> None:
        """The forge module's own escalation path deliberately mints this
        inconsistent pair (``allow_inconsistent_claims``) — the fixture must
        agree it is the one row a real canonical-invariant stack rejects."""
        row = self._row(matrix, role=DEFAULT_ROLE, is_superuser=True)
        assert row["consistent"] is False
        assert row["has_superuser_privileges"] is False
