"""Reusable live suite for Python deployment preflight checks."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from security_tests_m8._config import get_config
from security_tests_m8.deployment import scan_deployment

pytestmark = [pytest.mark.live, pytest.mark.live_security, pytest.mark.live_deployment]


class DeploymentPreflightSuite:
    """Reusable live suite for compose deployment preflight checks."""

    deployment_root: ClassVar[str | Path | None] = None

    def _deployment_root(self) -> Path:
        root = self.deployment_root or get_config().deployment_root
        if root is None:
            pytest.skip(
                "Deployment preflight checks require deployment_root or "
                "LIVE_TEST_DEPLOYMENT_ROOT"
            )
        path = Path(root).resolve()
        if not path.exists():
            pytest.skip(f"Deployment root does not exist: {path}")
        return path

    def test_deployment_preflight_has_no_errors(self) -> None:
        """Env and compose deployment files must pass P0 preflight gates."""
        report = scan_deployment(self._deployment_root())
        report.assert_no_errors()
