"""Generic protected-endpoint suite for downstream FastAPI M8 services."""

from __future__ import annotations

from typing import ClassVar

import pytest
import requests

from security_tests_m8._client import auth_header
from security_tests_m8._config import get_config

pytestmark = [pytest.mark.live, pytest.mark.live_security]


class ProtectedEndpointSuite:
    """Reusable checks for one protected downstream service endpoint."""

    service: ClassVar[str | None] = None
    endpoint: ClassVar[str] = "/category/"

    def _url(self) -> str:
        base_url = get_config().resolve_service_base_url(self.service)
        return f"{base_url}/{self.endpoint.lstrip('/')}"

    def test_no_token_rejected(self) -> None:
        """A protected endpoint must reject unauthenticated requests."""
        response = requests.get(self._url(), timeout=get_config().timeout)
        assert response.status_code in (401, 403)

    def test_invalid_token_rejected(self) -> None:
        """A protected endpoint must reject malformed bearer tokens."""
        response = requests.get(
            self._url(),
            headers=auth_header("not.a.valid.jwt"),
            timeout=get_config().timeout,
        )
        assert response.status_code in (401, 403)

    def test_valid_token_accepted(self, admin_headers: dict[str, str]) -> None:
        """A protected endpoint must accept a valid access token."""
        response = requests.get(
            self._url(),
            headers=admin_headers,
            timeout=get_config().timeout,
        )
        assert response.status_code == 200
