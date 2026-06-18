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


def _configured_protected_endpoints() -> list[tuple[str, str]]:
    config = get_config()
    return [
        (service, endpoint)
        for service, endpoints in config.protected_endpoints.items()
        for endpoint in endpoints
    ]


class ConfiguredProtectedEndpointsSuite:
    """Reusable checks for endpoints declared in live-test configuration."""

    @pytest.mark.parametrize(("service", "endpoint"), _configured_protected_endpoints())
    def test_no_token_rejected(self, service: str, endpoint: str) -> None:
        """Configured protected endpoints must reject unauthenticated requests."""
        url = self._url(service, endpoint)
        response = requests.get(url, timeout=get_config().timeout)
        assert response.status_code in (401, 403)

    @pytest.mark.parametrize(("service", "endpoint"), _configured_protected_endpoints())
    def test_invalid_token_rejected(self, service: str, endpoint: str) -> None:
        """Configured protected endpoints must reject malformed bearer tokens."""
        url = self._url(service, endpoint)
        response = requests.get(
            url,
            headers=auth_header("not.a.valid.jwt"),
            timeout=get_config().timeout,
        )
        assert response.status_code in (401, 403)

    @pytest.mark.parametrize(("service", "endpoint"), _configured_protected_endpoints())
    def test_valid_token_accepted(
        self, service: str, endpoint: str, admin_headers: dict[str, str]
    ) -> None:
        """Configured protected endpoints must accept a valid access token."""
        url = self._url(service, endpoint)
        response = requests.get(
            url,
            headers=admin_headers,
            timeout=get_config().timeout,
        )
        assert response.status_code == 200

    @staticmethod
    def _url(service: str, endpoint: str) -> str:
        base_url = get_config().resolve_service_base_url(service)
        return f"{base_url}/{endpoint.lstrip('/')}"


_INTERNAL_PATH_FRAGMENTS = ("/opt/", "/app/", "/usr/local/", "site-packages", 'File "')


class ServiceInfoDisclosureSuite:
    """Reusable checks for unknown-route disclosure in one service."""

    service: ClassVar[str | None] = None
    unknown_route: ClassVar[str] = "/no/such/route/"

    def test_unknown_route_returns_404_without_internal_path(self) -> None:
        """Unknown routes must not leak tracebacks or internal filesystem paths."""
        response = requests.get(self._url(), timeout=get_config().timeout)

        assert response.status_code == 404
        assert "Traceback" not in response.text
        for fragment in _INTERNAL_PATH_FRAGMENTS:
            assert fragment not in response.text

    def _url(self) -> str:
        base_url = get_config().resolve_service_base_url(self.service)
        return f"{base_url}/{self.unknown_route.lstrip('/')}"


class ConfiguredServiceInfoDisclosureSuite:
    """Reusable unknown-route disclosure checks for all configured services."""

    def test_unknown_routes_do_not_disclose_internal_paths(self) -> None:
        """Configured services must return clean 404 responses for unknown routes."""
        config = get_config()
        assert config.service_base_urls, "No service URLs configured"
        for service_name, base_url in config.service_base_urls.items():
            response = requests.get(
                f"{base_url}/no/such/route/",
                timeout=config.timeout,
            )

            assert response.status_code == 404, service_name
            assert "Traceback" not in response.text, service_name
            for fragment in _INTERNAL_PATH_FRAGMENTS:
                assert fragment not in response.text, service_name
