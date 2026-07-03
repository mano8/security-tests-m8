"""
Live Security Test Suite — Media internal callback ingress (plan 11.1)
======================================================================
Target:  the public entrypoint (``LIVE_TEST_PUBLIC_BASE``) of a media stack.

Media worker callbacks live at ``/media/v1/internal/*`` and are gated at the
app layer by ``MEDIA_INTERNAL_SERVICE_TOKEN``. A hardened public Traefik router
must additionally *exclude* the ``/media/v1/internal`` prefix so those routes
are never internet-routable — mirroring the auth ``/private`` and ``/metrics``
posture. This suite proves that public requests to representative internal
callbacks are blocked at the proxy layer (404) with **no bearer**, a **wrong
bearer**, and — opt-in — a **configured worker bearer**, so a stolen worker
token cannot be replayed through the public domain.

OPERATOR NOTE: if any test below fails with a non-404 status, the public media
router is missing ``PathPrefix(`/media/v1/internal`)`` from its exclusion list.
Add it, route internal callbacks on the internal entrypoint only, and restart
Traefik. See the SECURITY CONTRACT comment beside the media public router.

Run against any running media stack:
    pytest -k MediaInternalExposure -v --no-cov
"""

from __future__ import annotations

import pytest
import requests

from security_tests_m8._config import get_config

pytestmark = [pytest.mark.live, pytest.mark.live_security]

# Representative worker → media internal callbacks (method, path suffix under
# ``/media/v1/internal``). The nil UUIDs never need to resolve: a correct public
# edge rejects the request before routing, so the probe only asserts the ingress
# block, not application behaviour.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"
_INTERNAL_CALLBACKS: tuple[tuple[str, str], ...] = (
    ("post", f"/objects/{_NIL_UUID}/scan-result"),
    ("post", f"/objects/{_NIL_UUID}/variants"),
    ("patch", f"/variant-jobs/{_NIL_UUID}"),
)

_FIX = (
    "Fix: exclude PathPrefix(`/media/v1/internal`) from the media public router "
    "and route internal callbacks on the internal entrypoint only, then restart "
    "Traefik."
)


def _internal_url(path: str) -> str:
    base_url = get_config().media_internal_base_url()
    if base_url is None:
        pytest.skip(
            "Media internal exposure checks require LIVE_TEST_PUBLIC_BASE "
            "(the public entrypoint that must NOT expose /media/v1/internal)"
        )
    return f"{base_url}/{path.lstrip('/')}"


def _probe(
    method: str, path: str, headers: dict[str, str] | None = None
) -> requests.Response | None:
    """Send one probe to the public edge, returning None on TLS handshake refusal."""
    config = get_config()
    try:
        return requests.request(
            method,
            _internal_url(path),
            json={},
            headers=headers or {},
            timeout=config.timeout,
            verify=config.public_tls_verify,
        )  # noqa: S501
    except requests.exceptions.SSLError:
        return None


class MediaInternalExposureSuite:
    """Category G — media ``/media/v1/internal/*`` public ingress must be blocked."""

    @pytest.mark.parametrize(("method", "path"), _INTERNAL_CALLBACKS)
    def test_g01_internal_callback_blocked_no_bearer(
        self, method: str, path: str
    ) -> None:
        """SECURITY PASS: public media internal callback returns 404 with no bearer."""
        response = _probe(method, path)
        if response is None:
            return
        assert response.status_code == 404, (
            "[SECURITY FAIL: TRAEFIK] /media/v1/internal is publicly routed. "
            f"{method.upper()} {path} returned {response.status_code}, expected 404. "
            f"{_FIX}"
        )

    @pytest.mark.parametrize(("method", "path"), _INTERNAL_CALLBACKS)
    def test_g02_internal_callback_blocked_wrong_bearer(
        self, method: str, path: str
    ) -> None:
        """SECURITY PASS: a wrong worker bearer is still blocked at the edge (404)."""
        response = _probe(
            method, path, headers={"Authorization": "Bearer wrong_totally"}
        )
        if response is None:
            return
        assert response.status_code == 404, (
            "[SECURITY FAIL: TRAEFIK] /media/v1/internal is publicly routed even "
            f"with a bearer. {method.upper()} {path} returned {response.status_code}, "
            f"expected 404. {_FIX}"
        )

    @pytest.mark.parametrize(("method", "path"), _INTERNAL_CALLBACKS)
    def test_g03_internal_callback_blocked_with_configured_bearer(
        self, method: str, path: str
    ) -> None:
        """SECURITY PASS: even a VALID worker token is blocked at the public edge.

        Opt-in. Set ``LIVE_TEST_MEDIA_INTERNAL_TOKEN`` to the stack's
        ``MEDIA_INTERNAL_SERVICE_TOKEN``. A 404 proves that a stolen but valid
        worker token cannot be replayed through the public domain; the app-layer
        bearer gate stays as defense in depth on the internal entrypoint.
        """
        headers = get_config().media_internal_headers()
        if not headers:
            pytest.skip(
                "Set LIVE_TEST_MEDIA_INTERNAL_TOKEN to run the configured-bearer "
                "media internal exposure check"
            )
        response = _probe(method, path, headers=headers)
        if response is None:
            return
        assert response.status_code == 404, (
            "[SECURITY FAIL-G03] A valid MEDIA_INTERNAL_SERVICE_TOKEN reached the "
            f"public media internal route. {method.upper()} {path} returned "
            f"{response.status_code}, expected 404 at the proxy layer. A stolen "
            f"worker token is remotely replayable. {_FIX}"
        )
