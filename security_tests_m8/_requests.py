"""Request defaults for configured live-test target URLs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from security_tests_m8._config import LiveTestConfig


_ORIGINAL_REQUEST = requests.sessions.Session.request
_INSTALLED = False
_TLS_VERIFY: bool | str = True
_TLS_PREFIXES: tuple[str, ...] = ()


def _url_matches_live_https_target(url: object) -> bool:
    url_text = str(url)
    if not url_text.lower().startswith("https://"):
        return False
    return any(
        url_text == prefix or url_text.startswith(f"{prefix}/")
        for prefix in _TLS_PREFIXES
    )


def _request_with_live_tls_defaults(
    self: requests.sessions.Session, method: str, url: str, **kwargs: Any
) -> requests.Response:
    if "verify" not in kwargs and _TLS_VERIFY is not True:
        if _url_matches_live_https_target(url):
            kwargs["verify"] = _TLS_VERIFY
    return _ORIGINAL_REQUEST(self, method, url, **kwargs)


def install_live_tls_defaults(config: LiveTestConfig) -> None:
    """Apply configured TLS verification defaults to live-test target requests."""
    global _INSTALLED, _TLS_PREFIXES, _TLS_VERIFY

    prefixes = {
        config.auth_base_url,
        config.auth_health_url,
        config.service_base_url,
        config.public_base_url,
        *config.service_base_urls.values(),
    }
    _TLS_PREFIXES = tuple(
        sorted(
            (prefix.rstrip("/") for prefix in prefixes if prefix),
            key=len,
            reverse=True,
        )
    )
    _TLS_VERIFY = config.public_tls_verify

    if not _INSTALLED:
        setattr(requests.sessions.Session, "request", _request_with_live_tls_defaults)
        _INSTALLED = True
