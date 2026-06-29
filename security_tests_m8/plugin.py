"""Pytest plugin for reusable live security tests."""

from __future__ import annotations

import base64
import json
import uuid
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Protocol, TypeAlias, cast

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurve,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from security_tests_m8._config import configure_from_env, get_config
from security_tests_m8._detection import StackInfo, detect_stack
from security_tests_m8._preflight import PreflightError, run_live_preflight
from security_tests_m8.forge import forge_asymmetric

_PrivateKey: TypeAlias = RSAPrivateKey | EllipticCurvePrivateKey
_Forge = Callable[..., str]


class _PublicKey(Protocol):
    def public_bytes(self, encoding: Encoding, format: PublicFormat) -> bytes: ...


def _build_ec_curves() -> dict[str, EllipticCurve]:
    from cryptography.hazmat.primitives.asymmetric import ec

    return {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }


_EC_CURVES = _build_ec_curves()


def _b64int(value: str) -> int:
    return int.from_bytes(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"
    )


def _jwk_to_public_key(jwk: dict[str, object]) -> _PublicKey:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if jwk["kty"] == "RSA":
        return rsa.RSAPublicNumbers(
            _b64int(str(jwk["e"])), _b64int(str(jwk["n"]))
        ).public_key()
    if jwk["kty"] == "EC":
        curve_name = str(jwk.get("crv", ""))
        if curve_name not in _EC_CURVES:
            raise ValueError(f"Unsupported EC curve: {curve_name!r}")
        return ec.EllipticCurvePublicNumbers(
            _b64int(str(jwk["x"])),
            _b64int(str(jwk["y"])),
            _EC_CURVES[curve_name],
        ).public_key()
    raise ValueError(f"Unsupported JWK kty: {jwk['kty']!r}")


def _pub_der(key: _PublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _find_committed_private_key(
    live_jwks: list[dict[str, object]], repo_root: Path
) -> tuple[Path, dict[str, object]] | None:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    committed: list[tuple[Path, bytes]] = []
    for priv_path in repo_root.rglob("private.pem"):
        pub_path = priv_path.parent / "public.pem"
        if not pub_path.exists():
            continue
        try:
            committed.append(
                (
                    priv_path,
                    _pub_der(
                        cast(_PublicKey, load_pem_public_key(pub_path.read_bytes()))
                    ),
                )
            )
        except (OSError, ValueError):
            continue

    for jwk in live_jwks:
        if jwk.get("use", "sig") != "sig":
            continue
        try:
            live_der = _pub_der(_jwk_to_public_key(jwk))
        except (KeyError, TypeError, ValueError):
            continue
        for priv_path, committed_der in committed:
            if committed_der == live_der:
                return priv_path, jwk
    return None


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register command line options for env-driven live test configuration."""
    group = parser.getgroup("security-tests-m8")
    group.addoption(
        "--live-env-file",
        action="store",
        default=None,
        help="Load live security test configuration from this env file.",
    )
    group.addoption(
        "--live-env-override",
        action="store_true",
        default=False,
        help="Let --live-env-file override existing process environment variables.",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register markers exposed by the package."""
    env_file = config.getoption("--live-env-file")
    if env_file:
        configure_from_env(
            env_file=env_file,
            override_env_file=config.getoption("--live-env-override"),
        )

    markers = {
        "live": "live integration test",
        "live_security": "algorithm-independent live security test",
        "live_asymmetric": "RS256/ES256 live security test",
        "live_hs256": "HS256 live security test",
        "live_stateful": "stateful token-mode live security test",
        "live_stateless": "stateless token-mode live security test",
        "live_hybrid": "hybrid token-mode live security test",
        "live_deployment": "deployment preflight/static live security test",
        "require_algorithm(*names)": "skip unless detected JWT alg matches",
        "require_token_mode(*names)": "skip unless detected token mode matches",
        "require_redis": "skip unless health reports Redis available",
        "destructive": "test mutates live auth/session/rate-limit state",
    }
    for name, description in markers.items():
        config.addinivalue_line("markers", f"{name}: {description}")


def pytest_sessionstart(session: pytest.Session) -> None:
    """Abort live sessions before collection when the target stack is not runnable."""
    config = get_config()
    if not config.fail_fast_preflight:
        return
    try:
        run_live_preflight(config)
    except PreflightError as exc:
        pytest.exit(f"Live security preflight failed: {exc}", returncode=2)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip live tests whose requirements do not match the running stack."""
    detected = detect_stack()
    if not detected.reachable:
        skip = pytest.mark.skip(
            reason="Live stack not reachable; start a stack or configure URLs"
        )
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip)
        return

    redis_skip = pytest.mark.skip(
        reason="Redis unavailable; rate limiting and stateful JTI checks need Redis"
    )
    redis_unknown_skip = pytest.mark.skip(
        reason=(
            "Redis status unknown — health detail unavailable; "
            "set LIVE_TEST_HEALTH_DETAIL_CREDENTIAL to detect Redis state"
        )
    )
    token_mode_unknown_skip = pytest.mark.skip(
        reason=(
            "Token mode unknown — health detail unavailable; set "
            "LIVE_TEST_HEALTH_DETAIL_CREDENTIAL or LIVE_TEST_TOKEN_MODE"
        )
    )
    for item in items:
        alg_marker = item.get_closest_marker("require_algorithm")
        if alg_marker and detected.algorithm not in alg_marker.args:
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        f"Stack runs {detected.algorithm!r}; "
                        f"test requires one of {alg_marker.args}"
                    )
                )
            )
            continue
        mode_marker = item.get_closest_marker("require_token_mode")
        if mode_marker:
            if not detected.token_mode_known:
                item.add_marker(token_mode_unknown_skip)
                continue
            if detected.token_mode not in mode_marker.args:
                item.add_marker(
                    pytest.mark.skip(
                        reason=(
                            f"Stack token_mode is {detected.token_mode!r}; "
                            f"test requires one of {mode_marker.args}"
                        )
                    )
                )
                continue
        needs_redis = (
            item.get_closest_marker("require_redis")
            or "live_stateful" in item.keywords
            or "live_hybrid" in item.keywords
        )
        if needs_redis:
            if not detected.detail_available:
                item.add_marker(redis_unknown_skip)
            elif not detected.redis_ok:
                item.add_marker(redis_skip)


@pytest.fixture(scope="session")
def stack_config() -> StackInfo:
    """Detected algorithm and token_mode of the running live stack."""
    return detect_stack()


@pytest.fixture(scope="session")
def live_jwks_keys() -> list[dict[str, object]]:
    """Return all JWKs from the configured auth service."""
    config = get_config()
    try:
        response = requests.get(
            f"{config.auth_base_url}/.well-known/jwks.json", timeout=5
        )
        if response.status_code == 200:
            keys = response.json().get("keys", [])
            if isinstance(keys, list):
                return [key for key in keys if isinstance(key, dict)]
    except (ValueError, requests.RequestException):
        pass
    return []


@pytest.fixture(scope="session")
def admin_token() -> str:
    """Return a fresh admin access token."""
    config = get_config()
    response = requests.post(
        f"{config.auth_base_url}/login/access-token",
        data={"username": config.admin_email, "password": config.admin_password},
        timeout=config.timeout,
    )
    assert response.status_code == 200, f"Admin login failed: {response.text}"
    return str(response.json()["access_token"])


@pytest.fixture(scope="session")
def admin_headers(admin_token: str) -> dict[str, str]:
    """Return Authorization headers for the admin account."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def admin_login() -> dict[str, object]:
    """Return a full admin login response: access token, cookies, and headers."""
    config = get_config()
    response = requests.post(
        f"{config.auth_base_url}/login/access-token",
        data={"username": config.admin_email, "password": config.admin_password},
        timeout=config.timeout,
    )
    assert response.status_code == 200
    token = str(response.json()["access_token"])
    return {
        "access_token": token,
        "cookies": dict(response.cookies),
        "headers": {"Authorization": f"Bearer {token}"},
    }


@pytest.fixture(scope="session")
def regular_user(
    admin_headers: dict[str, str],
) -> Iterator[dict[str, object]]:
    """Create a throwaway non-superuser account, yield credentials, then delete it.

    The account uses a random ``redteam_<hex>@redteam-test.com`` email so each run
    is isolated and never collides with real users. It is removed at session
    teardown via the admin account so a run leaves no standing test identity
    behind. Deletion is best-effort: if the stack is unreachable at teardown the
    cleanup is skipped rather than failing the run.
    """
    config = get_config()
    email = f"redteam_{uuid.uuid4().hex[:8]}@redteam-test.com"
    generated_value = "RedTeam!Pass99"
    response = requests.post(
        f"{config.auth_base_url}/users/new_user/",
        json={
            "email": email,
            "password": generated_value,
            "full_name": "Red Team User",
        },
        headers=admin_headers,
        timeout=config.timeout,
    )
    assert response.status_code == 200, f"Could not create test user: {response.text}"
    user_id = response.json()["id"]
    login = requests.post(
        f"{config.auth_base_url}/login/access-token",
        data={"username": email, "password": generated_value},
        timeout=config.timeout,
    )
    assert login.status_code == 200
    token = str(login.json()["access_token"])
    try:
        yield {
            "id": user_id,
            "email": email,
            "password": generated_value,
            "token": token,
            "cookies": dict(login.cookies),
            "headers": {"Authorization": f"Bearer {token}"},
        }
    finally:
        try:
            requests.delete(
                f"{config.auth_base_url}/users/delete/{user_id}/",
                headers=admin_headers,
                timeout=config.timeout,
            )
        except requests.RequestException:
            pass


@pytest.fixture(scope="session")
def committed_key_forge(
    stack_config: StackInfo, live_jwks_keys: list[dict[str, object]]
) -> _Forge:
    """Return a token forge using a private key found under repo_root."""
    config = get_config()
    detected_alg = stack_config.algorithm
    if not detected_alg.startswith(("RS", "ES")):
        pytest.skip(f"committed_key_forge: symmetric stack ({detected_alg!r})")
    if not live_jwks_keys:
        pytest.skip("committed_key_forge: JWKS unavailable or empty")
    if config.repo_root is None:
        pytest.skip("committed_key_forge: configure(repo_root=...) is required")

    result = _find_committed_private_key(live_jwks_keys, config.repo_root)
    if result is None:
        pytest.skip("committed_key_forge: no committed key matches live JWKS")
    priv_path, matched_jwk = result
    live_kid = str(matched_jwk.get("kid", "unknown"))
    live_alg = str(matched_jwk.get("alg", detected_alg))
    if live_alg != detected_alg:
        warnings.warn(
            f"Health reports algorithm={detected_alg!r}, but JWKS key has "
            f"alg={live_alg!r}; using JWKS value",
            stacklevel=2,
        )
    key_pem = priv_path.read_text(encoding="utf-8")
    live_iss, live_aud = _live_token_issuer_audience()

    def _forge(**kwargs: object) -> str:
        kwargs.setdefault("kid", live_kid)
        kwargs.setdefault("iss", live_iss)
        kwargs.setdefault("aud", live_aud)
        return forge_asymmetric(
            key_pem,
            live_alg,
            is_superuser=bool(kwargs.get("is_superuser", True)),
            token_type=str(kwargs.get("token_type", "access")),
            kid=str(kwargs.get("kid", live_kid)),
            iss=_optional_str(kwargs.get("iss")),
            aud=_optional_str(kwargs.get("aud")),
        )

    return _forge


def _optional_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _live_token_issuer_audience() -> tuple[str | None, str | None]:
    config = get_config()
    try:
        sample = requests.post(
            f"{config.auth_base_url}/login/access-token",
            data={"username": config.admin_email, "password": config.admin_password},
            timeout=config.timeout,
        )
        if sample.status_code != 200:
            return None, None
        raw = sample.json()["access_token"].split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        return payload.get("iss"), payload.get("aud")
    except (KeyError, TypeError, ValueError, requests.RequestException):
        return None, None


@pytest.fixture(scope="session")
def public_key_pem(
    stack_config: StackInfo, live_jwks_keys: list[dict[str, object]]
) -> str:
    """Return a public key PEM reconstructed from JWKS."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    alg = stack_config.algorithm
    if not alg.startswith(("RS", "ES")):
        pytest.skip(f"public_key_pem: symmetric stack ({alg!r})")
    if not live_jwks_keys:
        pytest.skip("public_key_pem: JWKS unavailable or empty")
    signing_jwk = next(
        (
            key
            for key in live_jwks_keys
            if key.get("kty") in {"RSA", "EC"}
            and key.get("use", "sig") == "sig"
            and key.get("alg", alg) == alg
        ),
        None,
    )
    if signing_jwk is None:
        pytest.skip(f"public_key_pem: no signing key with alg={alg!r}")
    try:
        pub = _jwk_to_public_key(signing_jwk)
        return pub.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
    except (KeyError, TypeError, ValueError) as exc:
        pytest.skip(f"public_key_pem: key reconstruction failed: {exc}")


@pytest.fixture(scope="session")
def asymmetric_key_pem(
    stack_config: StackInfo, live_jwks_keys: list[dict[str, object]]
) -> tuple[str, str, str | None]:
    """Return private key PEM, algorithm, and kid for rejection-path tests."""
    alg = stack_config.algorithm
    if not alg.startswith(("RS", "ES")):
        pytest.skip(f"asymmetric_key_pem: symmetric stack ({alg!r})")
    config = get_config()
    if config.repo_root and live_jwks_keys:
        result = _find_committed_private_key(live_jwks_keys, config.repo_root)
        if result is not None:
            priv_path, matched_jwk = result
            return (
                priv_path.read_text(encoding="utf-8"),
                str(matched_jwk.get("alg", alg)),
                str(matched_jwk["kid"]) if matched_jwk.get("kid") else None,
            )
    return _ephemeral_private_key(alg)


def _ephemeral_private_key(alg: str) -> tuple[str, str, None]:
    from cryptography.hazmat.primitives import serialization

    if alg.startswith("RS"):
        from cryptography.hazmat.primitives.asymmetric import rsa

        key: _PrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
    else:
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return pem, alg, None


@pytest.fixture(scope="session")
def service_base_urls() -> dict[str, str]:
    """Return configured service URL mapping."""
    return dict(get_config().service_base_urls)


@pytest.fixture(scope="session")
def service_base_url() -> str:
    """Return the default configured service URL."""
    return get_config().resolve_service_base_url()


@pytest.fixture(scope="session")
def service_url() -> Callable[[str | None], str]:
    """Return a resolver for named service URLs."""
    return get_config().resolve_service_base_url
