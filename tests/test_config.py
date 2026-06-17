import os
from pathlib import Path

import pytest

from security_tests_m8 import (
    LiveTestConfig,
    configure,
    configure_from_env,
    get_config,
    load_env_file,
)

_PLACEHOLDER = "pw"
_OPT_IN_PRIVATE_VALUE = "private"
_OPT_IN_REFRESH_VALUE = "refresh"


def test_single_service_base_normalized_and_resolved() -> None:
    config = LiveTestConfig(
        auth_base_url="http://auth/",
        admin_email="admin@example.com",
        admin_password=_PLACEHOLDER,
        service_base_url="http://svc/",
    ).normalized()

    assert config.auth_base_url == "http://auth"
    assert config.resolve_service_base_url() == "http://svc"
    assert config.service_base_urls["default"] == "http://svc"


def test_named_service_resolution_prefers_requested_service() -> None:
    config = LiveTestConfig(
        service_base_urls={"catalog": "http://catalog/", "orders": "http://orders"},
        default_service="catalog",
    ).normalized()

    assert config.resolve_service_base_url("orders") == "http://orders"
    assert config.resolve_service_base_url() == "http://catalog"


def test_unknown_service_raises_clear_error() -> None:
    config = LiveTestConfig(service_base_urls={"catalog": "http://catalog"})

    with pytest.raises(LookupError, match="Known services: catalog"):
        config.resolve_service_base_url("orders")


def test_configure_updates_singleton(tmp_path: Path) -> None:
    configure(
        auth_base_url="http://auth/",
        admin_email="admin@example.com",
        admin_password=_PLACEHOLDER,
        service_base_url="http://svc/",
        repo_root=tmp_path,
    )

    config = get_config()
    assert config.auth_base_url == "http://auth"
    assert config.repo_root == tmp_path.resolve()
    assert config.resolve_service_base_url() == "http://svc"


def test_from_env_parses_all_overrides(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LIVE_TEST_AUTH_BASE", "http://auth/")
    monkeypatch.setenv("LIVE_TEST_ADMIN_EMAIL", "ops@example.com")
    monkeypatch.setenv("LIVE_TEST_ADMIN_PASSWORD", _PLACEHOLDER)
    monkeypatch.setenv("LIVE_TEST_SVC_BASE", "http://default/")
    monkeypatch.setenv("LIVE_TEST_SVC_BASES", '{"catalog": "http://catalog/"}')
    monkeypatch.setenv("LIVE_TEST_DEFAULT_SVC", "catalog")
    monkeypatch.setenv("LIVE_TEST_TIMEOUT", "3")
    monkeypatch.setenv("LIVE_TEST_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("LIVE_TEST_DEPLOYMENT_ROOT", str(tmp_path / "deploy"))
    monkeypatch.setenv("LIVE_TEST_PUBLIC_BASE", "https://public/")
    monkeypatch.setenv("LIVE_TEST_PUBLIC_TLS_VERIFY", "false")
    monkeypatch.setenv("LIVE_TEST_PRIVATE_API_SECRET", _OPT_IN_PRIVATE_VALUE)
    monkeypatch.setenv("LIVE_TEST_REFRESH_SECRET_KEY", _OPT_IN_REFRESH_VALUE)

    config = LiveTestConfig.from_env()

    assert config.auth_base_url == "http://auth"
    assert config.admin_email == "ops@example.com"
    assert config.admin_password == _PLACEHOLDER
    assert config.timeout == 3
    assert config.repo_root == tmp_path.resolve()
    assert config.deployment_root == (tmp_path / "deploy").resolve()
    assert config.public_base_url == "https://public"
    assert config.public_tls_verify is False
    assert config.private_api_secret == _OPT_IN_PRIVATE_VALUE
    assert config.refresh_secret_key == _OPT_IN_REFRESH_VALUE
    assert config.resolve_service_base_url() == "http://catalog"


def test_env_service_bases_requires_json_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIVE_TEST_SVC_BASES", '["not", "object"]')

    with pytest.raises(ValueError, match="JSON object"):
        LiveTestConfig.from_env()


def test_from_env_parses_protected_endpoint_map(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "LIVE_TEST_PROTECTED_ENDPOINTS",
        '{"fastapi": ["/category/", 123]}',
    )

    config = LiveTestConfig.from_env()

    assert config.protected_endpoints == {"fastapi": ["/category/", "123"]}


def test_env_endpoint_map_requires_json_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIVE_TEST_PROTECTED_ENDPOINTS", '["not", "object"]')

    with pytest.raises(ValueError, match="JSON object"):
        LiveTestConfig.from_env()


def test_env_endpoint_map_values_must_be_arrays(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIVE_TEST_PROTECTED_ENDPOINTS", '{"fastapi": "/category/"}')

    with pytest.raises(ValueError, match="values must be arrays"):
        LiveTestConfig.from_env()


def test_unconfigured_service_resolution_fails() -> None:
    config = LiveTestConfig()

    with pytest.raises(LookupError, match="No service URL configured"):
        config.resolve_service_base_url()


def test_raw_service_base_url_fallback_without_normalization() -> None:
    config = LiveTestConfig(service_base_url="http://svc")

    assert config.resolve_service_base_url() == "http://svc"


def test_configure_accepts_repo_root_string(tmp_path: Path) -> None:
    config = configure(
        repo_root=str(tmp_path), deployment_root=str(tmp_path / "deploy")
    )

    assert config.repo_root == tmp_path.resolve()
    assert config.deployment_root == (tmp_path / "deploy").resolve()


def test_load_env_file_preserves_existing_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LIVE_TEST_ADMIN_EMAIL=file@example.com\n", encoding="utf-8")
    monkeypatch.setenv("LIVE_TEST_ADMIN_EMAIL", "shell@example.com")

    loaded = load_env_file(env_file)

    assert loaded == {"LIVE_TEST_ADMIN_EMAIL": "file@example.com"}
    assert os.environ["LIVE_TEST_ADMIN_EMAIL"] == "shell@example.com"


def test_load_env_file_skips_invalid_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n# comment\nNO_EQUALS\n =bad\nLIVE_TEST_TIMEOUT='12'\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("LIVE_TEST_TIMEOUT", raising=False)

    loaded = load_env_file(env_file)

    assert loaded == {"LIVE_TEST_TIMEOUT": "12"}
    assert os.environ["LIVE_TEST_TIMEOUT"] == "12"


def test_configure_from_env_applies_defaults_when_env_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("LIVE_TEST_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("LIVE_TEST_FAIL_FAST_PREFLIGHT", raising=False)
    monkeypatch.delenv("LIVE_TEST_PROTECTED_ENDPOINTS", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("LIVE_TEST_ADMIN_EMAIL=tester@example.com\n", encoding="utf-8")

    config = configure_from_env(
        env_file,
        fail_fast_preflight=True,
        protected_endpoints={"fastapi": ["/category/"]},
    )

    assert config.admin_email == "tester@example.com"
    assert config.fail_fast_preflight is True
    assert config.protected_endpoints == {"fastapi": ["/category/"]}


def test_configure_from_env_loads_dotenv_from_current_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("LIVE_TEST_ADMIN_EMAIL", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "LIVE_TEST_ADMIN_EMAIL=cwd@example.com\n", encoding="utf-8"
    )

    config = configure_from_env()

    assert config.admin_email == "cwd@example.com"
