from pathlib import Path
from textwrap import dedent

from security_tests_m8.deployment import scan_deployment


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")


def _write_good_stack(root: Path) -> None:
    _write(
        root / ".env",
        """
        API_BIND_IP=127.0.0.1
        DB_PASSWORD=RootDbPassword_Aa1-0000000000000000000000000001
        AUTH_DB_PASSWORD=AuthDbPassword_Aa1-0000000000000000000000000002
        API_DB_PASSWORD=ApiDbPassword_Aa1-0000000000000000000000000003
        REDIS_PASSWORD=RedisPassword_Aa1-0000000000000000000000000004
        """,
    )
    _write(
        root / "auth.env",
        """
        ENVIRONMENT=production
        STRICT_PRODUCTION_MODE=true
        BACKEND_CORS_ORIGINS=https://app.example.com
        SET_DOCS=false
        SET_OPEN_API=false
        SET_REDOC=false
        DB_PASSWORD=AuthDbPassword_Aa1-0000000000000000000000000002
        EVENT_SIGNING_ENABLED=true
        TOKEN_STRICT_VALIDATION=true
        ACCESS_REVOCATION_FAILURE_MODE=fail_closed
        REFRESH_SECRET_KEY=RefreshSecret_Aa1-0000000000000000000000000005
        PRIVATE_API_SECRET=PrivateApiSecret_Aa1-0000000000000000000000000006
        SESSION_SECRET=SessionSecret_Aa1-0000000000000000000000000007
        TOKENS_ENCRYPTION_KEY=TokensEncryptionKey_Aa1-0000000000000000008
        EVENT_SIGNING_KEY=EventSigningKey_Aa1-00000000000000000000000009
        """,
    )
    _write(
        root / "api.env",
        """
        ENVIRONMENT=production
        BACKEND_CORS_ORIGINS=https://app.example.com
        SET_DOCS=false
        SET_OPEN_API=false
        SET_REDOC=false
        DB_PASSWORD=ApiDbPassword_Aa1-0000000000000000000000000003
        REFRESH_SECRET_KEY=RefreshSecret_Aa1-0000000000000000000000000005
        PRIVATE_API_SECRET=PrivateApiSecret_Aa1-0000000000000000000000000006
        EVENT_SIGNING_KEY=EventSigningKey_Aa1-00000000000000000000000009
        """,
    )
    _write(
        root / "docker-compose.yml",
        """
        services:
          auth_user_service:
            image: tepochtli/fa-auth-m8:1.2.3
            env_file:
              - ./auth.env
          fastapi_full:
            image: example/fastapi-m8:2.0.0
            env_file:
              - ./api.env
          postgres:
            image: postgres:18.4-alpine
        """,
    )


def _codes(root: Path) -> set[str]:
    return {finding.code for finding in scan_deployment(root).findings}


def test_generated_strong_values_pass_preflight(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)

    report = scan_deployment(tmp_path)

    assert report.errors == ()


def test_changethis_placeholder_fails_preflight(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(tmp_path / "auth.env", "REFRESH_SECRET_KEY=changethis")

    assert "placeholder-value" in _codes(tmp_path)


def test_duplicate_high_value_secrets_fail_preflight(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(
        tmp_path / "auth.env",
        """
        REFRESH_SECRET_KEY=SharedSecret_Aa1-000000000000000000000000
        PRIVATE_API_SECRET=SharedSecret_Aa1-000000000000000000000000
        """,
    )

    assert "duplicate-secret-value" in _codes(tmp_path)


def test_public_api_bind_fails_in_production(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(
        tmp_path / ".env",
        """
        API_BIND_IP=0.0.0.0
        DB_PASSWORD=RootDbPassword_Aa1-0000000000000000000000000001
        AUTH_DB_PASSWORD=AuthDbPassword_Aa1-0000000000000000000000000002
        API_DB_PASSWORD=ApiDbPassword_Aa1-0000000000000000000000000003
        REDIS_PASSWORD=RedisPassword_Aa1-0000000000000000000000000004
        """,
    )

    assert "public-api-bind" in _codes(tmp_path)


def test_latest_image_fails_for_hardened_or_production_stack(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          auth_user_service:
            image: tepochtli/fa-auth-m8:latest
            env_file:
              - ./auth.env
        """,
    )

    assert "latest-image" in _codes(tmp_path)


def test_default_vault_dev_token_fails_preflight(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(tmp_path / "vault.env", "VAULT_DEV_TOKEN=root")

    assert "vault-dev-token-default" in _codes(tmp_path)
