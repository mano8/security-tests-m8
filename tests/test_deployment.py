from pathlib import Path
from textwrap import dedent

import pytest

from security_tests_m8.deployment import (
    DeploymentFinding,
    DeploymentPreflightReport,
    scan_deployment,
)


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


def test_env_discovery_scans_real_env_files_and_ignores_examples(
    tmp_path: Path,
) -> None:
    _write(tmp_path / ".env", "ROOT_SECRET=changethis")
    _write(tmp_path / "auth.env", "AUTH_SECRET=changethis")
    _write(tmp_path / "api.env", "API_SECRET=changethis")
    _write(tmp_path / "media.env", "MEDIA_SECRET=changethis")
    _write(tmp_path / "grafana/.env", "GRAFANA_SECRET=changethis")
    _write(tmp_path / "compose.env", "COMPOSE_FILE_SECRET=changethis")

    _write(tmp_path / ".env.example", "EXAMPLE_ROOT_SECRET=changethis")
    _write(tmp_path / "auth.env.example", "EXAMPLE_AUTH_SECRET=changethis")
    _write(tmp_path / "api.env.example", "EXAMPLE_API_SECRET=changethis")
    _write(tmp_path / "media.env.example", "EXAMPLE_MEDIA_SECRET=changethis")
    _write(tmp_path / "grafana/.env.example", "EXAMPLE_GRAFANA_SECRET=changethis")
    _write(tmp_path / "compose.env.example", "EXAMPLE_COMPOSE_SECRET=changethis")

    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          api:
            image: example/api:1.0.0
            env_file:
              - ./compose.env
              - ./auth.env.example
              - path: ./api.env.example
            environment:
              COMPOSE_ENVIRONMENT_SECRET: changethis
        """,
    )

    report = scan_deployment(tmp_path)
    placeholder_locations = {
        (finding.path.relative_to(tmp_path).as_posix(), finding.key)
        for finding in report.findings
        if finding.code == "placeholder-value"
    }

    assert (".env", "ROOT_SECRET") in placeholder_locations
    assert ("auth.env", "AUTH_SECRET") in placeholder_locations
    assert ("api.env", "API_SECRET") in placeholder_locations
    assert ("media.env", "MEDIA_SECRET") in placeholder_locations
    assert ("grafana/.env", "GRAFANA_SECRET") in placeholder_locations
    assert ("compose.env", "COMPOSE_FILE_SECRET") in placeholder_locations
    assert ("docker-compose.yml", "COMPOSE_ENVIRONMENT_SECRET") in placeholder_locations
    assert not any(path.endswith(".example") for path, _ in placeholder_locations)


def test_report_lists_scanned_deployment_files(tmp_path: Path) -> None:
    _write_good_stack(tmp_path)
    _write(tmp_path / "grafana/.env", "GF_SECURITY_ADMIN_PASSWORD=StrongPassword1")
    _write(tmp_path / "auth.env.example", "IGNORED_SECRET=changethis")

    report = scan_deployment(tmp_path)
    scanned = {path.relative_to(tmp_path).as_posix() for path in report.scanned_files}

    assert scanned == {
        ".env",
        "api.env",
        "auth.env",
        "docker-compose.yml",
        "grafana/.env",
    }


def test_finding_format_handles_paths_outside_root_and_missing_key(
    tmp_path: Path,
) -> None:
    finding = DeploymentFinding(
        code="outside-root",
        message="outside root",
        severity="warning",
        path=tmp_path.parent / "outside.env",
    )

    assert finding.format(tmp_path).startswith("WARNING outside-root ")
    assert "outside.env - outside root" in finding.format(tmp_path)


def test_report_assert_no_errors_lists_error_findings(tmp_path: Path) -> None:
    finding = DeploymentFinding(
        code="boom",
        message="broken",
        severity="error",
        path=tmp_path / "auth.env",
        key="SECRET",
    )
    report = DeploymentPreflightReport(root=tmp_path, findings=(finding,))

    with pytest.raises(AssertionError, match="ERROR boom auth.env:SECRET"):
        report.assert_no_errors()


def test_env_parser_handles_exports_quotes_and_invalid_lines(tmp_path: Path) -> None:
    env_file = tmp_path / "quoted.env"
    env_file.write_text(
        "\n# ignored\nNO_EQUALS\nexport QUOTED='hello'\n =bad\nPLAIN=world\n",
        encoding="utf-8",
    )

    report = scan_deployment(tmp_path)
    values = {(finding.path.name, finding.key) for finding in report.findings}

    assert values == set()
    scanned = {path.name for path in report.scanned_files}
    assert "quoted.env" in scanned


def test_scan_deployment_rejects_missing_root(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_deployment(tmp_path / "missing")


def test_compose_edge_cases_cover_scanner_branches(tmp_path: Path) -> None:
    _write(tmp_path / ".pytest_cache/ignored.env", "IGNORED_SECRET=changethis")
    _write(tmp_path / "api.env", "API_SECRET=strong-value")
    _write(tmp_path / "compose.yml", "[1]")
    _write(tmp_path / "compose.yaml", "services: []")
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          api:
            image: example/api:latest
            env_file: ./api.env
            environment:
              - ENVIRONMENT=production
              - BACKEND_CORS_ORIGINS=http://localhost:5173
              - SET_DOCS=true
              - EMPTY_SECRET=
              - COMMENT_SECRET=# copied from template
              - PRIVATE_API_SECRET=
              - GF_SECURITY_ADMIN_PASSWORD=admin
              - DB_PASSWORD=postgres
          worker:
            image: example/worker:1.0.0
            environment:
              OPTIONAL_VALUE:
        """,
    )

    report = scan_deployment(tmp_path)
    codes = {finding.code for finding in report.findings}
    scanned = {path.relative_to(tmp_path).as_posix() for path in report.scanned_files}

    assert "api.env" in scanned
    assert ".pytest_cache/ignored.env" not in scanned
    assert {
        "latest-image",
        "localhost-cors-production",
        "docs-enabled-production",
        "empty-sensitive-value",
        "placeholder-comment-value",
        "grafana-admin-password-default",
        "root-db-password-default",
    }.issubset(codes)


def test_strict_mode_makes_degradation_policy_errors(tmp_path: Path) -> None:
    _write(
        tmp_path / "auth.env",
        """
        STRICT_PRODUCTION_MODE=true
        EVENT_SIGNING_ENABLED=false
        TOKEN_STRICT_VALIDATION=false
        ACCESS_REVOCATION_FAILURE_MODE=fail_open
        """,
    )

    report = scan_deployment(tmp_path)
    severities = {finding.code: finding.severity for finding in report.findings}

    assert severities["event-signing-disabled"] == "error"
    assert severities["token-strict-validation-disabled"] == "error"
    assert severities["revocation-fail-open"] == "error"


def test_public_bind_break_glass_allows_production_bind(tmp_path: Path) -> None:
    _write(
        tmp_path / ".env",
        """
        ENVIRONMENT=production
        API_BIND_IP=0.0.0.0
        ALLOW_PUBLIC_API_BIND=true
        """,
    )

    assert "public-api-bind" not in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Docker socket mount checks (_scan_docker_socket_mounts / _volume_source)
# ---------------------------------------------------------------------------


def _write_hardened_env(root: Path) -> None:
    """Write a minimal production env so the stack is treated as hardened."""
    _write(root / "auth.env", "ENVIRONMENT=production\n")


def test_docker_socket_string_volume_fails_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock:ro
        """,
    )

    assert "docker-socket-mount" in _codes(tmp_path)


def test_docker_socket_long_form_volume_fails_for_hardened_stack(
    tmp_path: Path,
) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            volumes:
              - type: bind
                source: /var/run/docker.sock
                target: /var/run/docker.sock
                read_only: true
        """,
    )

    assert "docker-socket-mount" in _codes(tmp_path)


def test_non_socket_volumes_pass_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            volumes:
              - ./data:/data
              - type: bind
                source: ./config
                target: /etc/app/config
        """,
    )

    assert "docker-socket-mount" not in _codes(tmp_path)


def test_bare_volume_entry_does_not_cause_false_positive(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        # YAML integer volume entries (malformed but parseable) must not raise.
        "services:\n  app:\n    image: example/app:1.0.0\n    volumes:\n      - 9000\n",
    )

    assert "docker-socket-mount" not in _codes(tmp_path)


def test_docker_socket_skipped_for_dev_stack(tmp_path: Path) -> None:
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock:ro
        """,
    )
    # No env file → not flagged as hardened/production.

    assert "docker-socket-mount" not in _codes(tmp_path)


# ---------------------------------------------------------------------------
# Public service port checks (_scan_public_service_ports / _port_binds_publicly)
# ---------------------------------------------------------------------------


def test_host_container_port_fails_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            ports:
              - "8000:80"
        """,
    )

    assert "public-service-port" in _codes(tmp_path)


def test_explicit_0000_port_fails_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          minio:
            image: quay.io/minio/minio:1.0.0
            ports:
              - "0.0.0.0:9005:9000"
        """,
    )

    assert "public-service-port" in _codes(tmp_path)


def test_port_with_protocol_suffix_fails_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            ports:
              - "4430:443/tcp"
        """,
    )

    assert "public-service-port" in _codes(tmp_path)


def test_loopback_port_passes_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          grafana:
            image: grafana/grafana:1.0.0
            ports:
              - "127.0.0.1:3000:3000"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_variable_ip_port_passes_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            ports:
              - "${API_BIND_IP:-127.0.0.1}:9000:9000"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_variable_host_port_passes_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - "${PORT}:80"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_bare_port_passes_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - "80"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_long_form_port_empty_host_ip_fails_for_hardened_stack(
    tmp_path: Path,
) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - target: 80
                published: 8080
        """,
    )

    assert "public-service-port" in _codes(tmp_path)


def test_long_form_port_explicit_0000_fails_for_hardened_stack(
    tmp_path: Path,
) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - target: 80
                published: 8080
                host_ip: "0.0.0.0"
        """,
    )

    assert "public-service-port" in _codes(tmp_path)


def test_long_form_port_loopback_passes_for_hardened_stack(tmp_path: Path) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - target: 8080
                published: 8080
                host_ip: "127.0.0.1"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_long_form_port_variable_ip_passes_for_hardened_stack(
    tmp_path: Path,
) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - target: 9000
                published: 9000
                host_ip: "${API_BIND_IP:-127.0.0.1}"
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_long_form_port_no_published_passes_for_hardened_stack(
    tmp_path: Path,
) -> None:
    _write_hardened_env(tmp_path)
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          app:
            image: example/app:1.0.0
            ports:
              - target: 80
        """,
    )

    assert "public-service-port" not in _codes(tmp_path)


def test_public_service_port_skipped_for_dev_stack(tmp_path: Path) -> None:
    _write(
        tmp_path / "docker-compose.yml",
        """
        services:
          traefik:
            image: traefik:v3.7.5
            ports:
              - "8000:80"
        """,
    )
    # No env file → not flagged as hardened/production.

    assert "public-service-port" not in _codes(tmp_path)
