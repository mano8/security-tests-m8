# security-tests-m8

Reusable live security tests for FastAPI M8 auth and service stacks.

## Summary

`security-tests-m8` is a pytest plugin plus a set of reusable test suite classes. It lets any FastAPI M8 project run the same live security checks that were originally written for `fa-auth-m8`, without copying test files between repositories.

Use it to test:

- JWT structure and token forgery protections
- RS256, ES256, and HS256 algorithm behavior
- stateless, stateful, and hybrid token modes
- login abuse, authorization, IDOR, CORS, cookies, headers, metrics, health, private APIs, avatars, API keys, and rate limiting
- protected endpoints in one or more downstream FastAPI M8 services

The tests run against a real live stack. They do not mock your auth service. You point the package at your running auth URL, admin credentials, and optional service URLs, then inherit the suite classes you want in your own test files.

## Requirements

- Python 3.11 or newer
- `pytest`
- a running FastAPI M8 auth stack
- an admin account that can log in through `/login/access-token`
- optional downstream FastAPI M8 service URLs for protected endpoint tests

## Install

From this repository:

```bash
pip install -e .
```

From another project, install the package in the test environment:

```bash
pip install security-tests-m8
```

The package registers itself as a pytest plugin through the `pytest11` entry point, so fixtures and markers are available automatically after installation.

## Quick Start

Create or update `tests/live/conftest.py` in the project that will run the tests:

```python
from security_tests_m8 import configure

configure(
    auth_base_url="http://localhost:9000/user",
    service_base_url="http://localhost:9000/fastapi",
    admin_email="admin@example.com",
    admin_password="change-me",
)
```

Create a live test file and subclass the suites you want:

```python
from security_tests_m8.suites import (
    AuthAttackSuite,
    DeploymentPreflightSuite,
    JWTStructuralSuite,
    ProtectedEndpointSuite,
    SecurityHeadersSuite,
)


class TestAuthAttacks(AuthAttackSuite):
    pass


class TestJWTStructure(JWTStructuralSuite):
    pass


class TestSecurityHeaders(SecurityHeadersSuite):
    pass


class TestDeploymentPreflight(DeploymentPreflightSuite):
    pass


class TestCategoryEndpoint(ProtectedEndpointSuite):
    endpoint = "/category/"
```

Run the tests:

```bash
pytest tests/live -m live
```

## How It Works

The package has three parts:

1. Configuration is stored in a process-wide `LiveTestConfig`. You set it with `security_tests_m8.configure(...)` or environment variables.
2. The pytest plugin exposes fixtures such as `admin_token`, `admin_headers`, `regular_user`, `stack_config`, `service_base_url`, and `service_url`.
3. Suite classes contain the actual tests. Your project imports a suite and subclasses it, which makes pytest collect those tests in your project.

During collection, the plugin probes the configured auth stack and auto-skips tests that do not match the current deployment. For example, RS256-only tests are skipped on an HS256 stack, and stateful Redis checks are skipped if Redis is not available.

## Configuration

You can configure with Python:

```python
from pathlib import Path

from security_tests_m8 import configure

configure(
    auth_base_url="http://localhost:9000/user",
    admin_email="admin@example.com",
    admin_password="change-me",
    service_base_url="http://localhost:9000/fastapi",
    timeout=10,
    repo_root=Path(__file__).parents[2],
    deployment_root=Path(__file__).parents[2] / "examples/docker_compose/hardened_m8",
    public_base_url="https://localhost:4430",
    public_tls_verify=False,
    private_api_secret="change-me",
    refresh_secret_key="change-me",
)
```

Or with environment variables:

```bash
export LIVE_TEST_AUTH_BASE="http://localhost:9000/user"
export LIVE_TEST_ADMIN_EMAIL="admin@example.com"
export LIVE_TEST_ADMIN_PASSWORD="change-me"
export LIVE_TEST_SVC_BASE="http://localhost:9000/fastapi"
export LIVE_TEST_TIMEOUT="10"
export LIVE_TEST_DEPLOYMENT_ROOT="/path/to/repo/examples/docker_compose/hardened_m8"
export LIVE_TEST_PUBLIC_BASE="https://localhost:4430"
export LIVE_TEST_PUBLIC_TLS_VERIFY="false"
```

### Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `LIVE_TEST_AUTH_BASE` | Base URL for the auth service | `http://localhost:9000/user` |
| `LIVE_TEST_ADMIN_EMAIL` | Admin login email | `admin@example.com` |
| `LIVE_TEST_ADMIN_PASSWORD` | Admin login password | `changethis` |
| `LIVE_TEST_SVC_BASE` | Single/default downstream service URL | unset |
| `LIVE_TEST_SVC_BASES` | JSON object of named service URLs | `{}` |
| `LIVE_TEST_DEFAULT_SVC` | Default service name from `LIVE_TEST_SVC_BASES` | unset |
| `LIVE_TEST_TIMEOUT` | Request timeout in seconds | `10` |
| `LIVE_TEST_REPO_ROOT` | Repository root used to discover committed JWT keys | unset |
| `LIVE_TEST_DEPLOYMENT_ROOT` | Compose deployment directory used by `DeploymentPreflightSuite` | unset |
| `LIVE_TEST_PUBLIC_BASE` | Public HTTPS entrypoint for public/private route checks | `https://localhost:4430` |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | Verify TLS certificates for public URL checks | `true` |
| `LIVE_TEST_PRIVATE_API_SECRET` | Secret header value for private API tests | unset |
| `LIVE_TEST_REFRESH_SECRET_KEY` | Refresh-token secret used by refresh/cookie tests | unset |

## Single-Service Usage

For a project with one downstream service, configure `service_base_url` and subclass `ProtectedEndpointSuite` for each protected endpoint you want to verify.

```python
from security_tests_m8 import configure

configure(
    auth_base_url="http://localhost:9000/user",
    service_base_url="http://localhost:9000/fastapi",
    admin_email="admin@example.com",
    admin_password="change-me",
)
```

```python
from security_tests_m8.suites import ProtectedEndpointSuite


class TestCategories(ProtectedEndpointSuite):
    endpoint = "/category/"


class TestDashboardActivity(ProtectedEndpointSuite):
    endpoint = "/dashboard/users/activity/"
```

Each protected endpoint suite checks:

- no token is rejected with `401` or `403`
- an invalid bearer token is rejected with `401` or `403`
- a valid admin access token is accepted with `200`

## Multi-Service Usage

For a stack with several FastAPI M8 services, configure a named URL map.

```python
from security_tests_m8 import configure

configure(
    auth_base_url="http://localhost:9000/user",
    service_base_urls={
        "catalog": "http://localhost:9000/catalog",
        "orders": "http://localhost:9000/orders",
        "billing": "http://localhost:9000/billing",
    },
    default_service="catalog",
    admin_email="admin@example.com",
    admin_password="change-me",
)
```

The same setup can be provided from the shell:

```bash
export LIVE_TEST_SVC_BASES='{"catalog":"http://localhost:9000/catalog","orders":"http://localhost:9000/orders","billing":"http://localhost:9000/billing"}'
export LIVE_TEST_DEFAULT_SVC="catalog"
```

Then select the service per test class:

```python
from security_tests_m8.suites import ProtectedEndpointSuite


class TestCatalogCategories(ProtectedEndpointSuite):
    service = "catalog"
    endpoint = "/category/"


class TestOrderList(ProtectedEndpointSuite):
    service = "orders"
    endpoint = "/orders/"
```

If a suite names a service that is not configured, setup fails with a clear list of known service names.

## Available Suites

Universal auth and HTTP security suites:

- `AuthAttackSuite`
- `JWTStructuralSuite`
- `AuthorizationSuite`
- `RateLimitingSuite`
- `CORSSuite`
- `PrivateAPISuite`
- `MetricsAPISuite`
- `HealthAPISuite`
- `AvatarUrlSuite`
- `InfoDisclosureSuite`
- `SecurityHeadersSuite`
- `CookieSecuritySuite`
- `ApiKeySuite`

Token-mode suites:

- `StatelessContractSuite`
- `StatefulRevocationSuite`
- `StatefulAccessRevocationSuite`
- `HybridContractSuite`

JWT algorithm suites:

- `AsymmetricJWTSuite`
- `JWKSSuite`
- `CrossServiceTokenSuite`
- `HS256Suite`
- `HS256WeakKeySuite`

Generic service and deployment suites:

- `ProtectedEndpointSuite`
- `DeploymentPreflightSuite`

## Full Auth-Service Example

```python
from security_tests_m8.suites import (
    ApiKeySuite,
    AsymmetricJWTSuite,
    AuthAttackSuite,
    AuthorizationSuite,
    AvatarUrlSuite,
    CookieSecuritySuite,
    CORSSuite,
    CrossServiceTokenSuite,
    HealthAPISuite,
    HS256Suite,
    HS256WeakKeySuite,
    HybridContractSuite,
    InfoDisclosureSuite,
    JWKSSuite,
    JWTStructuralSuite,
    MetricsAPISuite,
    PrivateAPISuite,
    RateLimitingSuite,
    SecurityHeadersSuite,
    StatefulAccessRevocationSuite,
    StatefulRevocationSuite,
    StatelessContractSuite,
)


class TestAuthAttacks(AuthAttackSuite):
    pass


class TestJWTStructure(JWTStructuralSuite):
    pass


class TestAuthorization(AuthorizationSuite):
    pass


class TestRateLimiting(RateLimitingSuite):
    pass


class TestCORS(CORSSuite):
    pass


class TestPrivateAPI(PrivateAPISuite):
    pass


class TestMetrics(MetricsAPISuite):
    pass


class TestHealth(HealthAPISuite):
    pass


class TestAvatarUrls(AvatarUrlSuite):
    pass


class TestInfoDisclosure(InfoDisclosureSuite):
    pass


class TestSecurityHeaders(SecurityHeadersSuite):
    pass


class TestCookieSecurity(CookieSecuritySuite):
    pass


class TestApiKeys(ApiKeySuite):
    pass


class TestStatelessMode(StatelessContractSuite):
    pass


class TestStatefulRevocation(StatefulRevocationSuite):
    pass


class TestStatefulAccessRevocation(StatefulAccessRevocationSuite):
    pass


class TestHybridMode(HybridContractSuite):
    pass


class TestAsymmetricJWT(AsymmetricJWTSuite):
    pass


class TestJWKS(JWKSSuite):
    pass


class TestCrossServiceTokens(CrossServiceTokenSuite):
    pass


class TestHS256(HS256Suite):
    pass


class TestHS256WeakKeys(HS256WeakKeySuite):
    pass
```

## Pytest Markers

The plugin registers these markers:

- `live`
- `live_security`
- `live_asymmetric`
- `live_hs256`
- `live_stateful`
- `live_stateless`
- `live_hybrid`
- `live_deployment`
- `require_algorithm(*names)`
- `require_token_mode(*names)`
- `require_redis`
- `destructive`

Common commands:

```bash
pytest tests/live -m live
pytest tests/live -m "live and not destructive"
pytest tests/live -m live_asymmetric
pytest tests/live -m live_hs256
pytest tests/live -m live_stateful
pytest tests/live -m live_stateless
pytest tests/live -m live_hybrid
```

## Exposed Fixtures

These fixtures are available in consumer tests after the package is installed:

- `stack_config`
- `admin_token`
- `admin_headers`
- `admin_login`
- `regular_user`
- `live_jwks_keys`
- `committed_key_forge`
- `public_key_pem`
- `asymmetric_key_pem`
- `service_base_urls`
- `service_base_url`
- `service_url`

Example:

```python
def test_custom_protected_route(service_url, admin_headers):
    import requests

    response = requests.get(
        f"{service_url('catalog')}/category/",
        headers=admin_headers,
        timeout=10,
    )
    assert response.status_code == 200
```

## Notes for Live Stacks

- The tests use the configured admin account to create tokens and, for some suites, create a temporary regular user.
- Some tests are marked `destructive` because they exercise revocation, rate limiting, API key mutation, or other live state changes.
- Algorithm and token-mode specific tests are skipped automatically when they do not match the detected stack.
- `repo_root` or `LIVE_TEST_REPO_ROOT` is needed only for tests that try to compare live JWKS keys with committed private keys.
- `deployment_root` or `LIVE_TEST_DEPLOYMENT_ROOT` enables the Python deployment preflight suite for compose env/image checks.
- `public_tls_verify=False` is useful for local HTTPS stacks with self-signed certificates.

## Development

Install the package with development dependencies:

```bash
pip install -e ".[dev]"
```

Run local unit tests:

```bash
pytest
```

Run formatting and linting with your project tooling as needed. The package uses Ruff settings from `pyproject.toml`.

## Examples

A ready-to-run full security test example is available in [`examples/hardened_m8_full_security/`](examples/hardened_m8_full_security/).

This example runs the full reusable suite against the `fa-auth-m8` hardened Docker Compose stack:

- Tested compose stack: [`mano8/fa-auth-m8/examples/docker_compose/hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8)
- Local workspace path: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`
- Example in this repo: [`mano8/security-tests-m8/examples/hardened_m8_full_security`](https://github.com/mano8/security-tests-m8/tree/main/examples/hardened_m8_full_security)

The hardened stack uses RS256 access tokens, stateful token mode, Redis-backed revocation, PostgreSQL, Traefik, Prometheus, Grafana, and the sample `fastapi_full` consumer exposed at `/fastapi`. The example keeps its login, password, and shared secret values as `changethis` for local wiring.
