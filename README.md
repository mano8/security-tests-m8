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
- a dedicated test-only superuser that can log in through `/login/access-token`
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

## Quick Start: CLI

For normal stack validation, create a dedicated live-test env file for the test runner. From a stack directory such as `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`, create `test.env` with the `LIVE_TEST_*` values, replace any placeholder secret values, then run:

```bash
security-tests-m8 preflight --deployment-root .
security-tests-m8 run --env-file test.env
```

`security-tests-m8 run` keeps pytest as the execution engine internally, but it creates the temporary package test module for you. By default it runs `-m "live and not destructive"` so repeated CLI runs do not intentionally mutate login lockout, session, or rate-limit state. You can still pass pytest selection flags after `--`:

```bash
security-tests-m8 run --env-file test.env -- -ra
security-tests-m8 run --env-file test.env --include-destructive
security-tests-m8 run --env-file test.env -- -m live_asymmetric -ra
```

Useful commands:

```bash
security-tests-m8 run
security-tests-m8 run --env-file test.env
security-tests-m8 preflight
security-tests-m8 preflight --deployment-root .
security-tests-m8 scan-env --deployment-root .
security-tests-m8 list-suites
```

## Destructive vs Non-Destructive Tests

Non-destructive tests are designed to be safe for repeated normal validation runs. They read live endpoints, check token structure, verify access control, inspect headers/cookies, and avoid intentionally consuming lockout or revocation state. CLI `run` uses this mode by default with `-m "live and not destructive"`.

Destructive tests intentionally mutate live auth, session, API-key, revocation, or rate-limit state to prove the stack behaves under attack conditions. They may trigger login lockouts, revoke sessions or tokens, consume rate-limit counters, create or mutate test users/API keys, or make later tests fail until the stack state expires or is reset. Run them only when that side effect is acceptable.

Recommended normal run:

```bash
security-tests-m8 run --env-file test.env
```

Full mutation-heavy run:

```bash
security-tests-m8 run --env-file test.env --include-destructive
pytest --live-env-file test.env --pyargs security_tests_m8.full_security -m live
```

Equivalent non-destructive pytest run:

```bash
pytest --live-env-file test.env --pyargs security_tests_m8.full_security -m "live and not destructive"
```

## Quick Start: pytest

Use pytest mode when you want custom local tests, local suite subclasses, or direct pytest marker selection:

```bash
pytest --live-env-file test.env --pyargs security_tests_m8.full_security
pytest --live-env-file test.env tests/live
pytest --live-env-file test.env --pyargs security_tests_m8.full_security -m live_deployment
```

The package registers itself as a pytest plugin through the `pytest11` entry point. `--live-env-file` loads the same live-test env file used by CLI mode, and `--live-env-override` lets file values replace existing process environment variables.

For custom local tests, create a file that imports the packaged suite:

```python
from security_tests_m8.full_security import *  # noqa: F403
```

## How It Works

The package has three parts:

1. Configuration is stored in a process-wide `LiveTestConfig`. You set it with `security_tests_m8.configure(...)` or environment variables.
2. The pytest plugin exposes fixtures such as `admin_token`, `admin_headers`, `regular_user`, `stack_config`, `service_base_url`, and `service_url`.
3. Suite classes contain the actual tests. Your project imports a suite and subclasses it, which makes pytest collect those tests in your project.

When `fail_fast_preflight=True`, the plugin checks auth health, configured service availability, dedicated test-superuser login, and bootstrap-superuser misuse before collection. If the stack is unavailable or credentials are wrong, pytest exits before the full suite can trigger lockouts.

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

Or with a live-test env file loaded by CLI `run`, pytest `--live-env-file`, or `configure_from_env()`:

```bash
LIVE_TEST_AUTH_BASE=http://localhost:9000/user
LIVE_TEST_ADMIN_EMAIL=tester@example.com
LIVE_TEST_ADMIN_PASSWORD=change-this-test-password
LIVE_TEST_SVC_BASE=http://localhost:9000/fastapi
LIVE_TEST_TIMEOUT=10
LIVE_TEST_FAIL_FAST_PREFLIGHT=true
LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER=true
LIVE_TEST_DEPLOYMENT_ROOT=/path/to/repo/examples/docker_compose/hardened_m8
LIVE_TEST_PUBLIC_BASE=https://localhost:4430
LIVE_TEST_PUBLIC_TLS_VERIFY=false
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
| `LIVE_TEST_FAIL_FAST_PREFLIGHT` | Abort before collection if auth, services, or credentials are not usable | `false` |
| `LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER` | Refuse `FIRST_SUPERUSER` from `auth.env` as the test account | `true` |
| `LIVE_TEST_PROTECTED_ENDPOINTS` | JSON object of service names to protected endpoint arrays | `{}` |

## Choosing An Env File

`test.env` configures the test runner. It should contain `LIVE_TEST_*` values such as `LIVE_TEST_AUTH_BASE`, `LIVE_TEST_ADMIN_EMAIL`, `LIVE_TEST_ADMIN_PASSWORD`, `LIVE_TEST_SVC_BASES`, and `LIVE_TEST_DEPLOYMENT_ROOT`. `LIVE_TEST_PRIVATE_API_SECRET` and `LIVE_TEST_REFRESH_SECRET_KEY` are optional opt-in values; set them only when you want the secret-exposure checks to forge requests with the real stack secrets.

Deployment env files configure the stack itself. Files such as `.env`, `auth.env`, `api.env`, `media.env`, `grafana/.env`, and any other non-example `*.env` file under the deployment root are scanned by deployment preflight. Example/template files such as `.env.example`, `auth.env.example`, `api.env.example`, `media.env.example`, `grafana/.env.example`, and `test.env.example` are intentionally ignored. If you keep `test.env` under the deployment root, do not leave placeholder values such as `changethis` in it, because preflight will report them.

## Deployment Env Preflight

The deployment preflight scanner checks compose env files and inline compose `environment:` values for placeholder secrets, duplicate high-value secrets, unsafe production settings, default credentials, and unpinned images in hardened/production stacks.

```bash
security-tests-m8 preflight --deployment-root .
security-tests-m8 preflight --env-file test.env
security-tests-m8 preflight --deployment-root . --strict-warnings
```

It prints the exact env and compose files scanned, all findings, an explicit PASS/FAIL result, the reason for that result, and the required action. It exits `0` when there are no errors and `1` when errors are present. Warnings are printed but only fail the command with `--strict-warnings`.

## CLI vs pytest Mode

CLI mode is the simplest path for non-power users: point at an env file and run the packaged suite without adding local pytest files. It excludes `destructive` tests by default; use `--include-destructive` when you intentionally want full mutation-heavy coverage. Pytest mode is the right fit for teams that want custom tests, custom suite subclasses, project-specific fixtures, or direct use of pytest marker expressions.

Both modes use the same configuration model and the same reusable suites.

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
- `ConfiguredProtectedEndpointsSuite`
- `ServiceInfoDisclosureSuite`
- `ConfiguredServiceInfoDisclosureSuite`
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

- The tests use the configured dedicated test-only superuser to create tokens and, for some suites, create a temporary regular user.
- Do not use the stack bootstrap superuser (`FIRST_SUPERUSER`) as the live-test account. With fail-fast preflight enabled, the package refuses that configuration by default.
- Some tests are marked `destructive` because they exercise revocation, rate limiting, API key mutation, or other live state changes. CLI `run` excludes these by default; pass `--include-destructive` to run them.
- Algorithm and token-mode specific tests are skipped automatically when they do not match the detected stack.
- `repo_root` or `LIVE_TEST_REPO_ROOT` is needed only for tests that try to compare live JWKS keys with committed private keys.
- `deployment_root` or `LIVE_TEST_DEPLOYMENT_ROOT` enables the Python deployment preflight suite for compose env/image checks.
- `public_tls_verify=False` is useful for local HTTPS stacks with self-signed certificates.
- `LIVE_TEST_PRIVATE_API_SECRET` and `LIVE_TEST_REFRESH_SECRET_KEY` are opt-in checks. Leave them unset to skip those checks, or set them to the real values from the target stack.

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

The hardened stack uses RS256 access tokens, stateful token mode, Redis-backed revocation, PostgreSQL, Traefik, Prometheus, Grafana, and the sample `fastapi_full` consumer exposed at `/fastapi`. The example expects a dedicated test-only superuser. CLI mode loads the file passed with `--env-file`; the local pytest example loads `.env` from its own directory through `tests/live/conftest.py`.
