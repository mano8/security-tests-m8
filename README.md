# security-tests-m8

![CI/CD](https://github.com/mano8/security-tests-m8/actions/workflows/CI.yaml/badge.svg?branch=main)
[![PyPI version](https://img.shields.io/pypi/v/security-tests-m8)](https://pypi.org/project/security-tests-m8/)
[![Python](https://img.shields.io/pypi/pyversions/security-tests-m8)](https://pypi.org/project/security-tests-m8/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/security-tests-m8?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/security-tests-m8)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/a412ae6b7fc443de829514a6c62ee5d4)](https://app.codacy.com/gh/mano8/security-tests-m8/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![codecov](https://codecov.io/gh/mano8/security-tests-m8/graph/badge.svg?token=8M408KN18A)](https://codecov.io/gh/mano8/security-tests-m8)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/mano8/security-tests-m8/blob/main/LICENSE)

Reusable live security tests for FastAPI M8 auth and service stacks.

## Table of Contents

- [Summary](#summary)
- [Requirements](#requirements)
- [Install](#install)
- [Quick Start: CLI](#quick-start-cli)
- [Destructive vs Non-Destructive Tests](#destructive-vs-non-destructive-tests)
- [Quick Start: pytest](#quick-start-pytest)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
- [Choosing An Env File](#choosing-an-env-file)
- [Deployment Env Preflight](#deployment-env-preflight)
- [CLI vs pytest Mode](#cli-vs-pytest-mode)
- [Single-Service Usage](#single-service-usage)
- [Multi-Service Usage](#multi-service-usage)
- [AI Gateway Suite](#ai-gateway-suite)
- [Available Suites](#available-suites)
- [Full Auth-Service Example](#full-auth-service-example)
- [Pytest Markers](#pytest-markers)
- [Exposed Fixtures](#exposed-fixtures)
- [Notes for Live Stacks](#notes-for-live-stacks)
- [Development](#development)
- [Examples](#examples)

## Summary

`security-tests-m8` is a pytest plugin plus a set of reusable test suite classes. It lets any FastAPI M8 project run the same live security checks that were originally written for `fa-auth-m8`, without copying test files between repositories.

It targets **any Docker Compose (or remote) stack whose issuer is `fa-auth-m8` and whose downstream services are built on `fastapi-m8`** — not only the hardened reference stack. The `hardened_m8` deployment is just the example used throughout this README; point the same suites at a minimal, staging, or production stack by changing configuration only. The plugin probes the live stack at collection time and auto-skips checks that do not apply to the detected algorithm, token mode, or available components (see [How It Works](#how-it-works)).

Use it to test:

- JWT structure and token forgery protections
- RS256, ES256, and HS256 algorithm behavior
- stateless, stateful, and hybrid token modes
- login abuse, authorization, IDOR, CORS, cookies, headers, metrics, health, private APIs, avatars, API keys, and rate limiting
- protected endpoints in one or more downstream FastAPI M8 services

The tests run against a real live stack. They do not mock your auth service. You point the package at your running auth URL, admin credentials, and optional service URLs, then inherit the suite classes you want in your own test files.

## Requirements

- Python 3.12 or newer
- `pytest`
- a running FastAPI M8 auth stack
- a dedicated test-only superuser that can log in through `/login/access-token`
- optional downstream FastAPI M8 service URLs for protected endpoint tests

## Install

From this repository:

```bash
pip install -e .
```

From another project, install (or update to the latest release) the package in the test environment:

```bash
pip install --upgrade security-tests-m8
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
2. The pytest plugin exposes fixtures such as `admin_token`, `admin_headers`, `fresh_admin_headers`, `regular_user`, `stack_config`, `service_base_url`, and `service_url`.
3. Suite classes contain the actual tests. Your project imports a suite and subclasses it, which makes pytest collect those tests in your project.

When `fail_fast_preflight=True`, the plugin checks auth health, configured service availability, dedicated test-superuser login, and bootstrap-superuser misuse before collection. If the stack is unavailable or credentials are wrong, pytest exits before the full suite can trigger lockouts.

During collection, the plugin probes the configured auth stack and auto-skips tests that do not match the current deployment. For example, RS256-only tests are skipped on an HS256 stack, and stateful Redis checks are skipped if Redis is not available.

### Canonical fixture matrix (§5.5, FIXTURE-01)

`auth-sdk-m8` is the single canonical owner of the shared role/flag/decision/event/introspection fixture matrix used across the M8 auth stack. This harness stays SDK-free by design — it never imports or installs `auth-sdk-m8` at runtime, so its coupling to the SDK is limited to the canonical role strings `security_tests_m8.forge` mints. Instead of consuming the matrix as installed package data, it **vendors** an identical, checked-in copy at `security_tests_m8/testing/authorization_matrix.json`, verified the same way on load via `security_tests_m8.testing.load_authorization_fixture_matrix()`: schema version and checksum are checked, and a hand-edited or stale copy fails closed rather than being silently trusted. `tests/test_fixture_matrix.py` asserts the vendored copy verifies and that `forge.py`'s canonical two-role claim pairing agrees with the fixture's role/flag truth table — re-copy the file (never hand-edit it) whenever `auth-sdk-m8` regenerates its matrix.

## Configuration

You can configure with Python:

```python
from pathlib import Path

from security_tests_m8 import configure

configure(
    auth_base_url="http://localhost:9000/user",
    admin_email="admin@example.com",
    admin_password="changethis",
    service_base_url="http://localhost:9000/fastapi",
    timeout=10,
    repo_root=Path(__file__).parents[2],
    deployment_root=Path(__file__).parents[2] / "examples/docker_compose/hardened_m8",
    public_base_url="https://localhost:4430",
    public_tls_verify=False,
    private_api_secret="changethis",
    private_api_client_id="media-service",
    refresh_secret_key="changethis",
)
```

Or with a live-test env file loaded by CLI `run`, pytest `--live-env-file`, or `configure_from_env()`:

```bash
LIVE_TEST_AUTH_BASE=http://localhost:9000/user
LIVE_TEST_INTERNAL_AUTH_BASE=http://localhost:9000/user
LIVE_TEST_AUTH_HEALTH_URL=http://localhost:9000/user/health/
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

For local HTTPS stacks that use a self-signed Traefik certificate, set
`LIVE_TEST_PUBLIC_TLS_VERIFY=false` to disable verification for the configured
live-test target URLs, or set it to a certificate bundle path such as
`/path/to/hardened_m8/traefik/certs/local.crt`.

### Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `LIVE_TEST_AUTH_BASE` | Base URL for the auth service | `http://localhost:9000/user` |
| `LIVE_TEST_INTERNAL_AUTH_BASE` | Internal service-to-service entrypoint that exposes `/private/*`. Hardened stacks block `/private` at the public edge (Traefik → 404), so the F06 per-consumer legacy-shape check targets this URL. Falls back to `LIVE_TEST_AUTH_BASE` when unset | unset |
| `LIVE_TEST_AUTH_HEALTH_URL` | Optional private/internal auth health URL used for readiness and stack detection | unset |
| `LIVE_TEST_ADMIN_EMAIL` | Admin login email | `admin@example.com` |
| `LIVE_TEST_ADMIN_PASSWORD` | Admin login password | `changethis` |
| `LIVE_TEST_SVC_BASE` | Single/default downstream service URL | unset |
| `LIVE_TEST_SVC_BASES` | JSON object of named service URLs | `{}` |
| `LIVE_TEST_DEFAULT_SVC` | Default service name from `LIVE_TEST_SVC_BASES` | unset |
| `LIVE_TEST_TIMEOUT` | Request timeout in seconds | `10` |
| `LIVE_TEST_REPO_ROOT` | Repository root used to discover committed JWT keys | unset |
| `LIVE_TEST_DEPLOYMENT_ROOT` | Compose deployment directory used by `DeploymentPreflightSuite` | unset |
| `LIVE_TEST_PUBLIC_BASE` | Public HTTPS entrypoint for public/private route checks | `https://localhost:4430` |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | TLS verification setting for configured live-test HTTPS target URLs; use `false` or a CA bundle path for local self-signed stacks | `true` |
| `LIVE_TEST_PRIVATE_API_SECRET` | Secret header value (`X-Internal-Token`) for private API tests | unset |
| `LIVE_TEST_PRIVATE_API_CLIENT_ID` | Per-consumer id (`X-Internal-Client`) for fa-auth-m8 >= 1.0.0 issuers; leave unset for legacy single-secret stacks | unset |
| `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` | Dedicated credential (`X-Internal-Token`) that unlocks the deep `/health` infrastructure detail (token mode, Redis/DB); falls back to `LIVE_TEST_PRIVATE_API_SECRET` for legacy stacks | unset |
| `LIVE_TEST_REFRESH_SECRET_KEY` | Refresh-token secret used by refresh/cookie tests | unset |
| `LIVE_TEST_FAIL_FAST_PREFLIGHT` | Abort before collection if auth, services, or credentials are not usable | `false` |
| `LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER` | Refuse `FIRST_SUPERUSER` from `auth.env` as the test account | `true` |
| `LIVE_TEST_PROTECTED_ENDPOINTS` | JSON object of service names to protected endpoint arrays | `{}` |
| `LIVE_TEST_CROSS_SERVICE_ENDPOINTS` | JSON object of service names to a single probe path, pinning the route `CrossServiceTokenSuite` uses per service; falls back to the first entry in `LIVE_TEST_PROTECTED_ENDPOINTS` | `{}` |
| `LIVE_TEST_MEDIA_PUBLIC_PREFIX` | Public path prefix the media stack is mounted under at the edge; the `MediaInternalExposureSuite` probes `<public-base>/<prefix>/v1/internal/*` | `media` |
| `LIVE_TEST_MEDIA_INTERNAL_TOKEN` | Worker `MEDIA_INTERNAL_SERVICE_TOKEN`; opt-in — proves a *valid* worker token is still blocked (404) at the public edge for `/media/v1/internal/*` | unset |
| `LIVE_TEST_API_KEY` | Known-valid plaintext API key (minted before a Redis outage); opt-in — the `ApiKeyRedisDegradedSuite` verifies it fails closed (503) while Redis is down | unset |
| `LIVE_TEST_API_KEY_STRICT_RATE_LIMIT` | Declares the stack runs strict API-key rate limiting (production/strict); opt-in — enables the fail-closed assertion for `ApiKeyRedisDegradedSuite` | `false` |

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

## Cross-Service Token Propagation

`CrossServiceTokenSuite` proves that every downstream consumer trusts the issuer's tokens and refuses forged ones. It is fully driven by configuration — no consumer name and no route is baked into the package — and runs once per configured service, using the same `LIVE_TEST_SVC_BASE` / `LIVE_TEST_SVC_BASES` / `LIVE_TEST_DEFAULT_SVC` model as every other suite.

The probe route for a service is resolved in this order:

1. `LIVE_TEST_CROSS_SERVICE_ENDPOINTS[service]`, when you want to pin one exact route.
2. The first entry of `LIVE_TEST_PROTECTED_ENDPOINTS[service]`.
3. Otherwise the service is skipped with an explicit reason.

Pick a route that returns `200` with an admin token and `401`/`403` without one. Rejection checks accept either `401` or `403`, since consumers differ in which they return.

```bash
export LIVE_TEST_SVC_BASES='{"reparto":"http://localhost:9000/reparto","media":"http://localhost:9000/media","prompt":"http://localhost:9000/prompt"}'
export LIVE_TEST_DEFAULT_SVC="reparto"
export LIVE_TEST_PROTECTED_ENDPOINTS='{"reparto":["/schools/"],"media":["/category/"],"prompt":["/prompt-template/"]}'
# optional: pin a different route for the cross-service probe only
export LIVE_TEST_CROSS_SERVICE_ENDPOINTS='{"reparto":"/academic-years/"}'
```

There is deliberately no fallback route. A guessed path that a consumer does not publish answers with an application `404`, which is not a refusal — probing it would report a missing route as an accepted forgery.

## AI Gateway Suite

`security-tests-m8 run --target ai-gateway` runs the live suite of an
`ai-gateway-m8` stack on its own, without the media services. Install the
`ai` extra: it signs job contexts through `ai-sdk-m8`'s public primitive.

```bash
pip install "security-tests-m8[ai]"
security-tests-m8 run --target ai-gateway --env-file ai-gateway.env --include-destructive
```

The suite needs three things from the stack, all addressed by configuration:

1. **Its own service client.** The gateway's compose stacks register a
   `security-tests` client in `AI_SERVICE_CLIENTS`, holding every execute scope
   and `job-context:issue`, keyed to a test issuer seed (`./secrets/test_client_secret`
   and `./secrets/test_issuer_seed`). The suite mints every job context with
   that seed. A deployment that serves real callers removes that client.
2. **The stub provider.** Provider calls go to
   [`security_tests_m8/ai_stub_provider.py`](security_tests_m8/ai_stub_provider.py),
   an OpenAI-compatible stub with only the standard library as a dependency.
   It records a fingerprint of each request's credential, never the value, and
   its control API (`/__stub/`) sets the keys it accepts and its answer mode:
   `ok`, `gzip_bomb`, `deep_json`, `status:<code>`, `throttle:<seconds>` or
   `delay:<seconds>`. Run it as the stack's allowlisted local provider name, on
   the network the gateway reaches local providers through:

   ```bash
   docker run -d --name ai-stub --network <project>_ai_net --network-alias ollama \
       --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000 \
       -e STUB_CONTROL_TOKEN=<token> --entrypoint python ai-gateway-m8:stack \
       -c "$(cat security_tests_m8/ai_stub_provider.py)" --port 11434
   ```

   Never expose the stub outside the stack under test.
3. **Container access** for the database, log and lifecycle rows: the compose
   project name and a container engine CLI. The suite finds containers by their
   compose labels, runs `psql`/`pg_dump` in the database container and starts
   copies of the gateway's services (same image, configuration and secrets,
   read-only, no capabilities, labelled as this suite's own). Without it those
   rows skip.

| Variable | Purpose |
| --- | --- |
| `LIVE_TEST_AI_BASE` | The gateway on the in-network path, with its prefix (`http://ai_gateway:8000/ai`, or `http://127.0.0.1:18080/ai` through the stack's `api` entrypoint) |
| `LIVE_TEST_PUBLIC_BASE`, `LIVE_TEST_AI_PUBLIC_PREFIX` | The public router and the gateway's prefix on it (default `ai`), for the ingress rows; `LIVE_TEST_PUBLIC_TLS_VERIFY` names the stack CA |
| `LIVE_TEST_AI_CLIENT_ID`, `LIVE_TEST_AI_CLIENT_SECRET` | The suite's service client (default id `security-tests`) |
| `LIVE_TEST_AI_ISSUER_SEED_FILE` | The test issuer's Ed25519 seed file |
| `LIVE_TEST_AI_STUB_BASE`, `LIVE_TEST_AI_STUB_CONTROL_TOKEN` | The stub as the suite reaches it, and its control token |
| `LIVE_TEST_AI_STUB_PROVIDER_URL` | The stub as the gateway reaches it, when that differs (default: `LIVE_TEST_AI_STUB_BASE`) |
| `LIVE_TEST_AI_HEALTH_DETAIL_CREDENTIAL`, `LIVE_TEST_AI_METRICS_CREDENTIAL` | The gateway's health-detail and metrics-scrape credentials |
| `LIVE_TEST_AI_PRODUCTION` | `false` on a development stack, where docs may be served (default `true`) |
| `LIVE_TEST_AI_COMPOSE_PROJECT`, `LIVE_TEST_CONTAINER_ENGINE` | Container access (engine default `docker`) |
| `LIVE_TEST_AI_DB_SERVICE`, `LIVE_TEST_AI_DB_NAME`, `LIVE_TEST_AI_AUTH_DB_NAME` | The database service and the gateway's and issuer's databases (defaults `m8_db`, `ai_db`, `auth_db`) |
| `LIVE_TEST_AI_TENANT_DAILY_BUDGET_UNITS`, `LIVE_TEST_AI_MAX_INFLIGHT_PER_CLIENT` | The stack's `AI_TENANT_DAILY_BUDGET_UNITS` and `AI_MAX_INFLIGHT_PER_CLIENT`, for the two-replica overspend and in-flight rows |
| `LIVE_TEST_AUTH_BASE`, `LIVE_TEST_ADMIN_EMAIL`, `LIVE_TEST_ADMIN_PASSWORD` | The issuer and its superuser |

What the suite proves, by class:

- `AiGatewayIngressSuite` — the public router stops `/ai/v1/execute`,
  `/ai/v1/internal`, metrics, docs and OpenAPI after path normalisation, strips
  the service-client headers, and keeps `/health` shallow; the gateway itself
  serves no docs under production and gates metrics and health detail.
- `AiGatewayContextSuite` — service-client authentication and the job-context
  matrix: missing, replayed (also concurrently), expired, not yet valid,
  over-TTL, another installation's `aud`, another `azp` or `iss`, the wrong
  capability or profile, a tampered signature, an unregistered or foreign key,
  an oversized header, a user JWT on an execution route.
- `AiGatewayDestinationSuite` — SSRF destinations refused at write time and at
  call time, the endpoint frozen once a credential exists, a decompression bomb
  and over-deep JSON refused typed, the schema refusing boundary and
  credential-scope changes, the runtime role unable to rewrite audit rows.
- `AiGatewaySecretsSuite` and the user-scope canary row — a used, rotated key
  absent from the database dump, the logs, the metrics and the API.
- `AiGatewayPolicySuite` — `rerank` never sent to an external profile (also
  when the binding is repointed after the context was minted), non-public data
  never sent to an external platform key, one tenant's invalid key leaving
  another tenant's traffic flowing, a disabled explicit credential never
  falling through to the global key, a throttled credential refused without a
  provider call.
- `AiGatewayUserScopeSuite` — personal BYOK enabled, a WRITER's own key through
  its whole lifecycle, other users, the tenant's ADMIN and lower tiers refused,
  the superuser's stop failing the user's next execution, user-binding
  precedence.
- `AiGatewayBootSuite` — web and scheduler refuse a database not at their
  packaged schema head, and another installation's `AI_DEPLOYMENT_ID`.
- `AiGatewaySettlementSuite` — a gateway killed after the provider received
  the request settles `charged_uncertain` exactly once under a new scheduler
  lease while the paused former leader commits nothing; a Vault stalled before
  the dispatch marker releases the execution (Vault stacks).
- `AiGatewayReplicaSuite` — with a second web replica: a cooldown honoured by
  both replicas, a concurrent overspend of a tenant's budget refused, the
  client's in-flight cap held.
- `AiGatewayRestoreSuite` — a snapshot restore detected, reconciled and
  ratified, restoring only what is re-confirmed.

Every class but the ingress one is `destructive`: it creates providers,
models, profiles, credentials, bindings and throwaway issuer accounts (the
accounts are deleted at teardown; providers and models cannot be deleted
through the API and stay behind, under unique `t88-` names), kills and pauses
containers, and changes database state. Run it against a test stack only. The
restore row runs last because ratification leaves the deployment's budget
hold in force until the next UTC day: every budgeted execution on that stack
is refused with `quota_exceeded` until then.

The cross-service rows (contexts minted by the media service, data classes
derived from live objects, the parser sandbox, storage identities,
provenance) need the integrated media stack and are absent here by design.

## Available Suites

Universal auth and HTTP security suites:

- `AuthAttackSuite`
- `JWTStructuralSuite`
- `AuthorizationSuite`
- `RateLimitingSuite`
- `CORSSuite`
- `PrivateAPISuite`
- `MediaInternalExposureSuite`
- `MetricsAPISuite`
- `HealthAPISuite`
- `AvatarUrlSuite`
- `InfoDisclosureSuite`
- `SecurityHeadersSuite`
- `CookieSecuritySuite`
- `ApiKeySuite`
- `ApiKeyRedisDegradedSuite`

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

AI gateway suites ([AI Gateway Suite](#ai-gateway-suite)):

- `AiGatewayIngressSuite`
- `AiGatewayContextSuite`
- `AiGatewayDestinationSuite`
- `AiGatewaySecretsSuite`
- `AiGatewayPolicySuite`
- `AiGatewayUserScopeSuite`
- `AiGatewayBootSuite`
- `AiGatewaySettlementSuite`
- `AiGatewayReplicaSuite`
- `AiGatewayRestoreSuite`

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
- `live_ai_gateway`
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
- `admin_headers` — session-scoped; one token minted at first use and reused for the whole run
- `fresh_admin_headers` — function-scoped; logs in for the individual test. Use it whenever the check's subject is that a **valid** token is accepted: on a stack that revokes the previous session at each login, the session-scoped token can be legitimately revoked by the time a later acceptance check runs
- `admin_login`
- `regular_user` — session-scoped; creates a throwaway `redteam_<hex>@redteam-test.com` non-superuser and deletes it (best-effort, via the admin account) at session teardown
- `live_jwks_keys`
- `committed_key_forge`
- `public_key_pem`
- `asymmetric_key_pem`
- `service_base_urls`
- `service_base_url`
- `service_url`
- `ai_gateway`, `ai_operator`, `ai_world`, `ai_stub`, `ai_replicas` — the AI
  gateway target, container access, the session's gateway objects, the stub
  provider and a second web replica ([AI Gateway Suite](#ai-gateway-suite))

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
- **Throwaway `redteam_*` user.** The `regular_user` fixture creates one non-superuser account per session with a random email of the form `redteam_<hex>@redteam-test.com` (password `RedTeam!Pass99`), used to prove that a normal user cannot escalate privileges or reach admin-only routes. The fixture **deletes that user at session teardown** through the admin account, so a normal run leaves no standing test identity behind. Deletion is best-effort: if the stack is unreachable when teardown runs, the account may survive and can be pruned manually (filter on the `redteam_*@redteam-test.com` pattern). The dedicated **superuser** you configure is never created or deleted by the suite — it must already exist and is yours to manage.
- Do not use the stack bootstrap superuser (`FIRST_SUPERUSER`) as the live-test account. With fail-fast preflight enabled, the package refuses that configuration by default.
- Some tests are marked `destructive` because they exercise revocation, rate limiting, API key mutation, or other live state changes. CLI `run` excludes these by default; pass `--include-destructive` to run them.
- Algorithm and token-mode specific tests are skipped automatically when they do not match the detected stack.
- `repo_root` or `LIVE_TEST_REPO_ROOT` is needed only for tests that try to compare live JWKS keys with committed private keys.
- `deployment_root` or `LIVE_TEST_DEPLOYMENT_ROOT` enables the Python deployment preflight suite for compose env/image checks.
- `public_tls_verify=False` is useful for local HTTPS stacks with self-signed certificates.
- `LIVE_TEST_PRIVATE_API_SECRET` and `LIVE_TEST_REFRESH_SECRET_KEY` are opt-in checks. Leave them unset to skip those checks, or set them to the real values from the target stack.
- `LIVE_TEST_PRIVATE_API_CLIENT_ID` is the per-consumer id sent as `X-Internal-Client` alongside `X-Internal-Token` so private-API probes authenticate against a per-consumer issuer (fa-auth-m8 >= 1.0.0, no shared-secret fallback). Set it together with `LIVE_TEST_PRIVATE_API_SECRET` to also enable the F06 legacy-detection check (the retired `X-Internal-Token`-only shape must be rejected with 401). Leave it unset for legacy single-secret stacks.
- `LIVE_TEST_INTERNAL_AUTH_BASE` is the internal service-to-service entrypoint that exposes `/private/*`. Hardened stacks block `/private` at the public edge (Traefik → 404), so the F06 legacy-shape rejection can only be observed against the internal entrypoint. Set it to that URL (e.g. `http://localhost:9000/user`) when `LIVE_TEST_AUTH_BASE` points at the public edge; it falls back to `LIVE_TEST_AUTH_BASE` when unset, which is correct for simple stacks whose base reaches private routes directly.
- `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` unlocks the deep `/health` infrastructure detail body (token mode, Redis/DB reachability, degradation modes) used by stack detection and the token-mode / disclosure suites. fa-auth-m8 >= 1.0.0 gates that detail on a dedicated credential decoupled from `PRIVATE_API_SECRET` (plan 9.3), sent via `X-Internal-Token`. Set it to the stack's `HEALTH_DETAIL_CREDENTIAL` so those health-dependent tests can read what they need; the probes fall back to `LIVE_TEST_PRIVATE_API_SECRET` only for legacy stacks that still reuse it for the health gate.
- **Unavailable services are skipped, not reported as failures.** If the reverse proxy returns `502`/`504` or Traefik's no-route `404 page not found`, or if the connection is dropped, the test is skipped rather than failing with a misleading security finding. `503` is excluded from this skip so the `ApiKeyRedisDegradedSuite` can still assert it as the secure fail-closed response, and so is a `502`/`504` whose body is a typed JSON error (an object with a string `code`): that is the target's own answer about an upstream it calls, such as the AI gateway refusing a hostile provider response.

## Workflow Policy Module

`security_tests_m8.workflow_policy` provides importable helpers for asserting CI/CD workflow compliance across any M8 repo. Import the functions you need in your own `tests/test_ci_policy.py`:

```python
from security_tests_m8.workflow_policy import (
    # Docker publish integrity (11.5)
    docker_publish_job_has_oidc_permission,
    docker_publish_job_has_attestation_permission,
    docker_publish_has_provenance,
    docker_publish_has_sbom_step,
    docker_publish_has_cosign_step,
    # PyPI Trusted Publishing (11.6)
    pypi_workflow_has_no_api_token,
    pypi_publish_job_has_oidc_permission,
    pypi_publish_job_has_protected_environment,
    # CI workflow policy (11.7)
    ci_has_no_duplicate_workflow,
    ci_has_secret_scan_job,
    # Reproducible dependency sets (11.8)
    constraints_file_exists,
    constraints_file_has_no_custom_index,
    constraints_file_pins_deps,
    lock_file_uses_require_hashes,
    # SHA-pin helpers
    load_workflow,
    action_refs,
    all_actions_sha_pinned,
)
```

Each function takes a `repo_root: Path` argument and returns a `bool`. Use them directly in pytest functions or as building blocks for custom policy assertions.

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

`hardened_m8` is only the reference target. The same example runs against **any compose stack that uses `fa-auth-m8` as the issuer and `fastapi-m8`-based consumers** — minimal, staging, or production — by adapting configuration only (auth/service URLs, protected endpoints, deployment root, and TLS settings). Two ready-to-adapt copies of this example live next to the stacks they test:

- [`fa-auth-m8/examples/docker_compose/shared_live_tests`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/shared_live_tests)
- [`media-service-m8/docker_compose/shared_live_tests`](https://github.com/mano8/media-service-m8/tree/main/docker_compose/shared_live_tests)
