# hardened_m8 full security test example

This example runs the full `security-tests-m8` live security suite against the `fa-auth-m8` hardened Docker Compose stack.

> **This example is not hardened-only.** `hardened_m8` is the reference target,
> but the exact same suite runs against **any compose stack that uses
> `fa-auth-m8` as the issuer and `fastapi-m8`-based consumers** (minimal,
> staging, or production). Only configuration changes — see
> [Adapting To Another Stack](#adapting-to-another-stack).

- Tested compose stack on GitHub: [`mano8/fa-auth-m8/examples/docker_compose/hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8)
- Local compose stack path: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`
- Example folder on GitHub: [`mano8/security-tests-m8/examples/hardened_m8_full_security`](https://github.com/mano8/security-tests-m8/tree/main/examples/hardened_m8_full_security)

It is built for the default hardened stack routes:

- auth service: `http://localhost:9000/user`
- downstream FastAPI service: `http://localhost:9000/fastapi`
- public HTTPS entrypoint: `https://localhost:4430`
- stack root and JWT keys: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`

The live tests require a dedicated test-only superuser. Do not use `FIRST_SUPERUSER` / `FIRST_SUPERUSER_PASSWORD` from `auth.env`; the package preflight refuses that by default.

During a run the suite also creates one throwaway non-superuser, `redteam_<hex>@redteam-test.com`, to attempt privilege escalation against admin-only routes. That account is **deleted automatically at the end of the test session** (best-effort, through the admin account), so a run leaves no standing test identity behind. The dedicated superuser you configure is never created or deleted by the suite — it stays under your control.

CLI mode is recommended for normal users and excludes destructive tests by default. This local pytest example is for custom tests, extra marker selection, and local suite extension. The unknown-route information-disclosure test now lives in the package full suite and no longer needs to be copied into this folder.

## What It Runs

The example runs every suite wired into `full_security`, including:

- universal auth security suites (attack, structural, authorization, rate limiting, CORS, headers, cookies, disclosure)
- stateful/stateless/hybrid token contract suites
- RS256/JWKS/cross-service JWT suites; HS256 rejection and weak-key suites
- protected endpoint checks for `/fastapi/category/` and `/fastapi/dashboard/users/activity/`
- **`MediaInternalExposureSuite`** (Category G) — proves media worker callbacks at
  `/media/v1/internal/*` are blocked at the public edge (proxy-layer `404`) with no
  bearer, a wrong bearer, and — when `LIVE_TEST_MEDIA_INTERNAL_TOKEN` is set — a
  valid worker token. Requires `LIVE_TEST_MEDIA_PUBLIC_PREFIX` (default `media`).
- **`ApiKeyRedisDegradedSuite`** (Category N) — proves a valid API key is refused
  with `503` in production/strict posture when Redis is down. Opt-in: runs only when
  `LIVE_TEST_API_KEY` and `LIVE_TEST_API_KEY_STRICT_RATE_LIMIT=true` are set and
  the health detail confirms Redis is degraded.

Suites that do not match the detected stack (algorithm, token mode, Redis availability,
available opt-in config) are skipped automatically — the same file works across
HS256/RS256/ES256 and stateless/stateful/hybrid stacks without edits.

**Unavailable services are skipped, not reported as failures.** If the reverse proxy
returns `502`/`504`, Traefik's no-route `404 page not found`, or the connection is
dropped, the test is converted to a skip so a briefly unreachable backend never
appears as a false security finding.

## Files

```text
examples/hardened_m8_full_security/
├── .env.example
├── pytest.ini
├── README.md
└── tests/live/
    ├── conftest.py
    └── test_full_security.py
```

## Start The Hardened Stack

From the hardened stack directory:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/hardened_m8
cp .env.example .env
cp auth.env.example auth.env
cp api.env.example api.env
bash init.sh
docker compose up -d
```

Before running the live tests, create a dedicated superuser for the test suite. Put that account in the live-test env file you use for the run:

```ini
LIVE_TEST_ADMIN_EMAIL=tester@example.com
LIVE_TEST_ADMIN_PASSWORD=change-this-test-password
```

The account must already exist in the auth stack and must have superuser permissions.

## Run With The Recommended CLI Mode

Install `security-tests-m8` in editable mode:

```bash
cd /workspace/security-tests-m8
pip install -e .
```

From the hardened stack directory, keep stack configuration in `.env`, `auth.env`, `api.env`, `media.env`, and `grafana/.env`, then create a dedicated `test.env` for the live-test runner values:

```bash
cd /workspace/fa-auth-m8/examples/docker_compose/hardened_m8
cp test.env.example test.env
# Edit test.env with the dedicated test account and, if used, real opt-in secrets.
security-tests-m8 preflight --deployment-root .
security-tests-m8 run --env-file test.env
# Optional full mutation-heavy run:
security-tests-m8 run --env-file test.env --include-destructive
```

Deployment preflight scans non-example `*.env` files under the deployment root, including `test.env` if you keep it there. Do not leave `changethis` or other placeholder values in `test.env`; either replace the opt-in secret values with the real values from `auth.env` / `api.env`, or omit those variables to skip their opt-in checks.

## Run This Advanced Pytest Example

Use this folder when you want local pytest customization, marker selection, or extra local tests layered on top of the reusable package suite.

Copy the example env file, edit the dedicated test credentials, then run pytest from this directory. The package loads `.env` from the current directory automatically:

```bash
cd /workspace/security-tests-m8/examples/hardened_m8_full_security
cp .env.example .env
pytest
```

Useful marker selections:

```bash
pytest -m live
pytest -m "live and not destructive"
pytest -m live_asymmetric
pytest -m live_stateful
```

## Configuration Values

The example defaults are defined in `tests/live/conftest.py` and can be overridden with environment variables. All variables are also documented inline in `.env.example`.

| Variable | Example value | Notes |
| --- | --- | --- |
| `LIVE_TEST_AUTH_BASE` | `http://localhost:9000/user` | Public auth base URL |
| `LIVE_TEST_INTERNAL_AUTH_BASE` | `http://localhost:9001/user` | Internal entrypoint for `/private/*`; falls back to `LIVE_TEST_AUTH_BASE` when unset |
| `LIVE_TEST_SVC_BASE` | `http://localhost:9000/fastapi` | Single/default downstream service |
| `LIVE_TEST_SVC_BASES` | `{"fastapi":"http://localhost:9000/fastapi"}` | Named service map |
| `LIVE_TEST_DEFAULT_SVC` | `fastapi` | Default service name |
| `LIVE_TEST_ADMIN_EMAIL` | `tester@example.com` | Dedicated test superuser — never use `FIRST_SUPERUSER` |
| `LIVE_TEST_ADMIN_PASSWORD` | `change-this-test-password` | Test superuser password |
| `LIVE_TEST_PUBLIC_BASE` | `https://localhost:4430` | Public HTTPS edge for header/CORS/media-ingress checks |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | `false` | `false` = skip (self-signed); `true` = system CA; path = bundle |
| `LIVE_TEST_PRIVATE_API_SECRET` | real `PRIVATE_API_SECRET` | Opt-in; unlocks F01–F05 private-API probes. Unset = skip |
| `LIVE_TEST_PRIVATE_API_CLIENT_ID` | per-consumer id, e.g. `media-service` | Opt-in; per-consumer id for fa-auth-m8 >= 1.0.0. Set with `LIVE_TEST_PRIVATE_API_SECRET` to also enable F06 |
| `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` | real `HEALTH_DETAIL_CREDENTIAL` | Opt-in; unlocks deep `/health` detail (token mode, Redis/DB). Falls back to `LIVE_TEST_PRIVATE_API_SECRET` for legacy stacks |
| `LIVE_TEST_REFRESH_SECRET_KEY` | real `REFRESH_SECRET_KEY` | Opt-in; enables refresh-token and cookie tests |
| `LIVE_TEST_MEDIA_PUBLIC_PREFIX` | `media` | Edge prefix for media suites (default `media`) |
| `LIVE_TEST_MEDIA_INTERNAL_TOKEN` | real `MEDIA_INTERNAL_SERVICE_TOKEN` | Opt-in; enables the valid-worker-token probe in `MediaInternalExposureSuite` |
| `LIVE_TEST_API_KEY` | valid plaintext API key | Opt-in; minted before Redis outage for `ApiKeyRedisDegradedSuite` |
| `LIVE_TEST_API_KEY_STRICT_RATE_LIMIT` | `true` | Opt-in; declares strict posture to enable fail-closed assertion |
| `LIVE_TEST_FAIL_FAST_PREFLIGHT` | `true` | Abort before collection if auth/services/credentials are not usable |
| `LIVE_TEST_FORBID_BOOTSTRAP_SUPERUSER` | `true` | Refuse `FIRST_SUPERUSER` as the test account |
| `LIVE_TEST_PROTECTED_ENDPOINTS` | `{"fastapi":["/category/","/dashboard/users/activity/"]}` | Routes for `ConfiguredProtectedEndpointsSuite` |
| `LIVE_TEST_TIMEOUT` | `10` | Request timeout in seconds |
| `LIVE_TEST_REPO_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` | Stack root; asymmetric-key tests read `keys/private.pem` from here |
| `LIVE_TEST_DEPLOYMENT_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` | Compose directory for deployment preflight |

## Adapting To Another Stack

Nothing here is specific to `hardened_m8` beyond the configuration values. To
point this example at a different `fa-auth-m8` + `fastapi-m8` stack, copy this
folder (or just its `.env`) and change configuration only:

1. **Auth URL** — set `LIVE_TEST_AUTH_BASE` to your issuer's public base
   (for example `https://auth.example.com/user`).
2. **Service URL(s)** — set `LIVE_TEST_SVC_BASE` (single service) or
   `LIVE_TEST_SVC_BASES` + `LIVE_TEST_DEFAULT_SVC` (named map) to your
   `fastapi-m8` consumers.
3. **Protected endpoints** — set `LIVE_TEST_PROTECTED_ENDPOINTS` to the real
   read endpoints of each service so `ConfiguredProtectedEndpointsSuite` covers
   them.
4. **Public entrypoint / TLS** — set `LIVE_TEST_PUBLIC_BASE` and, for
   self-signed local certs, `LIVE_TEST_PUBLIC_TLS_VERIFY=false` (or a CA bundle
   path); for a real CA, leave verification on.
5. **Roots** — point `LIVE_TEST_DEPLOYMENT_ROOT` at the target compose
   directory for deployment preflight, and `LIVE_TEST_REPO_ROOT` at the stack
   that holds the committed JWT keys (only needed for the asymmetric key-leak
   checks).

The suites that do not match the detected algorithm, token mode, or available
components (Redis, JWKS, private API) skip automatically, so the same file works
across HS256/RS256/ES256 and stateless/stateful/hybrid stacks without edits.
