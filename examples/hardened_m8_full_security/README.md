# hardened_m8 full security test example

This example runs the full `security-tests-m8` live security suite against the `fa-auth-m8` hardened Docker Compose stack.

- Tested compose stack on GitHub: [`mano8/fa-auth-m8/examples/docker_compose/hardened_m8`](https://github.com/mano8/fa-auth-m8/tree/main/examples/docker_compose/hardened_m8)
- Local compose stack path: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`
- Example folder on GitHub: [`mano8/security-tests-m8/examples/hardened_m8_full_security`](https://github.com/mano8/security-tests-m8/tree/main/examples/hardened_m8_full_security)

It is built for the default hardened stack routes:

- auth service: `http://localhost:9000/user`
- downstream FastAPI service: `http://localhost:9000/fastapi`
- public HTTPS entrypoint: `https://localhost:4430`
- stack root and JWT keys: `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8`

All login values and shared secrets in this example are intentionally set to `changethis`.
That is useful for local example wiring only. Do not use these values for a real deployment.

## What It Runs

The example includes:

- universal auth security suites
- stateful/stateless/hybrid contract suites
- RS256/JWKS/cross-service JWT suites
- HS256 rejection and weak-key suites
- protected endpoint checks for `/fastapi/category/` and `/fastapi/dashboard/users/activity/`

The hardened stack is RS256 and stateful, so pytest automatically skips suites that do not apply to that detected stack.

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

Before the first boot, keep the local test values as `changethis`. In particular, set these values in the hardened stack env files:

```ini
# auth.env
FIRST_SUPERUSER=changethis
FIRST_SUPERUSER_PASSWORD=changethis
PRIVATE_API_SECRET=changethis
REFRESH_SECRET_KEY=changethis
SESSION_SECRET=changethis
TOKENS_ENCRYPTION_KEY=changethis
EVENT_SIGNING_KEY=changethis

# api.env
PRIVATE_API_SECRET=changethis
REFRESH_SECRET_KEY=changethis
EVENT_SIGNING_KEY=changethis

# .env
DB_PASSWORD=changethis
AUTH_DB_PASSWORD=changethis
API_DB_PASSWORD=changethis
REDIS_PASSWORD=changethis
```

The example test config also uses `LIVE_TEST_ADMIN_EMAIL=changethis` and `LIVE_TEST_ADMIN_PASSWORD=changethis`.

## Run The Example

Install `security-tests-m8` in editable mode:

```bash
cd /workspace/security-tests-m8
pip install -e .
```

Copy the example env file if you want shell-based configuration:

```bash
cd /workspace/security-tests-m8/examples/hardened_m8_full_security
cp .env.example .env
set -a
. ./.env
set +a
```

Then run the live tests:

```bash
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

The example defaults are defined in `tests/live/conftest.py` and can be overridden with environment variables.

| Variable | Example value |
| --- | --- |
| `LIVE_TEST_AUTH_BASE` | `http://localhost:9000/user` |
| `LIVE_TEST_SVC_BASE` | `http://localhost:9000/fastapi` |
| `LIVE_TEST_ADMIN_EMAIL` | `changethis` |
| `LIVE_TEST_ADMIN_PASSWORD` | `changethis` |
| `LIVE_TEST_PUBLIC_BASE` | `https://localhost:4430` |
| `LIVE_TEST_PUBLIC_TLS_VERIFY` | `false` |
| `LIVE_TEST_PRIVATE_API_SECRET` | `changethis` |
| `LIVE_TEST_REFRESH_SECRET_KEY` | `changethis` |
| `LIVE_TEST_REPO_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |
| `LIVE_TEST_DEPLOYMENT_ROOT` | `/workspace/fa-auth-m8/examples/docker_compose/hardened_m8` |

`LIVE_TEST_REPO_ROOT` lets asymmetric-key tests inspect the hardened stack's generated `keys/private.pem` and `keys/public.pem` files.
