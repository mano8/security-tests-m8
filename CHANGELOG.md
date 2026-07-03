# Changelog

## Unreleased

### Added

- **11.5/11.6 Reusable workflow policy checks + PyPI Trusted Publishing.** New
  `security_tests_m8/workflow_policy.py` module provides 11 importable functions
  for asserting CI/CD workflow compliance in any M8 repo: Docker publish integrity
  (`docker_publish_job_has_oidc_permission`, `docker_publish_job_has_attestation_permission`,
  `docker_publish_has_provenance`, `docker_publish_has_sbom_step`,
  `docker_publish_has_cosign_step`) and PyPI Trusted Publishing
  (`pypi_workflow_has_no_api_token`, `pypi_publish_job_has_oidc_permission`,
  `pypi_publish_job_has_protected_environment`) plus SHA-pinning helpers
  (`action_refs`, `all_actions_sha_pinned`, `load_workflow`). `tests/test_ci_policy.py`
  adds 45 tests: 7 verify this repo's own `PiPy.yml`/`CI.yaml` invariants (11.6 gate),
  38 cover every function branch with synthetic workflow fixtures. Own `PiPy.yml`
  updated: `PYPI_API_TOKEN` removed (OIDC Trusted Publishing is now the only publish
  path) and environment URL corrected from `fastapi-m8` to `security-tests-m8`.

- **11.3 API-key Redis-degraded fail-closed suite.** New reusable
  `ApiKeyRedisDegradedSuite` (Category N) proves that in production/strict
  posture a *valid* API key is refused with `503` when Redis rate limiting is
  unavailable, rather than silently accepted without limits. It is the mirror of
  `ApiKeySuite` M03/M04 (which are `require_redis` and skip when Redis is down):
  this suite runs only while Redis is degraded. Opt-in and self-skipping — it
  asserts only when strict posture is declared and health detail confirms Redis
  is down. Wired into `full_security` as `TestApiKeyRedisDegraded`.
  - New config: opt-in `LIVE_TEST_API_KEY` (known-valid plaintext key minted
    before the outage) and `LIVE_TEST_API_KEY_STRICT_RATE_LIMIT`, exposed on
    `LiveTestConfig` via `api_key_verify_headers()` and
    `expect_api_key_fail_closed()`.

- **11.1 Media internal callback ingress exposure suite.** New reusable
  `MediaInternalExposureSuite` (Category G) proves that media worker callbacks
  under `/media/v1/internal/*` are blocked at the public edge (proxy-layer 404)
  with no bearer, a wrong bearer, and — opt-in — a *valid* worker token, so a
  stolen `MEDIA_INTERNAL_SERVICE_TOKEN` cannot be replayed through the public
  domain. Wired into `full_security` as `TestMediaInternalExposure`.
  - New config: `LIVE_TEST_MEDIA_PUBLIC_PREFIX` (default `media`) and opt-in
    `LIVE_TEST_MEDIA_INTERNAL_TOKEN`, exposed on `LiveTestConfig` via
    `media_internal_base_url()` and `media_internal_headers()`.

## 0.3.0 — 2026-06-28

### Fixed

- **F06 legacy-shape check now targets the internal entrypoint.** The
  `test_f06_legacy_token_only_rejected_under_per_consumer_model` probe built its
  URL from `LIVE_TEST_AUTH_BASE`. On hardened stacks that base is the public
  Traefik edge, which blocks `/private` (→ 404) before the request reaches the
  issuer — so F06 saw 404 instead of the expected 401 and failed, contradicting
  the F01–F04 checks that assert that same 404. The probe now targets a new
  `LIVE_TEST_INTERNAL_AUTH_BASE` (via `LiveTestConfig.private_api_base_url()`),
  the internal service-to-service entrypoint that exposes `/private/*`. It falls
  back to `LIVE_TEST_AUTH_BASE` when unset, preserving behaviour for simple
  stacks whose base reaches private routes directly.

### Changed

- **9.4 Design B harness alignment** — `HealthAPISuite` (F3) flipped from
  "assert 404 (blocked by Traefik)" to "assert 200 with constant
  `{"status":"ok"}` body; assert no detail keys in ungated response". Reflects
  the Design B decision: `/health` is publicly routed through Traefik but the
  ungated body is a constant liveness response (no Redis/DB/token-mode leak).
  Detail remains credential-gated via `HEALTH_DETAIL_CREDENTIAL` (plan 9.3).
  - `test_f3_01` renamed: `health_publicly_reachable_with_shallow_constant_body`.
  - `test_f3_02` renamed: `unauthenticated_health_body_has_no_detail_keys`.
  - `test_f3_03` added: `health_absent_from_openapi` (was the former `test_f3_02`).

- **Detection honesty** — `StackInfo` gains two new fields: `detail_available`
  (True when the health response contained readable infra detail, i.e.
  `HEALTH_DETAIL_CREDENTIAL` was honoured) and `token_mode_known` (True when
  token mode was read from health detail or from `LIVE_TEST_TOKEN_MODE` / env
  config). `require_redis` / `live_stateful` / `live_hybrid` tests now skip with
  an explicit reason when `detail_available=False`; `require_token_mode` tests
  skip with an explicit reason when `token_mode_known=False`, instead of
  silently running blind on defaults. Set `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL`
  (or `LIVE_TEST_TOKEN_MODE`) to enable these suites.

## 0.2.0 — 2026-06-27

### Security

- **P2.3 trusted dependency audit in CI** — `pip-audit` added to the CI
  `security` job. Audits installed runtime dependencies against the PyPA
  advisory database on every PR and push to `main`. Audit runs inside
  GitHub Actions (a trusted environment); the local rule stands: do not
  run advisory-service queries from developer machines where private
  dependency metadata may be sent to an external service.
  Data-sharing expectation: `pip-audit` queries the PyPA advisory
  database (public vulnerability data); no private package metadata
  beyond package names and versions is transmitted. A `secret-scan` job
  using gitleaks was also added to detect accidental credential commits.
  The duplicate `ci.yml` workflow (which also ran `pip-audit` in a
  combined job) was removed; `CI.yaml` is now the canonical CI workflow.

- **P0.4 release artifact hygiene scanner** (`release_hygiene.py`) — new
  `scan_release_surface(root)` function that walks a repo worktree and flags
  runtime artifacts that must not appear on a release surface, Docker build
  context, or packaging archive:
  - `runtime-env-file` (error): non-example env files (`.env`, `auth.env`,
    `media.env`, `worker.env`, `api.env`, `test.env`, `grafana.env`).
  - `private-key-material` (error): files ending in `.key` or `.pem` (private
    keys and certificates, excluding `.example` copies).
  - `redis-dump` (error): `dump.rdb` Redis persistence snapshots.
  - `database-file` (error): `.db`, `.sqlite`, `.sqlite3` database files.
  - `runtime-data-dir` (error): runtime data directories (`minio/`, `redis/`,
    `media_redis/`, `db_data/`, `vault/`, `grafana/data/`, `prometheus/data/`).
  - `permission-denied` (warning): directories that cannot be read; scanner
    flags them rather than silently skipping, so they appear in the report
    for manual follow-up.
  - Tool caches (`.git`, `__pycache__`, `.mypy_cache`, `node_modules`, etc.)
    are skipped. Example files (`*.example`) are always safe.
  - New `scan-release` CLI subcommand (`security-tests-m8 scan-release
    [--deployment-root ROOT] [--strict-warnings]`) exits non-zero on errors
    (or on warnings when `--strict-warnings` is set), suitable for CI/release
    gates.

- **9.1 per-consumer private-API auth (harness alignment)** — the live-probe
  config/client now supports the per-consumer credential model required by
  fa-auth-m8 >= 1.0.0 (no shared-secret fallback).
  - New `LIVE_TEST_PRIVATE_API_CLIENT_ID` setting (`private_api_client_id`).
    When set, `LiveTestConfig.internal_headers()` emits `X-Internal-Client`
    alongside `X-Internal-Token`, so the preflight readiness probe, stack
    detection, and every suite that calls `internal_headers()` authenticate
    private-API calls under the per-consumer model. Unset keeps the legacy
    `X-Internal-Token`-only shape for single-secret stacks.
  - `internal_headers()` / `legacy_internal_headers()` centralised on
    `LiveTestConfig`; `_client`, `_preflight`, and `_detection` now delegate to
    it (no duplicated header builders).
  - New `test_f06` legacy-detection live check (opt-in): when a consumer id is
    configured, a private-route request carrying only `X-Internal-Token` must be
    rejected with 401 — proof the retired shared-secret fallback is gone.
  - README + `hardened_m8_full_security` example env/README aligned. New unit
    tests for the header builders and env parsing; 100% coverage, ruff + mypy +
    bandit green.

- **9.3 alignment: reach deep `/health` detail under the new token architecture**
  — fa-auth-m8 >= 1.0.0 gates the `/health` infrastructure detail (token mode,
  Redis/DB reachability, degradation modes) on a dedicated `HEALTH_DETAIL_CREDENTIAL`
  sent via `X-Internal-Token`, decoupled from `PRIVATE_API_SECRET`. The harness
  was still sending `PRIVATE_API_SECRET`, so health-dependent probes only saw the
  shallow status body.
  - New `LIVE_TEST_HEALTH_DETAIL_CREDENTIAL` setting (`health_detail_credential`)
    and `LiveTestConfig.health_detail_headers()` / `_client.health_detail_headers()`.
    Stack detection (`_detection`), readiness preflight (`_preflight`), the
    token-mode suite (`n08`), and the disclosure / security-header suites (`h05`,
    `SecurityHeadersSuite`) now read `/health` through the dedicated credential,
    falling back to `PRIVATE_API_SECRET` only for legacy stacks that still reuse it.
  - README + example env/README aligned; unit tests for the dedicated/fallback/empty
    cases.

- **0.4 P0 generic gates: Docker socket + public-bind checks** added to
  `scan_deployment` (`deployment.py`).
  - `docker-socket-mount` (error): flags any service in a hardened/production
    stack that mounts `/var/run/docker.sock` — use a static file provider or
    socket proxy instead.
  - `public-service-port` (error): flags any service in a hardened/production
    stack that publishes a port without an explicit loopback bind (i.e. binds
    on `0.0.0.0` explicitly or implicitly by omitting the host IP). No
    hardcoded port lists — matches the bind pattern, not the port number.
    Legitimately catches public MinIO, DB, Redis, or any other unintended
    public bind, as well as explicitly-intended public Traefik ports (advisory
    in `init.sh`; operator reviews findings).
  - Both checks skip non-hardened/non-production stacks.
  - 18 new tests covering all volume/port format variants (string short-form,
    string with `/tcp`/`/udp` suffix, explicit `0.0.0.0`, loopback, shell
    variable IP, long-form Mapping, bare ports, integer volume entries).
  - 72 tests, 100% coverage, ruff + mypy + bandit green.

### Changed

- **`regular_user` fixture now self-cleans.** The throwaway
  `redteam_<hex>@redteam-test.com` non-superuser created for privilege-escalation
  checks is deleted at session teardown through the admin account, so a run no
  longer leaves a standing test identity on the stack. Deletion is best-effort:
  if the stack is unreachable at teardown the cleanup is skipped rather than
  failing the run. README, the `hardened_m8_full_security` example, and the
  `shared_live_tests` READMEs (fa-auth-m8, media-service-m8, fa-ui-m8) document
  the create-and-delete lifecycle.

---

## 0.1.0

- Initial reusable pytest plugin and live suite package.
- Added config/env-driven auth, service, public entrypoint, and secret settings.
- Ported universal, algorithm-specific, token-mode, and protected endpoint suites.
- Added Python deployment preflight checks for compose env files and image policies.
