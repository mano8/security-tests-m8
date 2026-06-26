# Changelog

## [Unreleased]

---

## 0.2.0

### Security

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

---

## 0.1.0

- Initial reusable pytest plugin and live suite package.
- Added config/env-driven auth, service, public entrypoint, and secret settings.
- Ported universal, algorithm-specific, token-mode, and protected endpoint suites.
- Added Python deployment preflight checks for compose env files and image policies.
