# Changelog

## [Unreleased]

### Security

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
