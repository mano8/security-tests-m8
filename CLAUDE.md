# security-tests-m8

## Layer
Platform (live security testing suite)

---

## Purpose
Runs live security tests against running stacks to validate auth mechanisms and security configuration.

---

## Rules
- Tests run against live stack only — no mocking of security boundaries
- No coupling to internal service implementations
- Must remain reusable across all services
- Must remain usable in local and/or different host
- Mostly hight configurable
- Must run with and without credencials
- Must test all owasap recommended points
- Must be up to date with latest security flaws and best practices for tests

---

## Authority
All rules come from /.claude/policy.index.json (type: python)
