# security-tests-m8

## Layer

Platform (live security testing suite).

## Purpose

Run live security tests against running stacks to validate authentication
mechanisms and security configuration.

## Repository boundaries

- Run tests only against live stacks; do not mock security boundaries.
- Do not couple tests to internal service implementations.
- Keep the suite reusable across services and usable locally or on another host.
- Keep test configuration flexible, including operation with and without
  credentials.
- Cover applicable OWASP recommendations and keep tests current with security
  flaws and testing best practices.

## Standalone authority

This file, repository documentation, and existing CI are the authoritative local
context. A verified nearest workspace may optionally add launcher-selected
policies and tasks; its absence is a successful standalone condition and does not
make a parent workspace necessary.
