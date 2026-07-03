"""Reusable GitHub Actions workflow policy checks — findings 11.5, 11.6, 11.7, 11.8."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"uses:\s+([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+@(\S+))")


def load_workflow(path: Path) -> dict[str, Any]:
    """Load and parse a GitHub Actions workflow YAML file."""
    with path.open() as fh:
        return yaml.safe_load(fh)  # type: ignore[no-any-return]


def action_refs(path: Path) -> list[tuple[str, str]]:
    """Return (full-ref, sha-candidate) for every ``uses:`` line in a workflow."""
    results: list[tuple[str, str]] = []
    for m in _USES_RE.finditer(path.read_text(encoding="utf-8")):
        full_ref = m.group(1)
        sha_part = m.group(2).split("#")[0].strip()
        results.append((full_ref, sha_part))
    return results


def all_actions_sha_pinned(path: Path) -> bool:
    """Return True only when every action reference is a 40-char commit SHA."""
    refs = action_refs(path)
    if not refs:
        return False
    return all(_SHA_RE.match(sha) for _, sha in refs)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _job_permissions(wf: dict[str, Any], job_name: str) -> dict[str, Any]:
    return wf.get("jobs", {}).get(job_name, {}).get("permissions", {})  # type: ignore[return-value]


def _iter_steps(wf: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for job in wf.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            steps.append(step)
    return steps


# ---------------------------------------------------------------------------
# 11.5  Docker publish integrity checks
# ---------------------------------------------------------------------------


def docker_publish_job_has_oidc_permission(
    wf: dict[str, Any], job_name: str = "build-and-push"
) -> bool:
    """Return True when the publish job declares ``id-token: write``."""
    return _job_permissions(wf, job_name).get("id-token") == "write"


def docker_publish_job_has_attestation_permission(
    wf: dict[str, Any], job_name: str = "build-and-push"
) -> bool:
    """Return True when the publish job declares ``attestations: write``."""
    return _job_permissions(wf, job_name).get("attestations") == "write"


def docker_publish_has_provenance(wf: dict[str, Any]) -> bool:
    """Return True when a build-push step includes ``provenance: mode=max``."""
    for step in _iter_steps(wf):
        if "build-push-action" not in step.get("uses", ""):
            continue
        with_ = step.get("with") or {}
        if with_.get("provenance") == "mode=max":
            return True
    return False


def docker_publish_has_sbom_step(wf: dict[str, Any]) -> bool:
    """Return True when the workflow includes an SBOM-generation step."""
    return any("sbom-action" in step.get("uses", "") for step in _iter_steps(wf))


def docker_publish_has_cosign_step(wf: dict[str, Any]) -> bool:
    """Return True when cosign is installed and a sign step references a digest."""
    has_installer = False
    has_sign = False
    for step in _iter_steps(wf):
        if "cosign-installer" in step.get("uses", ""):
            has_installer = True
        run = step.get("run", "")
        if "cosign sign" in run and "digest" in run:
            has_sign = True
    return has_installer and has_sign


# ---------------------------------------------------------------------------
# 11.6  PyPI Trusted Publishing checks
# ---------------------------------------------------------------------------


def pypi_workflow_has_no_api_token(path: Path) -> bool:
    """Return True when the workflow file does not reference ``PYPI_API_TOKEN``."""
    return "PYPI_API_TOKEN" not in path.read_text(encoding="utf-8")


def pypi_publish_job_has_oidc_permission(
    wf: dict[str, Any], job_name: str = "pypi-publish"
) -> bool:
    """Return True when the publish job declares ``id-token: write``."""
    return _job_permissions(wf, job_name).get("id-token") == "write"


def pypi_publish_job_has_protected_environment(
    wf: dict[str, Any], job_name: str = "pypi-publish"
) -> bool:
    """Return True when the publish job targets a named protected environment."""
    env = wf.get("jobs", {}).get(job_name, {}).get("environment")
    if env is None:
        return False
    name = env.get("name") if isinstance(env, dict) else env
    return bool(name)


# ---------------------------------------------------------------------------
# 11.7  CI workflow consolidation and immutable action policy
# ---------------------------------------------------------------------------


def ci_has_no_duplicate_workflow(workflows_dir: Path) -> bool:
    """Return True when ``ci.yml`` does not coexist with ``CI.yaml``."""
    return not (workflows_dir / "ci.yml").exists()


def ci_has_secret_scan_job(wf: dict[str, Any]) -> bool:
    """Return True when the CI workflow contains a ``secret-scan`` job."""
    return "secret-scan" in wf.get("jobs", {})


# ---------------------------------------------------------------------------
# 11.8  Reproducible dependency sets
# ---------------------------------------------------------------------------


def constraints_file_exists(path: Path) -> bool:
    """Return True when a constraints/lock file exists at *path*."""
    return path.exists()


def constraints_file_has_no_custom_index(path: Path) -> bool:
    """Return True when the file does not reference a custom index URL."""
    content = path.read_text(encoding="utf-8")
    return "--index-url" not in content and "--extra-index-url" not in content


def constraints_file_pins_deps(path: Path, dep_names: list[str]) -> bool:
    """Return True when every name in *dep_names* appears in the constraints file."""
    content = path.read_text(encoding="utf-8").lower()
    return all(dep.lower() in content for dep in dep_names)


def lock_file_uses_require_hashes(path: Path) -> bool:
    """Return True when the lock file contains ``--hash=`` entries."""
    return "--hash=" in path.read_text(encoding="utf-8")
