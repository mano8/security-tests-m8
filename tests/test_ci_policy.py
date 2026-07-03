"""CI and publish-workflow policy tests — findings 11.5 and 11.6."""

from pathlib import Path


from security_tests_m8.workflow_policy import (
    action_refs,
    all_actions_sha_pinned,
    docker_publish_has_cosign_step,
    docker_publish_has_provenance,
    docker_publish_has_sbom_step,
    docker_publish_job_has_attestation_permission,
    docker_publish_job_has_oidc_permission,
    load_workflow,
    pypi_publish_job_has_oidc_permission,
    pypi_publish_job_has_protected_environment,
    pypi_workflow_has_no_api_token,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI_YAML = WORKFLOWS / "CI.yaml"
PIPY_YML = WORKFLOWS / "PiPy.yml"

_GOOD_SHA = "a" * 40

# ── Own repo compliance — finding 11.6 (PyPI Trusted Publishing) ────────────


def test_pipy_no_api_token() -> None:
    """PiPy.yml must not reference PYPI_API_TOKEN; OIDC Trusted Publishing only."""
    assert pypi_workflow_has_no_api_token(PIPY_YML)


def test_pypi_publish_job_has_oidc_permission() -> None:
    """The pypi-publish job must declare id-token: write for OIDC."""
    wf = load_workflow(PIPY_YML)
    assert pypi_publish_job_has_oidc_permission(wf)


def test_pypi_publish_job_uses_protected_environment() -> None:
    """The pypi-publish job must target a named protected environment."""
    wf = load_workflow(PIPY_YML)
    assert pypi_publish_job_has_protected_environment(wf)


def test_no_duplicate_ci_yml() -> None:
    """ci.yml must not exist — CI.yaml is the single canonical quality gate."""
    assert not (WORKFLOWS / "ci.yml").exists()


def test_ci_yaml_has_secret_scan_job() -> None:
    """CI.yaml must contain the gitleaks secret-scan job."""
    wf = load_workflow(CI_YAML)
    assert "secret-scan" in wf["jobs"]


def test_ci_yaml_actions_are_sha_pinned() -> None:
    """Every action reference in CI.yaml must be pinned to a 40-char commit SHA."""
    assert all_actions_sha_pinned(CI_YAML)


def test_pipy_yml_actions_are_sha_pinned() -> None:
    """Every action reference in PiPy.yml must be pinned to a 40-char commit SHA."""
    assert all_actions_sha_pinned(PIPY_YML)


# ── Reusable helpers — action_refs / all_actions_sha_pinned ─────────────────


def test_action_refs_parses_uses_lines(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text(f"uses: actions/checkout@{_GOOD_SHA} # v6", encoding="utf-8")
    refs = action_refs(wf)
    assert refs == [(f"actions/checkout@{_GOOD_SHA}", _GOOD_SHA)]


def test_action_refs_strips_comment_from_sha(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text(f"uses: owner/action@{_GOOD_SHA}#comment", encoding="utf-8")
    refs = action_refs(wf)
    assert refs[0][1] == _GOOD_SHA


def test_action_refs_empty_for_no_uses(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text("name: CI\njobs: {}", encoding="utf-8")
    assert action_refs(wf) == []


def test_all_actions_sha_pinned_true(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text(f"uses: owner/action@{_GOOD_SHA}", encoding="utf-8")
    assert all_actions_sha_pinned(wf)


def test_all_actions_sha_pinned_false_tag(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text("uses: owner/action@v3", encoding="utf-8")
    assert not all_actions_sha_pinned(wf)


def test_all_actions_sha_pinned_false_no_refs(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text("name: no actions", encoding="utf-8")
    assert not all_actions_sha_pinned(wf)


def test_all_actions_sha_pinned_false_mixed(tmp_path: Path) -> None:
    wf = tmp_path / "wf.yaml"
    wf.write_text(
        f"uses: owner/a@{_GOOD_SHA}\nuses: owner/b@v2",
        encoding="utf-8",
    )
    assert not all_actions_sha_pinned(wf)


# ── Reusable Docker publish integrity checks — finding 11.5 ────────────────


def _docker_wf(steps: list[dict]) -> dict:  # type: ignore[type-arg]
    return {
        "jobs": {
            "build-and-push": {
                "permissions": {"id-token": "write", "attestations": "write"},
                "steps": steps,
            }
        }
    }


_COSIGN_INSTALLER_STEP = {"uses": "sigstore/cosign-installer@abc"}
_COSIGN_SIGN_STEP = {"run": 'cosign sign --yes "img@${{ steps.push.outputs.digest }}"'}
_SBOM_STEP = {"uses": "anchore/sbom-action@abc"}
_BUILD_PUSH_PROVENANCE_STEP = {
    "uses": "docker/build-push-action@abc",
    "with": {"provenance": "mode=max", "push": True},
}
_BUILD_PUSH_NO_PROVENANCE_STEP = {
    "uses": "docker/build-push-action@abc",
    "with": {"push": True},
}
_BUILD_PUSH_WRONG_PROVENANCE_STEP = {
    "uses": "docker/build-push-action@abc",
    "with": {"provenance": "mode=min"},
}
_BUILD_PUSH_NULL_WITH_STEP = {
    "uses": "docker/build-push-action@abc",
    "with": None,
}


def test_docker_job_oidc_permission_present() -> None:
    wf = _docker_wf([])
    assert docker_publish_job_has_oidc_permission(wf)


def test_docker_job_oidc_permission_missing() -> None:
    wf = {"jobs": {"build-and-push": {"permissions": {}, "steps": []}}}
    assert not docker_publish_job_has_oidc_permission(wf)


def test_docker_job_oidc_permission_wrong_job() -> None:
    wf = _docker_wf([])
    assert not docker_publish_job_has_oidc_permission(wf, "other-job")


def test_docker_job_attestation_permission_present() -> None:
    wf = _docker_wf([])
    assert docker_publish_job_has_attestation_permission(wf)


def test_docker_job_attestation_permission_missing() -> None:
    wf = {"jobs": {"build-and-push": {"permissions": {}, "steps": []}}}
    assert not docker_publish_job_has_attestation_permission(wf)


def test_docker_publish_provenance_present() -> None:
    assert docker_publish_has_provenance(_docker_wf([_BUILD_PUSH_PROVENANCE_STEP]))


def test_docker_publish_provenance_absent_no_with() -> None:
    assert not docker_publish_has_provenance(
        _docker_wf([_BUILD_PUSH_NO_PROVENANCE_STEP])
    )


def test_docker_publish_provenance_absent_wrong_mode() -> None:
    assert not docker_publish_has_provenance(
        _docker_wf([_BUILD_PUSH_WRONG_PROVENANCE_STEP])
    )


def test_docker_publish_provenance_absent_null_with() -> None:
    assert not docker_publish_has_provenance(_docker_wf([_BUILD_PUSH_NULL_WITH_STEP]))


def test_docker_publish_provenance_absent_non_build_step() -> None:
    wf = {"jobs": {"j": {"steps": [{"uses": "actions/checkout@abc", "with": {}}]}}}
    assert not docker_publish_has_provenance(wf)


def test_docker_publish_provenance_no_jobs() -> None:
    assert not docker_publish_has_provenance({})


def test_docker_publish_sbom_present() -> None:
    assert docker_publish_has_sbom_step(_docker_wf([_SBOM_STEP]))


def test_docker_publish_sbom_absent() -> None:
    wf = {"jobs": {"j": {"steps": [{"uses": "actions/checkout@abc"}]}}}
    assert not docker_publish_has_sbom_step(wf)


def test_docker_publish_cosign_present() -> None:
    wf = _docker_wf([_COSIGN_INSTALLER_STEP, _COSIGN_SIGN_STEP])
    assert docker_publish_has_cosign_step(wf)


def test_docker_publish_cosign_missing_installer() -> None:
    wf = _docker_wf([_COSIGN_SIGN_STEP])
    assert not docker_publish_has_cosign_step(wf)


def test_docker_publish_cosign_missing_sign_run() -> None:
    wf = _docker_wf([_COSIGN_INSTALLER_STEP])
    assert not docker_publish_has_cosign_step(wf)


def test_docker_publish_cosign_sign_without_digest() -> None:
    wf = _docker_wf([_COSIGN_INSTALLER_STEP, {"run": "cosign sign --yes img:tag"}])
    assert not docker_publish_has_cosign_step(wf)


def test_docker_publish_cosign_no_steps() -> None:
    assert not docker_publish_has_cosign_step({})


def test_iter_steps_handles_null_steps() -> None:
    wf = _docker_wf([_SBOM_STEP])
    wf["jobs"]["null-steps"] = {"steps": None}  # type: ignore[index]
    assert docker_publish_has_sbom_step(wf)


# ── Reusable PyPI Trusted Publishing checks — finding 11.6 ─────────────────


def test_pypi_no_api_token_passes(tmp_path: Path) -> None:
    wf = tmp_path / "PiPy.yml"
    wf.write_text(
        "name: Upload\njobs:\n  pypi-publish:\n    steps: []", encoding="utf-8"
    )
    assert pypi_workflow_has_no_api_token(wf)


def test_pypi_api_token_detected(tmp_path: Path) -> None:
    wf = tmp_path / "PiPy.yml"
    wf.write_text("password: ${{ secrets.PYPI_API_TOKEN }}", encoding="utf-8")
    assert not pypi_workflow_has_no_api_token(wf)


def test_pypi_job_oidc_permission_present() -> None:
    wf = {"jobs": {"pypi-publish": {"permissions": {"id-token": "write"}}}}
    assert pypi_publish_job_has_oidc_permission(wf)


def test_pypi_job_oidc_permission_missing() -> None:
    wf = {"jobs": {"pypi-publish": {"permissions": {}}}}
    assert not pypi_publish_job_has_oidc_permission(wf)


def test_pypi_job_oidc_permission_no_jobs() -> None:
    assert not pypi_publish_job_has_oidc_permission({})


def test_pypi_protected_environment_string() -> None:
    wf = {"jobs": {"pypi-publish": {"environment": "pypi"}}}
    assert pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_dict_with_name() -> None:
    wf = {
        "jobs": {
            "pypi-publish": {"environment": {"name": "pypi", "url": "https://pypi.org"}}
        }
    }
    assert pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_missing() -> None:
    wf = {"jobs": {"pypi-publish": {}}}
    assert not pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_empty_string() -> None:
    wf = {"jobs": {"pypi-publish": {"environment": ""}}}
    assert not pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_dict_empty_name() -> None:
    wf = {"jobs": {"pypi-publish": {"environment": {"name": ""}}}}
    assert not pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_dict_no_name_key() -> None:
    wf = {"jobs": {"pypi-publish": {"environment": {"url": "https://pypi.org"}}}}
    assert not pypi_publish_job_has_protected_environment(wf)


def test_pypi_protected_environment_no_jobs() -> None:
    assert not pypi_publish_job_has_protected_environment({})
