"""
Live Security Test Suite — AI gateway (ai-gateway-m8), gateway only
====================================================================
Target:  one AI gateway stack, without the media services. Contexts are minted
         by the suite's own test issuer key (registered in the stack's
         ``AI_SERVICE_CLIENTS`` as ``security-tests``) and provider calls go to
         the suite's stub provider (``security_tests_m8.ai_stub_provider``).

Configuration (all optional; a missing input skips the rows that need it):

* ``LIVE_TEST_AI_BASE`` — the gateway on the in-network path, with its prefix
  (e.g. ``http://ai_gateway:8000/ai`` or ``http://127.0.0.1:18080/ai``);
* ``LIVE_TEST_PUBLIC_BASE`` (+ ``LIVE_TEST_AI_PUBLIC_PREFIX``, default ``ai``)
  — the public router, for the ingress rows;
* ``LIVE_TEST_AI_CLIENT_SECRET`` and ``LIVE_TEST_AI_ISSUER_SEED_FILE`` — the
  ``security-tests`` client and its job-context seed;
* ``LIVE_TEST_AI_STUB_BASE`` / ``LIVE_TEST_AI_STUB_CONTROL_TOKEN`` — the stub
  as the suite reaches it (``LIVE_TEST_AI_STUB_PROVIDER_URL`` when the gateway
  reaches it under another name);
* ``LIVE_TEST_AI_METRICS_CREDENTIAL``, ``LIVE_TEST_AI_HEALTH_DETAIL_CREDENTIAL``;
* ``LIVE_TEST_AI_COMPOSE_PROJECT`` (+ ``LIVE_TEST_CONTAINER_ENGINE``) — container
  access for the database, log and lifecycle rows;
* ``LIVE_TEST_AUTH_BASE`` / ``LIVE_TEST_ADMIN_*`` — the issuer and its superuser.

Every row that changes gateway state (contexts redeemed, providers, credentials
and bindings created, containers restarted) is marked ``destructive``: run the
suite against a test stack, with ``--include-destructive``.

The cross-service rows (media-minted contexts, live data-class derivation, the
deployed sandbox, Redis tiers, storage identities, provenance) belong to the
integrated media stack's suite and are absent here by design.

Run:
    security-tests-m8 run --target ai-gateway --include-destructive
"""

from __future__ import annotations

import concurrent.futures
import time
import uuid
from typing import Any

import pytest
import requests

from security_tests_m8._ai_fixtures import AiWorld, execution_body
from security_tests_m8._ai_gateway import (
    GatewayClient,
    StackOperator,
    canary,
    error_code,
    generate_seed,
    mint_context,
    require_operator,
    short_id,
    sql_value,
    tamper,
    unguarded,
    wait_for,
)
from security_tests_m8._availability import unavailable_reason
from security_tests_m8._config import get_config
from security_tests_m8.ai_stub_provider import bearer_fingerprint

_MARKS = [pytest.mark.live, pytest.mark.live_security, pytest.mark.live_ai_gateway]
_STATEFUL_MARKS = [*_MARKS, pytest.mark.destructive]

#: The external provider of the boundary rows: a reserved documentation domain
#: (RFC 2606). Those rows assert a refusal before any dispatch; were a defect to
#: dispatch anyway, only a fake canary key would leave for a host nobody runs.
_EXTERNAL_HOST = "https://api.example.com"


# ── helpers ───────────────────────────────────────────────────────────────────


def _public(path: str) -> str:
    base = get_config().ai_public_base_url()
    if base is None:
        pytest.skip("ingress checks require LIVE_TEST_PUBLIC_BASE (the public router)")
    return f"{base}/{path.lstrip('/')}"


def _raw_get(url: str, headers: dict[str, str] | None = None) -> requests.Response:
    """GET ``url`` exactly as written: no client-side path normalisation."""
    config = get_config()
    with requests.Session() as session:
        prepared = session.prepare_request(
            requests.Request("GET", url, headers=headers or {})
        )
        prepared.url = url
        return session.send(
            prepared, timeout=config.timeout, verify=config.public_tls_verify
        )


def _stopped_at_proxy(response: requests.Response) -> bool:
    """Whether the public router refused the request itself.

    A refused path gets the proxy's bare ``404 page not found`` (or ``400`` for
    a path it will not parse); a request that reached the gateway gets a JSON
    body. Anything else means the gateway saw the request.
    """
    if response.status_code == 400:
        return True
    return response.status_code == 404 and unavailable_reason(response) is not None


def _assert_refused(response: requests.Response, code: str, status: int) -> None:
    assert response.status_code == status and error_code(response) == code, (
        f"[SECURITY FAIL] expected {status} {code!r}, got {response.status_code} "
        f"{error_code(response)!r}: {response.text[:200]}"
    )


def _assert_no_provider_request(
    world: AiWorld, mark: int, job_ref: str | None = None
) -> None:
    sent = world.stub.since(mark)
    assert not sent, (
        f"[SECURITY FAIL] a refused execution still reached the provider: {sent}"
    )
    if job_ref is not None:
        assert world.dispatched(job_ref) is not True, (
            f"[SECURITY FAIL] execution {job_ref} recorded a provider dispatch"
        )


def _fingerprints(requests_seen: list[dict[str, Any]]) -> set[str]:
    return {str(entry["key_fingerprint"]) for entry in requests_seen}


# ── Secrets and surface: ingress (D-21) ───────────────────────────────────────

#: Paths the public router must never route (D-21), with path spellings
#: the proxy must normalise before matching.
_BLOCKED_PUBLIC_PATHS = (
    "v1/execute/embed",
    "v1/execute/rerank",
    "v1/execute/structured-output",
    "v1/execute/ocr",
    "v1/execute/ocr/00000000-0000-4000-8000-000000000000:dispatch",
    "v1/internal/anything",
    "metrics",
    "v1/metrics",
    "docs",
    "v1/docs",
    "redoc",
    "v1/redoc",
    "openapi.json",
    "v1/openapi.json",
    "/v1//execute/embed",
    "./v1/execute/embed",
    "v1/x/../execute/embed",
    "v1/execute%2Fembed",
)


class AiGatewayIngressSuite:
    """Public router blocks, header stripping and diagnostics (D-21, S-01)."""

    def test_s01_public_router_positive_control(self) -> None:
        """CONTROL: the public router serves the gateway's shallow health."""
        with unguarded():
            response = _raw_get(_public("health/"))
        assert response.status_code == 200, (
            f"the public router does not reach the gateway ({response.status_code}); "
            "every ingress row below would be meaningless"
        )

    @pytest.mark.parametrize("path", _BLOCKED_PUBLIC_PATHS)
    def test_s02_public_router_blocks_service_and_diagnostic_paths(
        self, path: str
    ) -> None:
        """SECURITY PASS: execution, internal and diagnostic paths stop at the proxy."""
        with unguarded():
            response = _raw_get(_public(path))
        assert _stopped_at_proxy(response), (
            f"[SECURITY FAIL: INGRESS] public {path!r} reached the gateway "
            f"({response.status_code} {response.text[:120]!r}). The public router "
            "must exclude /ai/v1/execute, /ai/v1/internal, metrics, docs and "
            "OpenAPI, after path normalisation."
        )

    def test_s03_public_router_strips_service_client_headers(self) -> None:
        """SECURITY PASS: a valid service client is not honoured through the edge."""
        config = get_config()
        headers = config.ai_service_client_headers()
        if not headers or not config.ai_base_url:
            pytest.skip("needs LIVE_TEST_AI_BASE and LIVE_TEST_AI_CLIENT_SECRET")
        inside = requests.get(
            f"{config.ai_base_url}/v1/profiles", headers=headers, timeout=config.timeout
        )
        assert inside.status_code == 200, (
            f"control failed: the in-network path refused the client ({inside.status_code})"
        )
        with unguarded():
            outside = _raw_get(_public("v1/profiles"), headers=headers)
        assert outside.status_code in (401, 403), (
            "[SECURITY FAIL: INGRESS] the public router forwarded X-Internal-Client "
            f"and X-Internal-Token: GET /v1/profiles answered {outside.status_code}. "
            "Strip the service-client and X-AI-Job-Context headers at the edge."
        )

    def test_s04_public_health_is_shallow_even_with_the_detail_credential(
        self,
    ) -> None:
        """SECURITY PASS: the health detail credential is stripped at the edge."""
        config = get_config()
        headers = config.ai_health_detail_headers()
        if not headers:
            pytest.skip("needs LIVE_TEST_AI_HEALTH_DETAIL_CREDENTIAL")
        with unguarded():
            response = _raw_get(_public("health/"), headers=headers)
        assert response.status_code == 200
        assert "checks" not in response.json(), (
            "[SECURITY FAIL: INGRESS] the public /health returned its detail; the "
            "edge must strip X-Internal-Token so the detail stays internal"
        )

    def test_s05_openapi_and_docs_absent_under_production(
        self, ai_gateway: GatewayClient
    ) -> None:
        """SECURITY PASS: no OpenAPI document or docs page on the gateway itself."""
        if not get_config().ai_production:
            pytest.skip("LIVE_TEST_AI_PRODUCTION=false: docs may be enabled")
        exposed = {
            path: ai_gateway.get(path).status_code
            for path in ("openapi.json", "docs", "redoc", "v1/openapi.json")
        }
        assert all(status == 404 for status in exposed.values()), (
            f"[SECURITY FAIL] diagnostics served under production: {exposed}"
        )

    def test_s06_metrics_require_the_scrape_credential(
        self, ai_gateway: GatewayClient
    ) -> None:
        """SECURITY PASS: metrics answer 401 without the scrape credential."""
        bare = ai_gateway.get("metrics")
        wrong = ai_gateway.get(
            "metrics", headers={"Authorization": "Bearer wrong-scrape-credential"}
        )
        assert bare.status_code == 401 and wrong.status_code == 401, (
            f"[SECURITY FAIL] metrics without a valid credential: "
            f"{bare.status_code}/{wrong.status_code}"
        )
        if get_config().ai_metrics_credential:
            assert (
                ai_gateway.get(
                    "metrics", headers=get_config().ai_metrics_headers()
                ).status_code
                == 200
            )

    def test_s07_health_detail_requires_its_credential(
        self, ai_gateway: GatewayClient
    ) -> None:
        """SECURITY PASS: health detail only with HEALTH_DETAIL_CREDENTIAL."""
        for headers in ({}, {"X-Internal-Token": "wrong-detail-credential"}):
            body = ai_gateway.get("health/", headers=headers).json()
            assert "checks" not in body, (
                f"[SECURITY FAIL] /health detail without its credential: {headers}"
            )
        if get_config().ai_health_detail_credential:
            body = ai_gateway.get(
                "health/", headers=get_config().ai_health_detail_headers()
            ).json()
            assert "checks" in body, "control failed: the detail credential is refused"


# ── Authentication and contexts (S-04, C-03) ──────────────────────────────────


class AiGatewayContextSuite:
    """Service-client authentication and the job-context matrix (S-04)."""

    def test_c01_valid_context_executes(self, ai_world: AiWorld, ai_stub: Any) -> None:
        """CONTROL: a valid client and context execute and reach the stub once."""
        mark = ai_stub.mark()
        response = ai_world.execute("embedding")
        assert response.status_code == 200, response.text[:300]
        assert _fingerprints(ai_stub.since(mark)) == {bearer_fingerprint(ai_world.key)}

    @pytest.mark.parametrize(
        ("label", "client_id", "secret"),
        [
            ("no client", None, None),
            ("wrong secret", None, "wrong-secret-value-000000000000"),
            ("unknown client", "not-a-registered-client", None),
        ],
    )
    def test_c02_unauthenticated_client_refused(
        self,
        ai_world: AiWorld,
        ai_stub: Any,
        label: str,
        client_id: str | None,
        secret: str | None,
    ) -> None:
        """SECURITY PASS: execution needs a registered client and its secret."""
        config = ai_world.gateway.config
        headers: dict[str, str] = {}
        if label != "no client":
            headers = {
                "X-Internal-Client": client_id or config.ai_client_id,
                "X-Internal-Token": secret or str(config.ai_client_secret),
            }
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", ai_world.profiles["embedding"]),
            ai_world.context("embedding"),
            headers=headers,
            client=False,
        )
        _assert_refused(response, "unauthorized", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c03_missing_context_refused(self, ai_world: AiWorld, ai_stub: Any) -> None:
        """SECURITY PASS: an authenticated client without a context → context_missing."""
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", ai_world.profiles["embedding"]),
            None,
        )
        _assert_refused(response, "context_missing", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c04_user_jwt_never_authorizes_execution(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a superuser JWT on an execution route → 401, no call."""
        jwt = {"Authorization": f"Bearer {ai_world.users.superuser_token()}"}
        body = execution_body("embedding", ai_world.profiles["embedding"])
        mark = ai_stub.mark()
        alone = ai_world.gateway.execute(
            "embedding", body, None, headers=jwt, client=False
        )
        _assert_refused(alone, "unauthorized", 401)
        with_client = ai_world.gateway.execute("embedding", body, None, headers=jwt)
        _assert_refused(with_client, "context_missing", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c05_replayed_context_refused(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a context is single-use (max_uses = 1)."""
        context = ai_world.context("embedding")
        first = ai_world.execute("embedding", context=context)
        assert first.status_code == 200, first.text[:300]
        mark = ai_stub.mark()
        second = ai_world.execute("embedding", context=context)
        _assert_refused(second, "context_replayed", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c06_concurrent_replay_redeems_once(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: eight simultaneous uses of one context → exactly one 200."""
        context = ai_world.context("embedding")
        mark = ai_stub.mark()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(
                pool.map(
                    lambda _: ai_world.execute("embedding", context=context), range(8)
                )
            )
        statuses = sorted(response.status_code for response in responses)
        assert statuses.count(200) == 1, (
            f"[SECURITY FAIL] one context redeemed {statuses.count(200)} times: {statuses}"
        )
        assert len(ai_stub.since(mark)) == 1
        refused = {error_code(r) for r in responses if r.status_code != 200}
        assert refused == {"context_replayed"}, refused

    @pytest.mark.parametrize(
        ("label", "overrides", "code"),
        [
            ("expired", {"issued_offset": -120, "ttl": 60}, "context_expired"),
            (
                "not yet valid",
                {"not_before_offset": 120, "ttl": 300},
                "context_invalid",
            ),
            ("issued in the future", {"issued_offset": 300}, "context_invalid"),
            ("TTL above the cap", {"ttl": 901}, "context_invalid"),
            (
                "another installation",
                {"audience": "ai-gateway/00000000-0000-4000-8000-000000000000"},
                "context_invalid",
            ),
            ("azp is another client", {"azp": "media-worker"}, "context_invalid"),
            ("iss is another client", {"issuer": "media-service"}, "context_invalid"),
        ],
    )
    def test_c07_invalid_claims_refused(
        self,
        ai_world: AiWorld,
        ai_stub: Any,
        label: str,
        overrides: dict[str, Any],
        code: str,
    ) -> None:
        """SECURITY PASS: every claim the gateway checks is enforced."""
        claims = ai_world.claims("embedding")
        claims = type(claims)(**{**claims.__dict__, **overrides})
        mark = ai_stub.mark()
        response = ai_world.execute(
            "embedding", context=mint_context(claims, ai_world.seed)
        )
        _assert_refused(response, code, 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c08_capability_and_profile_bound(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a context is valid only for its capability and profile."""
        mark = ai_stub.mark()
        rerank_ctx = ai_world.context("rerank")
        wrong_route = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", ai_world.profiles["rerank"]),
            rerank_ctx,
        )
        _assert_refused(wrong_route, "context_invalid", 401)
        other_profile = ai_world.profile("embedding")
        wrong_profile = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", other_profile),
            ai_world.context("embedding"),
        )
        _assert_refused(wrong_profile, "context_invalid", 401)
        _assert_no_provider_request(ai_world, mark)

    @pytest.mark.parametrize(
        "label", ["tampered", "unregistered key", "foreign signer"]
    )
    def test_c09_signature_and_key_enforced(
        self, ai_world: AiWorld, ai_stub: Any, label: str
    ) -> None:
        """SECURITY PASS: only the registered issuer's own signature is accepted."""
        claims = ai_world.claims("embedding")
        if label == "tampered":
            context = tamper(mint_context(claims, ai_world.seed))
        elif label == "unregistered key":
            context = mint_context(claims, generate_seed())
        else:
            context = mint_context(claims, generate_seed(), kid=ai_world.kid)
        mark = ai_stub.mark()
        response = ai_world.execute("embedding", context=context)
        _assert_refused(response, "context_invalid", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c10_oversized_context_refused(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a header above 4096 bytes is refused before decoding."""
        mark = ai_stub.mark()
        response = ai_world.execute("embedding", context="A" * 4097)
        _assert_refused(response, "context_invalid", 401)
        _assert_no_provider_request(ai_world, mark)

    def test_c11_ocr_route_not_served_when_ocr_disabled(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: with ocr off (Q12) the OCR routes are not served."""
        meta = ai_world.gateway.meta()
        if "ocr" in meta["gateway"].get("capabilities_enabled", []):
            pytest.skip("ocr is enabled on this stack")
        mark = ai_stub.mark()
        response = requests.post(
            ai_world.gateway.url("v1/execute/ocr"),
            headers=ai_world.gateway.config.ai_service_client_headers(),
            data=b"%PDF-1.4",
            timeout=ai_world.gateway.config.timeout,
        )
        assert response.status_code == 404, (
            f"[SECURITY FAIL] OCR route served while ocr is disabled: "
            f"{response.status_code}"
        )
        _assert_no_provider_request(ai_world, mark)


# ── Destination and provider answers (S-02, D-20) ─────────────────────────────

_SSRF_DESTINATIONS = [
    ("local literal address", "http://10.0.0.5:11434", "local"),
    ("local name not allowlisted", "http://metadata:11434", "local"),
    ("local loopback name", "http://localhost:11434", "local"),
    ("external plain http", "http://api.example.com", "external"),
    ("external port not allowlisted", "https://api.example.com:8443", "external"),
    ("external metadata address", "https://169.254.169.254", "external"),
    ("external loopback", "https://127.0.0.1", "external"),
    ("external IPv4-mapped loopback", "https://[::ffff:127.0.0.1]", "external"),
    ("external RFC 1918", "https://10.1.2.3", "external"),
    ("external CGNAT", "https://100.64.0.1", "external"),
    ("userinfo", "https://user:pass@api.example.com", "external"),
    ("query", "https://api.example.com/?redirect=1", "external"),
    ("fragment", "https://api.example.com/#x", "external"),
    ("scheme", "ftp://api.example.com", "external"),
]


class AiGatewayDestinationSuite:
    """Provider destinations and hostile provider answers (S-02, D-20)."""

    @pytest.mark.parametrize(
        ("label", "base_url", "boundary"),
        _SSRF_DESTINATIONS,
        ids=[case[0] for case in _SSRF_DESTINATIONS],
    )
    def test_d01_unsafe_provider_destination_refused(
        self, ai_world: AiWorld, label: str, base_url: str, boundary: str
    ) -> None:
        """SECURITY PASS: the write-time destination check refuses SSRF targets."""
        response = ai_world.admin.request(
            "POST",
            "admin/providers",
            {
                "name": f"t88-ssrf-{short_id()}",
                "provider_type": "openai_compatible",
                "base_url": base_url,
                "auth_type": "bearer",
                "boundary": boundary,
            },
        )
        assert response.status_code in (400, 422), (
            f"[SECURITY FAIL: SSRF] {label}: provider {base_url!r} ({boundary}) "
            f"was accepted ({response.status_code})"
        )

    def test_d02_external_name_resolving_private_refused_at_call_time(
        self, ai_world: AiWorld
    ) -> None:
        """SECURITY PASS: every resolved answer is checked before each call."""
        config = ai_world.gateway.config
        provider_id = ai_world.provider(f"https://{config.ai_db_service}", "external")
        model_id = ai_world.model(provider_id, ("embedding",))
        credential_id, _ = ai_world.credential(
            provider_id=provider_id, key=canary("ssrf"), accepted=False
        )
        profile = ai_world.profile("embedding")
        ai_world.bind("admin", profile, credential_id, model_id=model_id)
        claims = ai_world.claims("embedding", profile)
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", profile),
            mint_context(claims, ai_world.seed),
        )
        assert response.status_code >= 400 and error_code(response) in {
            "provider_unreachable",
            "boundary_denied",
        }, (
            f"[SECURITY FAIL: SSRF] an external provider resolving to a private "
            f"address was called: {response.status_code} {response.text[:200]}"
        )
        assert ai_world.dispatched(claims.job_ref) is not True

    def test_d03_endpoint_frozen_after_a_credential_exists(
        self, ai_world: AiWorld
    ) -> None:
        """SECURITY PASS: base_url and boundary cannot be repointed once used."""
        gateway_url = ai_world.gateway.config.ai_stub_gateway_url()
        provider_id = ai_world.provider(str(gateway_url), "local")
        ai_world.credential(provider_id=provider_id)
        moved = ai_world.admin.request(
            "PATCH", f"admin/providers/{provider_id}", {"base_url": f"{gateway_url}/v2"}
        )
        flipped = ai_world.admin.request(
            "PATCH", f"admin/providers/{provider_id}", {"boundary": "external"}
        )
        assert moved.status_code == 409 and flipped.status_code == 409, (
            f"[SECURITY FAIL] a provider holding a credential was repointed: "
            f"base_url {moved.status_code}, boundary {flipped.status_code}"
        )

    @pytest.mark.parametrize(
        ("mode", "code"),
        [("gzip_bomb", "response_too_large"), ("deep_json", "provider_rejected")],
    )
    def test_d04_hostile_provider_answer_refused(
        self, ai_world: AiWorld, ai_stub: Any, mode: str, code: str
    ) -> None:
        """SECURITY PASS: a decompression bomb or over-deep JSON is refused, typed."""
        ai_stub.configure(mode=mode)
        response = ai_world.execute("embedding")
        _assert_refused(response, code, 502)
        assert "vectors" not in response.text

    def test_d05_boundary_and_scope_immutable_in_the_database(
        self, ai_world: AiWorld, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: the schema refuses a boundary or credential-scope change."""
        operator = require_operator(ai_operator)
        database = ai_world.gateway.config.ai_db_name
        statements = {
            "provider boundary": (
                "UPDATE ai_provider SET boundary = 'external' "  # nosec B608 - sql_value
                f"WHERE id = '{sql_value(ai_world.provider_id)}'"
            ),
            "credential scope": (
                "UPDATE ai_credential SET scope_type = 'tenant', "  # nosec B608 - sql_value
                "tenant_id = gen_random_uuid() "
                f"WHERE id = '{sql_value(ai_world.credential_id)}'"
            ),
            "credential provider": (
                "UPDATE ai_credential SET provider_id = gen_random_uuid() "  # nosec B608 - sql_value
                f"WHERE id = '{sql_value(ai_world.credential_id)}'"
            ),
        }
        for user in ("ai_runtime", "postgres"):
            for label, sql in statements.items():
                result = operator.psql(database, sql, user=user, check=False)
                assert result.returncode != 0, (
                    f"[SECURITY FAIL] the database accepted a {label} change as {user}"
                )

    def test_d06_runtime_role_cannot_rewrite_audit(
        self, ai_world: AiWorld, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: the runtime role cannot update or delete audit rows (D-04)."""
        operator = require_operator(ai_operator)
        database = ai_world.gateway.config.ai_db_name
        for table in ("ai_admin_audit", "ai_credential_audit"):
            for sql in (
                f"DELETE FROM {table} WHERE false",  # nosec B608 - a fixed table name
                f"UPDATE {table} SET id = id WHERE false",  # nosec B608 - a fixed table name
            ):
                result = operator.psql(database, sql, user="ai_runtime", check=False)
                assert result.returncode != 0, (
                    f"[SECURITY FAIL] ai_runtime may run {sql.split()[0]} on {table}"
                )


# ── Secrets (S-01) ────────────────────────────────────────────────────────────


def _assert_secret_absent(
    world: AiWorld, operator: StackOperator, secrets_: list[str], where: str
) -> None:
    config = world.gateway.config
    surfaces = {
        "database dump": operator.pg_dump(config.ai_db_name),
        "gateway logs": operator.logs("ai_gateway"),
        "scheduler logs": operator.logs("ai_gateway_scheduler"),
    }
    if config.ai_metrics_credential:
        surfaces["metrics"] = world.gateway.metrics()
    for secret in secrets_:
        leaked = [name for name, text in surfaces.items() if secret in text]
        assert not leaked, (
            f"[SECURITY FAIL: S-01] a {where} canary is readable in: {leaked}"
        )


class AiGatewaySecretsSuite:
    """Stored provider secrets never leave the store (S-01)."""

    def test_e01_global_canary_absent_from_every_surface(
        self, ai_world: AiWorld, ai_stub: Any, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: a used and rotated key is absent from dump, logs, metrics, API."""
        operator = require_operator(ai_operator)
        credential_id, first = ai_world.credential()
        profile = ai_world.profile("embedding")
        ai_world.bind("admin", profile, credential_id)
        assert ai_world.execute("embedding", profile).status_code == 200
        second = canary("rotated")
        ai_stub.allow(second)
        rotated = ai_world.admin.request(
            "POST", f"admin/credentials/{credential_id}:rotate", {"secret": second}
        )
        assert rotated.status_code == 200, rotated.text[:200]
        mark = ai_stub.mark()
        assert ai_world.execute("embedding", profile).status_code == 200
        assert _fingerprints(ai_stub.since(mark)) == {bearer_fingerprint(second)}
        listing = ai_world.admin.request("GET", "admin/credentials").text
        single = ai_world.admin.request(
            "GET", f"admin/credentials/{credential_id}"
        ).text
        for secret in (first, second):
            assert secret not in listing and secret not in single, (
                "[SECURITY FAIL: S-01] the management API returned a stored secret"
            )
        _assert_secret_absent(ai_world, operator, [first, second], "global")


# ── Policy and destination (D-08, C-04) ───────────────────────────────────────


class AiGatewayPolicySuite:
    """Boundaries, data classes and credential isolation (D-08, S-05 gateway share)."""

    def _external(self, ai_world: AiWorld, capability: str) -> tuple[str, str]:
        provider_id = ai_world.provider(_EXTERNAL_HOST, "external")
        model_id = ai_world.model(provider_id, (capability,))
        credential_id, _ = ai_world.credential(
            provider_id=provider_id, key=canary("external"), accepted=False
        )
        return model_id, credential_id

    def test_f01_rerank_never_leaves_for_an_external_profile(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: rerank against an external provider → boundary_denied."""
        model_id, credential_id = self._external(ai_world, "rerank")
        profile = ai_world.profile("rerank")
        ai_world.bind("admin", profile, credential_id, model_id=model_id)
        claims = ai_world.claims("rerank", profile)
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "rerank",
            execution_body("rerank", profile),
            mint_context(claims, ai_world.seed),
        )
        _assert_refused(response, "boundary_denied", 403)
        _assert_no_provider_request(ai_world, mark, claims.job_ref)

    def test_f02_repoint_after_mint_is_honoured(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a binding repointed to an external model after the
        context was minted is refused at execution, not at mint time."""
        model_id, credential_id = self._external(ai_world, "rerank")
        profile = ai_world.profile("rerank")
        local_credential, _ = ai_world.credential()
        binding = ai_world.bind("admin", profile, local_credential)
        assert ai_world.execute("rerank", profile).status_code == 200
        claims = ai_world.claims("rerank", profile)
        context = mint_context(claims, ai_world.seed)
        repointed = ai_world.admin.request(
            "PATCH",
            f"admin/bindings/{binding}",
            {"model_id": model_id, "credential_id": credential_id},
        )
        assert repointed.status_code == 200, repointed.text[:200]
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "rerank", execution_body("rerank", profile), context
        )
        _assert_refused(response, "boundary_denied", 403)
        _assert_no_provider_request(ai_world, mark, claims.job_ref)

    @pytest.mark.parametrize("data_class", ["internal", "restricted"])
    def test_f03_non_public_data_never_reaches_a_platform_key(
        self, ai_world: AiWorld, ai_stub: Any, data_class: str
    ) -> None:
        """SECURITY PASS: internal/restricted data to an external platform key → denied."""
        model_id, credential_id = self._external(ai_world, "embedding")
        profile = ai_world.profile("embedding")
        ai_world.bind("admin", profile, credential_id, model_id=model_id)
        claims = ai_world.claims("embedding", profile, data_class=data_class)
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", profile),
            mint_context(claims, ai_world.seed),
        )
        assert response.status_code == 403 and error_code(response) in {
            "data_class_denied",
            "boundary_denied",
        }, (
            f"[SECURITY FAIL: D-08] {data_class} data was routed to an external "
            f"platform key: {response.status_code} {response.text[:200]}"
        )
        _assert_no_provider_request(ai_world, mark, claims.job_ref)

    def test_f04_invalid_tenant_key_leaves_other_tenants_flowing(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: one tenant's revoked BYOK key never stops another tenant."""
        profile = ai_world.profile("embedding")
        tenants = {}
        for label, accepted in (("bad", False), ("good", True)):
            tenant = str(uuid.uuid4())
            credential_id, key = ai_world.credential(
                f"tenants/{tenant}", accepted=accepted
            )
            ai_world.bind(f"tenants/{tenant}", profile, credential_id)
            tenants[label] = (tenant, key)
        for _ in range(3):
            bad = ai_world.execute("embedding", profile, tenant_id=tenants["bad"][0])
            assert bad.status_code >= 400, "control failed: a refused key executed"
            mark = ai_stub.mark()
            good = ai_world.execute("embedding", profile, tenant_id=tenants["good"][0])
            assert good.status_code == 200, (
                f"[SECURITY FAIL] tenant B stopped after tenant A's key failed: "
                f"{good.status_code} {good.text[:200]}"
            )
            assert _fingerprints(ai_stub.since(mark)) == {
                bearer_fingerprint(tenants["good"][1])
            }

    def test_f05_disabled_explicit_credential_never_falls_to_the_global_key(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a tenant binding whose credential is disabled fails closed."""
        profile = ai_world.profile("embedding")
        global_credential, global_key = ai_world.credential()
        ai_world.bind("admin", profile, global_credential)
        tenant = str(uuid.uuid4())
        credential_id, _ = ai_world.credential(f"tenants/{tenant}")
        ai_world.bind(f"tenants/{tenant}", profile, credential_id)
        disabled = ai_world.admin.request(
            "POST", f"tenants/{tenant}/credentials/{credential_id}:disable"
        )
        assert disabled.status_code == 200, disabled.text[:200]
        claims = ai_world.claims("embedding", profile, tenant_id=tenant)
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", profile),
            mint_context(claims, ai_world.seed),
        )
        _assert_refused(response, "credential_unavailable", 503)
        _assert_no_provider_request(ai_world, mark, claims.job_ref)
        other = ai_world.execute("embedding", profile, tenant_id=str(uuid.uuid4()))
        assert other.status_code == 200, (
            "control failed: the global binding is unusable"
        )
        assert bearer_fingerprint(global_key) in _fingerprints(ai_stub.since(mark))

    def test_f06_throttled_credential_refused_without_a_call(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a provider 429 cools the credential down; the next call
        is refused by the gateway without reaching the provider."""
        profile = ai_world.profile("embedding")
        credential_id, _ = ai_world.credential()
        ai_world.bind("admin", profile, credential_id)
        ai_stub.configure(mode="throttle:30")
        first = ai_world.execute("embedding", profile)
        _assert_refused(first, "rate_limited", 429)
        ai_stub.configure(mode="ok")
        mark = ai_stub.mark()
        for _ in range(3):
            again = ai_world.execute("embedding", profile)
            _assert_refused(again, "rate_limited", 429)
        _assert_no_provider_request(ai_world, mark)


# ── User scope (Q6, D-05, A-1, A-2) ───────────────────────────────────────────


class AiGatewayUserScopeSuite:
    """Personal BYOK in the first release (Q6, A-1, A-2)."""

    def test_u01_meta_reports_user_byok_enabled(
        self, ai_gateway: GatewayClient
    ) -> None:
        """SECURITY PASS: the first-deployment configuration enables user BYOK."""
        assert ai_gateway.meta()["gateway"]["user_byok_enabled"] is True, (
            "/meta reports user_byok_enabled false: the approved first-deployment "
            "configuration (Q6) is not deployed"
        )

    def test_u02_writer_manages_its_own_key_end_to_end(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a WRITER creates, validates, rotates, binds, disables
        and deletes its own key, and executions follow each step."""
        tenant = str(uuid.uuid4())
        writer = ai_world.users.create("writer", tenant)
        me = ai_world.session_for(writer)
        profile = ai_world.profile("embedding")
        credential_id, first = ai_world.credential("me", session=me)
        validated = me.request("POST", f"me/credentials/{credential_id}:validate")
        assert validated.status_code == 200, validated.text[:200]
        second = canary("me-rotated")
        ai_stub.allow(second)
        assert (
            me.request(
                "POST", f"me/credentials/{credential_id}:rotate", {"secret": second}
            ).status_code
            == 200
        )
        binding = ai_world.bind("me", profile, credential_id, session=me)
        claims = {"tenant_id": tenant, "user_id": writer["id"]}
        mark = ai_stub.mark()
        assert ai_world.execute("embedding", profile, **claims).status_code == 200
        assert _fingerprints(ai_stub.since(mark)) == {bearer_fingerprint(second)}
        assert (
            me.request("POST", f"me/credentials/{credential_id}:disable").status_code
            == 200
        )
        mark = ai_stub.mark()
        _assert_refused(
            ai_world.execute("embedding", profile, **claims),
            "credential_unavailable",
            503,
        )
        _assert_no_provider_request(ai_world, mark)
        assert me.request("DELETE", f"me/bindings/{binding}").status_code == 204
        assert (
            me.request("DELETE", f"me/credentials/{credential_id}").status_code == 204
        )
        assert first not in me.request("GET", "me/credentials").text

    def test_u03_other_principals_cannot_reach_a_users_key(
        self, ai_world: AiWorld
    ) -> None:
        """SECURITY PASS: user B, the tenant's ADMIN and lower tiers are refused."""
        tenant = str(uuid.uuid4())
        owner = ai_world.users.create("writer", tenant)
        credential_id, secret = ai_world.credential(
            "me", session=ai_world.session_for(owner)
        )
        peer = ai_world.session_for(ai_world.users.create("writer", tenant))
        admin = ai_world.session_for(ai_world.users.create("admin", tenant))
        for label, session, path in (
            ("user B", peer, f"me/credentials/{credential_id}"),
            ("tenant ADMIN", admin, f"tenants/{tenant}/credentials/{credential_id}"),
        ):
            response = session.request("GET", path)
            assert response.status_code == 404, (
                f"[SECURITY FAIL: A-1] {label} read another user's key: "
                f"{response.status_code}"
            )
            listing = session.request("GET", path.rsplit("/", 1)[0]).text
            assert credential_id not in listing, f"[SECURITY FAIL] {label} lists it"
        for role in ("reader", "user"):
            low = ai_world.session_for(ai_world.users.create(role, tenant))
            response = low.request("GET", "me/credentials")
            assert response.status_code == 403, (
                f"[SECURITY FAIL: A-1] a {role.upper()}-tier token reached "
                f"/v1/me/credentials ({response.status_code})"
            )
            created = low.request(
                "POST",
                "me/credentials",
                {
                    "provider_id": ai_world.provider_id,
                    "name": "t88",
                    "secret": canary("low"),
                },
            )
            assert created.status_code == 403
        stop = ai_world.admin.request(
            "GET", f"admin/user-credentials?owner_user_id={owner['id']}"
        )
        assert stop.status_code == 200 and secret not in stop.text

    def test_u04_superuser_stop_fails_the_users_next_execution(
        self, ai_world: AiWorld, ai_stub: Any
    ) -> None:
        """SECURITY PASS: a superuser-disabled user key → credential_unavailable, no call (A-2)."""
        tenant = str(uuid.uuid4())
        user = ai_world.users.create("writer", tenant)
        me = ai_world.session_for(user)
        profile = ai_world.profile("embedding")
        credential_id, _ = ai_world.credential("me", session=me)
        ai_world.bind("me", profile, credential_id, session=me)
        claims = {"tenant_id": tenant, "user_id": user["id"]}
        assert ai_world.execute("embedding", profile, **claims).status_code == 200
        stopped = ai_world.admin.request(
            "POST", f"admin/user-credentials/{credential_id}:disable"
        )
        assert stopped.status_code == 200, stopped.text[:200]
        context_claims = ai_world.claims("embedding", profile, **claims)
        mark = ai_stub.mark()
        response = ai_world.gateway.execute(
            "embedding",
            execution_body("embedding", profile),
            mint_context(context_claims, ai_world.seed),
        )
        _assert_refused(response, "credential_unavailable", 503)
        _assert_no_provider_request(ai_world, mark, context_claims.job_ref)

    def test_u05_user_binding_precedence(self, ai_world: AiWorld, ai_stub: Any) -> None:
        """SECURITY PASS: a user context resolves its own binding first; a context
        without user_id, or another user's, never does."""
        tenant = str(uuid.uuid4())
        user = ai_world.users.create("writer", tenant)
        profile = ai_world.profile("embedding")
        tenant_credential, tenant_key = ai_world.credential(f"tenants/{tenant}")
        ai_world.bind(f"tenants/{tenant}", profile, tenant_credential)
        me = ai_world.session_for(user)
        user_credential, user_key = ai_world.credential("me", session=me)
        ai_world.bind("me", profile, user_credential, session=me)
        cases = (
            ({"tenant_id": tenant, "user_id": user["id"]}, user_key),
            ({"tenant_id": tenant}, tenant_key),
            ({"tenant_id": tenant, "user_id": str(uuid.uuid4())}, tenant_key),
        )
        for claims, expected in cases:
            mark = ai_stub.mark()
            response = ai_world.execute("embedding", profile, **claims)
            assert response.status_code == 200, response.text[:200]
            seen = _fingerprints(ai_stub.since(mark))
            assert seen == {bearer_fingerprint(expected)}, (
                f"[SECURITY FAIL: C-04] claims {sorted(claims)} resolved the wrong key"
            )

    def test_u06_user_canary_absent_from_every_surface(
        self, ai_world: AiWorld, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: a user's key is absent from dump, logs and metrics."""
        operator = require_operator(ai_operator)
        tenant = str(uuid.uuid4())
        user = ai_world.users.create("writer", tenant)
        me = ai_world.session_for(user)
        profile = ai_world.profile("embedding")
        credential_id, secret = ai_world.credential("me", session=me)
        ai_world.bind("me", profile, credential_id, session=me)
        assert (
            ai_world.execute(
                "embedding", profile, tenant_id=tenant, user_id=user["id"]
            ).status_code
            == 200
        )
        _assert_secret_absent(ai_world, operator, [secret], "user")


# ── Boot: schema head and installation identity (D-04, C-14) ──────────────────


def _service_command(operator: StackOperator, service: str) -> list[str]:
    config = operator.inspect(operator.container(service))["Config"]
    return [*(config.get("Entrypoint") or []), *(config.get("Cmd") or [])]


def _boot_output(result: Any) -> str:
    return f"{result.stdout}{result.stderr}"


class AiGatewayBootSuite:
    """Web and scheduler refuse to start on the wrong schema or installation."""

    @pytest.mark.parametrize("service", ["ai_gateway", "ai_gateway_scheduler"])
    def test_b01_schema_other_than_the_packaged_head_refused(
        self, ai_gateway: GatewayClient, ai_operator: StackOperator | None, service: str
    ) -> None:
        """SECURITY PASS: a process refuses a database not at its packaged head.

        The recorded revision is moved off the head, a copy of ``service`` is
        booted, and the revision is restored; the running services are never
        restarted.
        """
        operator = require_operator(ai_operator)
        head = operator.query("SELECT version_num FROM alembic_version_ai")[0][0]
        database = ai_gateway.config.ai_db_name
        operator.psql(
            database, "UPDATE alembic_version_ai SET version_num = '9999_t88_not_head'"
        )
        try:
            result = operator.run_copy(service, f"t88-schema-{short_id()}", timeout=180)
        finally:
            operator.psql(
                database,
                "UPDATE alembic_version_ai SET version_num = "  # nosec B608 - sql_value
                f"'{sql_value(head)}'",
            )
        assert result.returncode != 0, (
            f"[SECURITY FAIL: D-04] {service} started on a schema revision other "
            "than its packaged head"
        )
        assert "schema revision mismatch" in _boot_output(result)

    @pytest.mark.parametrize("service", ["ai_gateway", "ai_gateway_scheduler"])
    def test_b02_other_installation_id_refused(
        self, ai_operator: StackOperator | None, service: str
    ) -> None:
        """SECURITY PASS: AI_DEPLOYMENT_ID ≠ ai_installation → boot refused (C-14)."""
        operator = require_operator(ai_operator)
        command = [
            "sh",
            "-c",
            f"umask 077; printf %s {uuid.uuid4()} > /tmp/deployment_id; "
            'export AI_DEPLOYMENT_ID_FILE=/tmp/deployment_id; exec "$@"',
            "sh",
            *_service_command(operator, service),
        ]
        result = operator.run_copy(
            service, f"t88-installation-{short_id()}", command=command, timeout=180
        )
        assert result.returncode != 0, (
            f"[SECURITY FAIL: C-14] {service} started under another installation's "
            "AI_DEPLOYMENT_ID"
        )
        assert "AI_DEPLOYMENT_ID differs" in _boot_output(result)


# ── Execution sequence and settlement (S-13, D-24, D-42) ──────────────────────


def _execution_row(operator: StackOperator, job_ref: str) -> dict[str, str]:
    rows = operator.query(
        "SELECT status, coalesce(settled_at::text, ''), "
        "first_byte_sent_at IS NOT NULL, tenant_scope_id "
        f"FROM ai_execution WHERE job_ref = '{sql_value(job_ref)}'"  # nosec B608 - sql_value
    )
    if not rows:
        return {}
    status, settled_at, sent, tenant = rows[0]
    return {"status": status, "settled_at": settled_at, "sent": sent, "tenant": tenant}


def _tenant_usage(operator: StackOperator, tenant: str) -> tuple[int, int]:
    rows = operator.query(
        "SELECT coalesce(sum(reserved), 0), coalesce(sum(used), 0) FROM ai_usage "
        f"WHERE scope_type = 'tenant' AND scope_id = '{sql_value(tenant)}'"  # nosec B608 - sql_value
    )
    return int(rows[0][0]), int(rows[0][1])


def _settlement_holder(operator: StackOperator) -> tuple[str, int]:
    holder, epoch = operator.query(
        "SELECT holder, epoch FROM ai_scheduler_lease WHERE job = 'settlement'"
    )[0]
    return holder, int(epoch)


class AiGatewaySettlementSuite:
    """Settlement after a crash, under a fenced scheduler lease (S-13, D-42)."""

    def test_t01_kill_after_send_paused_leader_and_double_sweep(
        self, ai_world: AiWorld, ai_stub: Any, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: a gateway killed after the provider received the request
        settles ``charged_uncertain`` exactly once — by the scheduler that holds
        the lease, while the paused former leader resumes and commits nothing,
        and later sweeps change nothing.

        Sequence: the stub holds the request; the web process is killed once the
        stub has it; the scheduler is paused past its 60 s lease; a second
        scheduler takes the lease and settles the row after the dispatch
        deadline; the first is resumed; two more sweep periods pass.
        """
        operator = require_operator(ai_operator)
        tenant = str(uuid.uuid4())
        claims = ai_world.claims("embedding", tenant_id=tenant)
        context = mint_context(claims, ai_world.seed)
        ai_stub.configure(mode="delay:600")
        mark = ai_stub.mark()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        pending = pool.submit(
            ai_world.gateway.execute,
            "embedding",
            execution_body("embedding", claims.profile_key),
            context,
            timeout=900,
        )
        second_scheduler: str | None = None
        paused = False
        try:
            assert wait_for(lambda: ai_stub.since(mark), 30, 0.5), (
                "setup: the stub never received the request"
            )
            operator.lifecycle("kill", "ai_gateway")
            operator.lifecycle("pause", "ai_gateway_scheduler")
            paused = True
            ai_stub.configure(mode="ok")
            first_holder, first_epoch = _settlement_holder(operator)
            row = _execution_row(operator, claims.job_ref)
            assert row.get("status") == "dispatching" and row["sent"] == "t", row
            time.sleep(65)  # past LEASE_TTL_SECONDS: the paused lease runs out
            second_scheduler = operator.start_copy(
                "ai_gateway_scheduler", f"t88-scheduler-{short_id()}"
            )
            operator.lifecycle("start", "ai_gateway")
            settled = wait_for(
                lambda: (
                    _execution_row(operator, claims.job_ref).get("status")
                    == "charged_uncertain"
                ),
                420,
                5,
            )
            assert settled, (
                "[SECURITY FAIL: S-13] the killed execution never settled: "
                f"{_execution_row(operator, claims.job_ref)}"
            )
            holder, epoch = _settlement_holder(operator)
            assert holder != first_holder and epoch > first_epoch, (
                "the settlement did not run under a new lease"
            )
            settled_row = _execution_row(operator, claims.job_ref)
            usage = _tenant_usage(operator, tenant)
            operator.lifecycle("unpause", "ai_gateway_scheduler")
            paused = False
            time.sleep(40)  # the resumed leader's tick, then two sweep periods
            assert _execution_row(operator, claims.job_ref) == settled_row, (
                "[SECURITY FAIL: D-42] the resumed former leader re-settled the row"
            )
            assert _tenant_usage(operator, tenant) == usage, (
                "[SECURITY FAIL: S-13] a later sweep changed the charge"
            )
            reserved, used = usage
            assert reserved == 0 and used > 0, (
                "[SECURITY FAIL: S-13] a request the provider received must be "
                f"charged, never refunded: reserved={reserved} used={used}"
            )
        finally:
            ai_stub.configure(mode="ok")
            if paused:
                operator.lifecycle("unpause", "ai_gateway_scheduler")
            if second_scheduler:
                operator.remove(second_scheduler)
            operator.lifecycle("start", "ai_gateway")
            assert operator.wait_healthy("ai_gateway"), "the gateway did not recover"
            pool.shutdown(wait=False, cancel_futures=True)
        del pending

    def test_t02_stalled_vault_before_the_marker_releases(
        self, ai_world: AiWorld, ai_stub: Any, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: a Vault stalled while a credential is resolved → the
        execution is released (no charge) and no provider request leaves."""
        operator = require_operator(ai_operator)
        if not operator.containers("vault"):
            pytest.skip("the stack has no vault service (vault_transit_m8 only)")
        profile = ai_world.profile("embedding")
        credential_id, _ = ai_world.credential()
        ai_world.bind("admin", profile, credential_id)
        tenant = str(uuid.uuid4())
        claims = ai_world.claims("embedding", profile, tenant_id=tenant)
        mark = ai_stub.mark()
        operator.lifecycle("pause", "vault")
        try:
            response = ai_world.gateway.execute(
                "embedding",
                execution_body("embedding", profile),
                mint_context(claims, ai_world.seed),
                timeout=120,
            )
        finally:
            operator.lifecycle("unpause", "vault")
        assert response.status_code in (503, 504) and error_code(response) in {
            "credential_unavailable",
            "timeout",
        }, (
            f"unexpected answer, Vault stalled: {response.status_code} {response.text[:200]}"
        )
        _assert_no_provider_request(ai_world, mark, claims.job_ref)
        row = _execution_row(operator, claims.job_ref)
        assert row.get("status") in (None, "released"), (
            f"[SECURITY FAIL: S-13] a stalled credential fetch left {row}"
        )
        assert _tenant_usage(operator, tenant)[1] == 0, (
            "[SECURITY FAIL: S-13] an execution that never dispatched was charged"
        )


# ── Two replicas (S-13, D-24) ─────────────────────────────────────────────────


def _fresh_rate_window() -> None:
    """Wait for a new minute so the client's rate window starts empty."""
    time.sleep(61 - (time.time() % 60))


class AiGatewayReplicaSuite:
    """Admission and cooldown hold across two web replicas (S-13, D-24)."""

    def test_r01_throttled_credential_refused_on_both_replicas(
        self, ai_world: AiWorld, ai_stub: Any, ai_replicas: list[GatewayClient]
    ) -> None:
        """SECURITY PASS: a cooldown set through one replica binds the other."""
        profile = ai_world.profile("embedding")
        credential_id, _ = ai_world.credential()
        ai_world.bind("admin", profile, credential_id)
        body = execution_body("embedding", profile)
        ai_stub.configure(mode="throttle:60")
        first = ai_replicas[0].execute(
            "embedding", body, ai_world.context("embedding", profile)
        )
        _assert_refused(first, "rate_limited", 429)
        ai_stub.configure(mode="ok")
        mark = ai_stub.mark()
        for replica in ai_replicas:
            again = replica.execute(
                "embedding", body, ai_world.context("embedding", profile)
            )
            _assert_refused(again, "rate_limited", 429)
        _assert_no_provider_request(ai_world, mark)

    def test_r02_concurrent_overspend_across_replicas_refused(
        self,
        ai_world: AiWorld,
        ai_stub: Any,
        ai_replicas: list[GatewayClient],
        ai_operator: StackOperator | None,
    ) -> None:
        """SECURITY PASS: with room for two executions left in a tenant's daily
        budget, twelve simultaneous requests over both replicas → exactly two."""
        operator = require_operator(ai_operator)
        budget = ai_world.gateway.config.ai_tenant_daily_budget_units
        if budget is None:
            pytest.skip(
                "needs LIVE_TEST_AI_TENANT_DAILY_BUDGET_UNITS (the stack's value)"
            )
        _fresh_rate_window()
        tenant = str(uuid.uuid4())
        warm = ai_world.execute("embedding", tenant_id=tenant)
        assert warm.status_code == 200, warm.text[:200]
        units = int(warm.json()["execution"]["units"])
        operator.psql(
            ai_world.gateway.config.ai_db_name,
            f"UPDATE ai_usage SET used = {int(budget - 2 * units)} "  # nosec B608 - int, sql_value
            f"WHERE scope_type = 'tenant' AND scope_id = '{sql_value(tenant)}'",
        )
        body = execution_body("embedding", ai_world.profiles["embedding"])
        contexts = [ai_world.context("embedding", tenant_id=tenant) for _ in range(12)]
        mark = ai_stub.mark()
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            responses = list(
                pool.map(
                    lambda item: ai_replicas[item[0] % 2].execute(
                        "embedding", body, item[1]
                    ),
                    enumerate(contexts),
                )
            )
        accepted = [r for r in responses if r.status_code == 200]
        assert len(accepted) == 2, (
            f"[SECURITY FAIL: S-13] {len(accepted)} executions admitted with room "
            f"for two: {sorted(r.status_code for r in responses)}"
        )
        assert {error_code(r) for r in responses if r.status_code != 200} == {
            "quota_exceeded"
        }
        assert len(ai_stub.since(mark)) == 2
        reserved, used = _tenant_usage(operator, tenant)
        assert reserved == 0 and used <= budget, (reserved, used)

    def test_r03_in_flight_cap_holds_across_replicas(
        self, ai_world: AiWorld, ai_stub: Any, ai_replicas: list[GatewayClient]
    ) -> None:
        """SECURITY PASS: N slow requests over both replicas never put more than
        AI_MAX_INFLIGHT_PER_CLIENT in dispatch, and every slot comes back."""
        cap = ai_world.gateway.config.ai_max_inflight_per_client
        if cap is None:
            pytest.skip(
                "needs LIVE_TEST_AI_MAX_INFLIGHT_PER_CLIENT (the stack's value)"
            )
        total = cap + 8
        _fresh_rate_window()
        ai_stub.configure(mode="delay:4")
        body = execution_body("embedding", ai_world.profiles["embedding"])
        contexts = [ai_world.context("embedding") for _ in range(total)]
        mark = ai_stub.mark()
        with concurrent.futures.ThreadPoolExecutor(max_workers=total) as pool:
            responses = list(
                pool.map(
                    lambda item: ai_replicas[item[0] % 2].execute(
                        "embedding", body, item[1]
                    ),
                    enumerate(contexts),
                )
            )
        ai_stub.configure(mode="ok")
        accepted = sum(r.status_code == 200 for r in responses)
        assert 0 < accepted <= cap, (
            f"[SECURITY FAIL: S-13] {accepted} of {total} executions ran at once "
            f"with an in-flight cap of {cap}"
        )
        assert len(ai_stub.since(mark)) == accepted
        assert {error_code(r) for r in responses if r.status_code != 200} <= {
            "rate_limited"
        }
        after = ai_world.execute("embedding")
        assert after.status_code == 200, (
            f"[SECURITY FAIL: S-13] an in-flight slot was not returned: {after.text[:200]}"
        )


# ── Restore (D-42, D-43, D-45) ────────────────────────────────────────────────

_SNAPSHOT = "/tmp/t88-ai-db.dump"  # nosec B108 - inside the database container
#: The restore steps wait out the replay hold: the context TTL cap plus skew
#: (900 s + 5 s on the first-deployment stacks), then a scheduler pass.
_RESTORE_STEPS_TIMEOUT = 1500


def _epoch(operator: StackOperator) -> int:
    return int(operator.query("SELECT last_value FROM ai_db_epoch")[0][0])


class AiGatewayRestoreSuite:
    """A snapshot restore is detected and held until ratified (D-42).

    Runs last: ratification leaves the deployment's budget hold in force until
    the next UTC day, so every budgeted execution on the stack is refused with
    ``quota_exceeded`` until then.
    """

    def _restart(self, operator: StackOperator, action: str) -> None:
        for service in ("ai_gateway", "ai_gateway_scheduler"):
            operator.lifecycle(action, service)

    def _restore_command(self, operator: StackOperator, *args: str) -> Any:
        return operator.run_copy(
            "ai_gateway",
            f"t88-restore-{short_id()}",
            command=["python", "-m", "ai_gateway.restore", *args],
            timeout=180,
        )

    def test_x01_restore_detected_reconciled_and_ratified(
        self, ai_world: AiWorld, ai_stub: Any, ai_operator: StackOperator | None
    ) -> None:
        """SECURITY PASS: execution refuses ``restore_detected`` after a snapshot
        restore; ``restore-reconcile`` resets providers, credentials and
        ``fall_through`` bindings; ``restore-ratify`` is refused until every step
        completed and then restores only what is re-confirmed."""
        operator = require_operator(ai_operator)
        config = ai_world.gateway.config
        database = config.ai_db_name
        held = operator.query(
            "SELECT ratified_at IS NULL AND detected_at IS NOT NULL FROM ai_restore_state"
        )
        if held[0][0] == "t":
            pytest.skip("a restore is already held on this stack")
        tenant = f"tenants/{uuid.uuid4()}"
        tenant_credential, _ = ai_world.credential(tenant)
        ai_world.bind(
            tenant,
            ai_world.profiles["embedding"],
            tenant_credential,
            on_unavailable="fall_through",
        )
        epoch = _epoch(operator)
        operator.exec(
            config.ai_db_service,
            ["pg_dump", "-U", "postgres", "-Fc", "-f", _SNAPSHOT, database],
        )
        assert wait_for(lambda: _epoch(operator) > epoch, 180, 5), (
            "setup: the scheduler never advanced the database epoch"
        )
        time.sleep(10)  # the high-water write follows the epoch draw
        self._restart(operator, "stop")
        try:
            operator.exec(
                config.ai_db_service,
                [
                    "pg_restore",
                    "-U",
                    "postgres",
                    "--clean",
                    "--if-exists",
                    "-d",
                    database,
                    _SNAPSHOT,
                ],
                timeout=300,
            )
        finally:
            self._restart(operator, "start")
        assert operator.wait_healthy("ai_gateway"), "the gateway did not restart"
        mark = ai_stub.mark()
        detected = ai_world.execute("embedding")
        _assert_refused(detected, "restore_detected", 503)
        _assert_no_provider_request(ai_world, mark)

        self._restart(operator, "stop")
        try:
            entered = self._restore_command(operator, "reconcile")
        finally:
            self._restart(operator, "start")
        assert entered.returncode == 0, _boot_output(entered)[-400:]
        assert operator.wait_healthy("ai_gateway")
        enabled = operator.query("SELECT count(*) FROM ai_provider WHERE enabled")[0][0]
        active = operator.query(
            "SELECT count(*) FROM ai_credential WHERE status = 'active'"
        )[0][0]
        falling = operator.query(
            "SELECT count(*) FROM ai_profile_binding WHERE on_unavailable = 'fall_through'"
        )[0][0]
        assert (enabled, active, falling) == ("0", "0", "0"), (
            "[SECURITY FAIL: D-42] restore-reconcile left providers enabled, "
            f"credentials active or fall_through bindings: {enabled}/{active}/{falling}"
        )
        _assert_refused(ai_world.execute("embedding"), "restore_detected", 503)
        early = self._restore_command(operator, "ratify", "--evidence", "t88 early")
        assert early.returncode == 1, (
            "[SECURITY FAIL: D-42] restore-ratify succeeded before every step completed"
        )

        complete = wait_for(
            lambda: (
                operator.query(
                    "SELECT replay_safety_completed_at IS NOT NULL AND "
                    "external_reconciliation_completed_at IS NOT NULL AND "
                    "security_report_completed_at IS NOT NULL FROM ai_restore_state"
                )[0][0]
                == "t"
            ),
            _RESTORE_STEPS_TIMEOUT,
            15,
        )
        assert complete, "the scheduler never completed the restore steps"
        self._restart(operator, "stop")
        try:
            ratified = self._restore_command(operator, "ratify", "--evidence", "t88")
        finally:
            self._restart(operator, "start")
        assert ratified.returncode == 0, _boot_output(ratified)[-400:]
        assert operator.wait_healthy("ai_gateway")
        mark = ai_stub.mark()
        unconfirmed = ai_world.execute("embedding")
        assert error_code(unconfirmed) != "restore_detected"
        assert unconfirmed.status_code >= 400, (
            "[SECURITY FAIL: D-42] an execution ran on a provider and credential "
            "nobody re-confirmed after the restore"
        )
        assert (
            ai_world.admin.request(
                "PATCH", f"admin/providers/{ai_world.provider_id}", {"enabled": True}
            ).status_code
            == 200
        )
        assert (
            ai_world.admin.request(
                "POST", f"admin/credentials/{ai_world.credential_id}:reconfirm"
            ).status_code
            == 200
        )
        held = ai_world.execute("embedding")
        _assert_refused(held, "quota_exceeded", 429)
        _assert_no_provider_request(ai_world, mark)


# Class-level marks so they survive subclassing from another module; see the
# note at the end of `service.py`.
setattr(AiGatewayIngressSuite, "pytestmark", list(_MARKS))
for _suite in (
    AiGatewayBootSuite,
    AiGatewaySettlementSuite,
    AiGatewayReplicaSuite,
    AiGatewayRestoreSuite,
    AiGatewayContextSuite,
    AiGatewayDestinationSuite,
    AiGatewaySecretsSuite,
    AiGatewayPolicySuite,
    AiGatewayUserScopeSuite,
):
    setattr(_suite, "pytestmark", list(_STATEFUL_MARKS))

__all__ = [
    "AiGatewayBootSuite",
    "AiGatewayContextSuite",
    "AiGatewayDestinationSuite",
    "AiGatewayIngressSuite",
    "AiGatewayPolicySuite",
    "AiGatewayReplicaSuite",
    "AiGatewayRestoreSuite",
    "AiGatewaySecretsSuite",
    "AiGatewaySettlementSuite",
    "AiGatewayUserScopeSuite",
]
