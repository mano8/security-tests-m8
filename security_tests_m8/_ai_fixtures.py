"""Pytest fixtures for the AI gateway suites (registered by the plugin).

``ai_world`` builds, once per session, the minimum the execution rows need on
the gateway under test: a ``local`` provider pointing at the stub, one model
serving every non-OCR capability, one profile per capability with a global
binding to a global credential the stub accepts. Each name carries a unique
suffix, so runs never collide; providers and models cannot be deleted
through the API, so a run leaves those rows behind, disabled bindings and
throwaway issuer accounts excepted. Run the suite against a test stack only.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
import requests

from security_tests_m8._ai_gateway import (
    ContextClaims,
    GatewayClient,
    IssuerUsers,
    ManagementSession,
    StackOperator,
    StubControl,
    canary,
    load_seed,
    mint_context,
    operator_or_none,
    require_ai_target,
    require_operator,
    short_id,
    sql_value,
    wait_for,
)
from security_tests_m8._config import get_config

CAPABILITIES = ("embedding", "rerank", "structured_output")

STRUCTURED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def execution_body(capability: str, profile_key: str) -> dict[str, Any]:
    """Return a minimal valid execution body for ``capability``."""
    if capability == "embedding":
        return {"profile_key": profile_key, "inputs": ["t88 probe"]}
    if capability == "rerank":
        return {"profile_key": profile_key, "query": "q", "documents": ["a", "b"]}
    return {
        "profile_key": profile_key,
        "input": "t88 probe",
        "schema_name": "answer",
        "json_schema": STRUCTURED_SCHEMA,
    }


@dataclass
class AiWorld:
    """The session's gateway objects and the helpers that extend them."""

    gateway: GatewayClient
    admin: ManagementSession
    stub: StubControl
    operator: StackOperator | None
    users: IssuerUsers
    audience: str
    seed: bytes
    kid: str
    provider_id: str = ""
    model_id: str = ""
    key: str = ""
    credential_id: str = ""
    profiles: dict[str, str] = field(default_factory=dict)

    def claims(
        self, capability: str, profile_key: str | None = None, **kwargs: Any
    ) -> ContextClaims:
        """Return valid claims for ``capability``, overridden by ``kwargs``."""
        return ContextClaims(
            capability=capability,
            profile_key=profile_key or self.profiles[capability],
            audience=self.audience,
            issuer=self.gateway.config.ai_client_id,
            **kwargs,
        )

    def context(
        self, capability: str, profile_key: str | None = None, **kwargs: Any
    ) -> str:
        """Return a valid, freshly signed job context."""
        return mint_context(self.claims(capability, profile_key, **kwargs), self.seed)

    def execute(
        self,
        capability: str,
        profile_key: str | None = None,
        *,
        context: str | None = None,
        **claims: Any,
    ) -> Any:
        """Execute ``capability`` with a valid body and a fresh context."""
        key = profile_key or self.profiles[capability]
        ctx = (
            context if context is not None else self.context(capability, key, **claims)
        )
        return self.gateway.execute(capability, execution_body(capability, key), ctx)

    def profile(self, capability: str) -> str:
        """Create a new profile for ``capability`` (no binding yet)."""
        key = f"t88-{capability.replace('_', '-')}-{short_id()}"
        self.admin.create(
            "admin/profiles", {"profile_key": key, "capability": capability}
        )
        return key

    def credential(
        self,
        scope: str = "admin",
        *,
        session: ManagementSession | None = None,
        provider_id: str | None = None,
        key: str | None = None,
        accepted: bool = True,
    ) -> tuple[str, str]:
        """Store a credential in ``scope``; return ``(id, secret)``.

        ``scope`` is ``admin`` (global), ``tenants/<id>`` or ``me``. An
        ``accepted`` key is added to the stub's allow-list; any other is one the
        stub refuses with ``401``.
        """
        secret = key or canary(scope.split("/")[0])
        if accepted:
            self.stub.allow(secret)
        row = (session or self.admin).create(
            f"{scope}/credentials",
            {
                "provider_id": provider_id or self.provider_id,
                "name": f"t88-{short_id()}",
                "secret": secret,
            },
        )
        return str(row["id"]), secret

    def bind(
        self,
        scope: str,
        profile_key: str,
        credential_id: str | None,
        *,
        session: ManagementSession | None = None,
        model_id: str | None = None,
        on_unavailable: str = "fail",
    ) -> str:
        """Bind ``profile_key`` in ``scope``; return the binding id."""
        body: dict[str, Any] = {
            "profile_key": profile_key,
            "model_id": model_id or self.model_id,
            "on_unavailable": on_unavailable,
        }
        if credential_id is not None:
            body["credential_id"] = credential_id
        row = (session or self.admin).create(f"{scope}/bindings", body)
        return str(row["id"])

    def provider(self, base_url: str, boundary: str) -> str:
        """Register a provider; return its id."""
        row = self.admin.create(
            "admin/providers",
            {
                "name": f"t88-{boundary}-{short_id()}",
                "provider_type": "openai_compatible",
                "base_url": base_url,
                "auth_type": "bearer",
                "boundary": boundary,
            },
        )
        return str(row["id"])

    def model(
        self, provider_id: str, capabilities: tuple[str, ...] = CAPABILITIES
    ) -> str:
        """Register a model of ``provider_id``; return its id."""
        body: dict[str, Any] = {
            "provider_id": provider_id,
            "external_model_id": "stub-model",
            "capabilities": list(capabilities),
            "model_version_label": "t88-1",
        }
        if "embedding" in capabilities:
            body["dimensions"] = 8
        return str(self.admin.create("admin/models", body)["id"])

    def session_for(self, user: dict[str, str]) -> ManagementSession:
        """Return a management session under ``user``'s token."""
        return ManagementSession(self.gateway, user["token"])

    def dispatched(self, job_ref: str) -> bool | None:
        """Whether any execution of ``job_ref`` sent a first byte upstream.

        ``None`` without container access. The gateway records
        ``first_byte_sent_at`` immediately before a request's first byte is
        written (D-24), so ``False`` proves no provider request left.
        """
        if self.operator is None:
            return None
        rows = self.operator.query(
            "SELECT count(*) FROM ai_execution WHERE job_ref = "  # nosec B608 - sql_value
            f"'{sql_value(job_ref)}' AND first_byte_sent_at IS NOT NULL"
        )
        return int(rows[0][0]) > 0


def build_world(world: AiWorld) -> AiWorld:
    """Create the session's provider, model, credential, profiles and bindings."""
    gateway_url = world.gateway.config.ai_stub_gateway_url()
    assert gateway_url is not None
    world.provider_id = world.provider(gateway_url, "local")
    world.model_id = world.model(world.provider_id)
    world.credential_id, world.key = world.credential("admin")
    for capability in CAPABILITIES:
        profile_key = world.profile(capability)
        world.bind("admin", profile_key, world.credential_id)
        world.profiles[capability] = profile_key
    return world


@pytest.fixture(scope="session")
def ai_gateway() -> GatewayClient:
    """Return the configured AI gateway, skipping when none is configured."""
    config = get_config()
    require_ai_target(config)
    return GatewayClient(config)


@pytest.fixture(scope="session")
def ai_operator() -> StackOperator | None:
    """Return container-level access to the stack, when configured."""
    return operator_or_none(get_config())


@pytest.fixture(scope="session")
def ai_world(
    ai_gateway: GatewayClient, ai_operator: StackOperator | None
) -> Iterator[AiWorld]:
    """Build the session's gateway objects against the stub provider."""
    config = get_config()
    if not config.ai_stub_base_url:
        pytest.skip(
            "AI gateway execution checks require the stub provider: "
            "LIVE_TEST_AI_STUB_BASE (and LIVE_TEST_AI_STUB_CONTROL_TOKEN)"
        )
    assert config.ai_issuer_seed_file is not None
    seed, kid = load_seed(config.ai_issuer_seed_file)
    users = IssuerUsers(config, ai_operator)
    stub = StubControl(config)
    stub.configure(mode="ok")
    world = AiWorld(
        gateway=ai_gateway,
        admin=ManagementSession(
            ai_gateway, users.superuser_token(), relogin=users.superuser_token
        ),
        stub=stub,
        operator=ai_operator,
        users=users,
        audience=ai_gateway.audience(),
        seed=seed,
        kid=kid,
    )
    try:
        yield build_world(world)
    finally:
        users.cleanup()


@pytest.fixture
def ai_stub(ai_world: AiWorld) -> Iterator[StubControl]:
    """Yield the stub; restore its ``ok`` mode after the test."""
    try:
        yield ai_world.stub
    finally:
        ai_world.stub.configure(mode="ok")


def _reachable(client: GatewayClient) -> bool:
    try:
        return client.get("health/").status_code == 200
    except requests.RequestException:
        return False


@pytest.fixture(scope="class")
def ai_replicas(
    ai_world: AiWorld, ai_operator: StackOperator | None
) -> Iterator[list[GatewayClient]]:
    """Run a second web replica beside the stack's; yield a client per replica.

    The copy shares the first replica's image, configuration, secrets and
    networks, so both admit against one database. Each client addresses its
    replica directly on the ``app_net`` network the suite shares.
    """
    operator = require_operator(ai_operator)
    network = "app_net"
    first = ai_world.gateway.replica(
        operator.address(operator.container("ai_gateway"), network)
    )
    second_id = operator.start_copy("ai_gateway", f"t88-replica-{short_id()}")
    try:
        second = ai_world.gateway.replica(operator.address(second_id, network))
        assert wait_for(lambda: _reachable(second), 120, 2), (
            "setup: the second replica never answered /health"
        )
        yield [first, second]
    finally:
        operator.remove(second_id)
