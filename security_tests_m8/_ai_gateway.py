"""Live-target helpers for the AI gateway suites.

Everything here addresses the stack through configuration only
(``LIVE_TEST_AI_*``, ``LIVE_TEST_AUTH_BASE``, ``LIVE_TEST_ADMIN_*``): no path
into a sibling checkout, no import of gateway code. The pieces:

* :func:`mint_context` signs a job context with the suite's own test issuer
  seed through the public ``ai-sdk-m8`` primitive (the ``ai`` extra);
* :class:`GatewayAdmin` drives the management API as the issuer's superuser;
* :class:`IssuerUsers` creates throwaway issuer accounts at a given tier and
  tenant (tenant membership is provisioned out of band, through the stack's
  database, as the issuer documents);
* :class:`StubControl` steers and reads the stub provider;
* :class:`StackOperator` runs ``psql``, ``pg_dump``, ``logs`` and container
  lifecycle commands against the compose project through the container
  engine CLI, finding containers by their compose labels.

No helper logs a secret, a token or a job context.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess  # nosec B404 - the operator runs the configured engine CLI
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests

from security_tests_m8 import _availability
from security_tests_m8._config import LiveTestConfig

JOB_CONTEXT_HEADER = "X-AI-Job-Context"
EXECUTE_ROUTES = {
    "embedding": "embed",
    "rerank": "rerank",
    "structured_output": "structured-output",
}

#: Credential-write throttle retries (the gateway allows 20 per minute per user).
_WRITE_RETRIES = 3


#: What :func:`sql_value` lets into a statement: a UUID, or a token of letters,
#: digits, ``_`` and ``-`` (job refs, revision ids).
_SQL_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,64}")


def sql_value(value: str) -> str:
    """Return ``value`` for interpolation into one of the suite's SQL statements.

    The statements run through ``psql -c`` and interpolate only values the
    suite generated or read back (ids, job refs, a schema revision); anything
    but a UUID or a plain token is refused rather than quoted.
    """
    try:
        return str(uuid.UUID(value))
    except ValueError:
        if not _SQL_TOKEN.fullmatch(value):
            raise ValueError("refused SQL value") from None
        return value


def canary(label: str) -> str:
    """Return a unique, recognisable secret value for one test credential."""
    return f"t88-{label}-{secrets.token_hex(16)}"


def short_id() -> str:
    """Return a short unique suffix for names and profile keys."""
    return uuid.uuid4().hex[:10]


@contextmanager
def unguarded() -> Iterator[None]:
    """Disarm the availability guard for probes that expect a proxy ``404``.

    A public router that refuses a path answers Traefik's bare ``404 page not
    found`` — the very body the guard reads as "no route to the backend". An
    ingress probe asserts that answer, so it must see it; each such probe pairs
    it with a positive control on the same router.
    """
    active = _availability.guard_active()
    _availability.set_guard_active(False)
    try:
        yield
    finally:
        _availability.set_guard_active(active)


def require_ai_target(config: LiveTestConfig) -> None:
    """Skip unless the AI gateway target and the suite's client are configured."""
    if not config.ai_base_url:
        pytest.skip("AI gateway checks require LIVE_TEST_AI_BASE")
    if not config.ai_client_secret or config.ai_issuer_seed_file is None:
        pytest.skip(
            "AI gateway execution checks require LIVE_TEST_AI_CLIENT_SECRET and "
            "LIVE_TEST_AI_ISSUER_SEED_FILE (the stack's security-tests client)"
        )


def _sdk() -> tuple[Any, Any, Any]:
    try:
        from ai_sdk_m8.jobcontext import JobContextPayload, sign
        from ai_sdk_m8.signed import (
            derive_kid,
            load_seed_file,
            public_key_from_seed,
        )
    except ImportError:  # pragma: no cover - exercised without the ai extra
        pytest.skip(
            "AI gateway checks need the ai extra: pip install security-tests-m8[ai]"
        )
    return JobContextPayload, sign, (derive_kid, load_seed_file, public_key_from_seed)


def load_seed(path: Path) -> tuple[bytes, str]:
    """Return an Ed25519 seed file's seed and the ``kid`` it derives."""
    _, _, (derive_kid, load_seed_file, public_key_from_seed) = _sdk()
    seed = load_seed_file(path)
    return seed, derive_kid(public_key_from_seed(seed))


def generate_seed() -> bytes:
    """Return a fresh Ed25519 seed no stack has registered."""
    return secrets.token_bytes(32)


@dataclass(frozen=True)
class ContextClaims:
    """The claims of one job context; defaults describe a valid one."""

    capability: str
    profile_key: str
    audience: str
    issuer: str
    data_class: str = "public"
    tenant_id: str | None = None
    user_id: str | None = None
    job_ref: str = field(default_factory=lambda: f"t88-{short_id()}")
    ttl: int = 60
    not_before_offset: int = 0
    issued_offset: int = 0
    azp: str | None = None
    allowed_boundaries: tuple[str, ...] | None = None


def mint_context(claims: ContextClaims, seed: bytes, *, kid: str | None = None) -> str:
    """Sign ``claims`` into a compact job context with ``seed``.

    ``kid`` defaults to the one ``seed`` derives; passing another one signs a
    context whose ``kid`` names a key the signature does not match.
    """
    payload_type, sign, (derive_kid, _, public_key_from_seed) = _sdk()
    now = int(time.time())
    iat = now + claims.issued_offset
    data: dict[str, Any] = {
        "kid": kid or derive_kid(public_key_from_seed(seed)),
        "iss": claims.issuer,
        "aud": claims.audience,
        "azp": claims.azp or claims.issuer,
        "data_class": claims.data_class,
        "capability": claims.capability,
        "profile_key": claims.profile_key,
        "job_ref": claims.job_ref,
        "attempt": 1,
        "jti": str(uuid.uuid4()),
        "iat": iat,
        "nbf": iat + claims.not_before_offset,
        "exp": iat + claims.ttl,
    }
    for name in ("tenant_id", "user_id", "allowed_boundaries"):
        value = getattr(claims, name)
        if value is not None:
            data[name] = list(value) if name == "allowed_boundaries" else value
    if kid is None:
        return str(sign(payload_type(**data), seed=seed))
    return _sign_with_foreign_kid(payload_type, data, seed)


def _sign_with_foreign_kid(payload_type: Any, data: dict[str, Any], seed: bytes) -> str:
    """Sign under the seed's own ``kid``, then swap in the claimed one.

    The SDK refuses to sign a payload whose ``kid`` its seed does not derive,
    so a mismatched-key context is built by re-encoding the signed payload
    segment: the signature then covers a ``kid`` other than the one presented.
    """
    import base64
    import json

    from ai_sdk_m8.signed import canonicalize

    _, sign, (derive_kid, _, public_key_from_seed) = _sdk()
    claimed = data["kid"]
    own = {**data, "kid": derive_kid(public_key_from_seed(seed))}
    token = str(sign(payload_type(**own), seed=seed))
    head, _, signature = token.partition(".")
    payload = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    payload["kid"] = claimed
    encoded = base64.urlsafe_b64encode(canonicalize(payload)).rstrip(b"=")
    return f"{encoded.decode()}.{signature}"


def tamper(token: str) -> str:
    """Return ``token`` with one signature character flipped."""
    head, _, signature = token.partition(".")
    flipped = "A" if signature[-2] != "A" else "B"
    return f"{head}.{signature[:-2]}{flipped}{signature[-1]}"


class GatewayClient:
    """Requests to the gateway's in-network base, with the suite's client."""

    def __init__(self, config: LiveTestConfig) -> None:
        assert config.ai_base_url is not None
        self.config = config
        self.base = config.ai_base_url

        self.host_header: dict[str, str] = {}

    def replica(self, address: str) -> GatewayClient:
        """Return a client bound to one replica's ``address``.

        The replica is reached on the configured base's port and path, with
        the configured host name in ``Host`` so its ``ALLOWED_HOSTS`` accepts
        the request.
        """
        parts = urlsplit(self.base)
        client = GatewayClient(self.config)
        port = f":{parts.port}" if parts.port else ""
        client.base = f"{parts.scheme}://{address}{port}{parts.path}"
        client.host_header = {"Host": f"{parts.hostname}{port}"}
        return client

    def url(self, path: str) -> str:
        """Return the absolute URL of ``path`` under the gateway base."""
        return f"{self.base}/{path.lstrip('/')}"

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        """GET ``path`` on the gateway."""
        timeout = kwargs.pop("timeout", self.config.timeout)
        kwargs["headers"] = {**self.host_header, **kwargs.get("headers", {})}
        return requests.get(self.url(path), timeout=timeout, **kwargs)

    def execute(
        self,
        capability: str,
        body: dict[str, Any],
        context: str | None,
        *,
        headers: dict[str, str] | None = None,
        client: bool = True,
        timeout: float | None = None,
    ) -> requests.Response:
        """POST one execution request; ``context=None`` sends no context."""
        sent = {**self.host_header}
        if client:
            sent.update(self.config.ai_service_client_headers())
        if context is not None:
            sent[JOB_CONTEXT_HEADER] = context
        sent.update(headers or {})
        wait = timeout if timeout is not None else max(self.config.timeout, 30)
        return requests.post(
            self.url(f"v1/execute/{EXECUTE_ROUTES[capability]}"),
            json=body,
            headers=sent,
            timeout=wait,
        )

    def meta(self) -> dict[str, Any]:
        """Return the gateway's ``/meta`` document."""
        response = self.get("meta")
        response.raise_for_status()
        return dict(response.json())

    def audience(self) -> str:
        """Return this installation's job-context ``aud``."""
        return f"ai-gateway/{self.meta()['gateway']['deployment_id']}"

    def metrics(self) -> str:
        """Return the metrics exposition (the scrape credential is required)."""
        response = self.get("metrics", headers=self.config.ai_metrics_headers())
        response.raise_for_status()
        return response.text


def error_code(response: requests.Response) -> str | None:
    """Return the typed ``code`` of a gateway error answer, if any."""
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict) and isinstance(body.get("code"), str):
        return str(body["code"])
    return None


class ManagementSession:
    """Management API calls under one issuer access token.

    ``relogin`` mints a replacement token when the issuer reports the current
    one revoked: a stack with single-session semantics revokes a session on
    each new login of the same account, and the suite logs the superuser in
    more than once.
    """

    def __init__(
        self,
        gateway: GatewayClient,
        token: str,
        relogin: Callable[[], str] | None = None,
    ) -> None:
        self.gateway = gateway
        self.headers = {"Authorization": f"Bearer {token}"}
        self._relogin = relogin

    def _revoked(self, response: requests.Response) -> bool:
        return (
            self._relogin is not None
            and response.status_code in (401, 403)
            and "revoked" in response.text.lower()
        )

    def request(self, method: str, path: str, json: Any = None) -> requests.Response:
        """Send one management request, waiting out the credential-write throttle."""
        for _ in range(_WRITE_RETRIES):
            response = requests.request(
                method,
                self.gateway.url(f"v1/{path.lstrip('/')}"),
                json=json,
                headers=self.headers,
                timeout=self.gateway.config.timeout,
            )
            if self._revoked(response):
                assert self._relogin is not None
                self.headers = {"Authorization": f"Bearer {self._relogin()}"}
                continue
            if response.status_code != 429:
                return response
            time.sleep(int(response.headers.get("Retry-After") or 5) + 1)
        return response

    def create(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST ``body`` and return the created row, failing loudly otherwise."""
        response = self.request("POST", path, body)
        assert response.status_code in (200, 201), (
            f"setup: POST {path} answered {response.status_code}: {response.text[:300]}"
        )
        return dict(response.json())


class IssuerUsers:
    """Throwaway issuer accounts, removed at teardown."""

    def __init__(self, config: LiveTestConfig, operator: StackOperator | None) -> None:
        self.config = config
        self.operator = operator
        self._admin_token: str | None = None
        self._created: list[str] = []

    def login(self, email: str, password: str) -> str:
        """Return a fresh access token for ``email``."""
        response = requests.post(
            f"{self.config.auth_base_url}/login/access-token",
            data={"username": email, "password": password},
            timeout=self.config.timeout,
        )
        assert response.status_code == 200, (
            f"setup: login failed ({response.status_code})"
        )
        return str(response.json()["access_token"])

    def superuser_token(self) -> str:
        """Return a fresh superuser access token."""
        return self.login(self.config.admin_email, self.config.admin_password)

    def create(self, role: str, tenant_id: str | None = None) -> dict[str, str]:
        """Create a user at ``role``, optionally in ``tenant_id``; return its login."""
        token = self.superuser_token()
        email = f"redteam_ai_{short_id()}@redteam-test.com"
        password = f"Rt!{secrets.token_urlsafe(12)}9a"
        response = requests.post(
            f"{self.config.auth_base_url}/users/new_user/",
            json={"email": email, "password": password, "role": role},
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.config.timeout,
        )
        assert response.status_code == 200, (
            f"setup: user create failed: {response.text[:200]}"
        )
        user_id = str(response.json()["id"])
        self._created.append(user_id)
        if tenant_id is not None:
            if self.operator is None:
                pytest.skip(
                    "tenant membership is provisioned out of band; set "
                    "LIVE_TEST_AI_COMPOSE_PROJECT so the suite can set it"
                )
            statement = (
                f"UPDATE auth_user SET tenant_id = '{sql_value(tenant_id)}' "  # nosec B608 - sql_value
                f"WHERE id = '{sql_value(user_id)}'"
            )
            self.operator.psql(self.config.ai_auth_db_name, statement)
        return {
            "id": user_id,
            "email": email,
            "token": self.login(email, password),
            "tenant_id": tenant_id or "",
        }

    def cleanup(self) -> None:
        """Delete every account this helper created (best effort)."""
        if not self._created:
            return
        try:
            token = self.superuser_token()
        except (AssertionError, requests.RequestException):
            return
        for user_id in self._created:
            try:
                requests.delete(
                    f"{self.config.auth_base_url}/users/delete/{user_id}/",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self.config.timeout,
                )
            except requests.RequestException:
                pass


class StubControl:
    """The stub provider's control API (``/__stub/``)."""

    def __init__(self, config: LiveTestConfig) -> None:
        assert config.ai_stub_base_url is not None
        self.config = config
        self.base = f"{config.ai_stub_base_url}/__stub"
        self.headers = config.ai_stub_control_headers()

    def _call(self, method: str, action: str, json: Any = None) -> dict[str, Any]:
        response = requests.request(
            method,
            f"{self.base}/{action}",
            json=json,
            headers=self.headers,
            timeout=self.config.timeout,
        )
        response.raise_for_status()
        return dict(response.json())

    def state(self) -> dict[str, Any]:
        """Return the stub's configuration and recorded requests."""
        return self._call("GET", "state")

    def configure(self, **changes: Any) -> dict[str, Any]:
        """Merge ``changes`` into the stub configuration."""
        return self._call("POST", "config", changes)

    def allow(self, *keys: str) -> None:
        """Add ``keys`` to the accepted bearer keys."""
        current = list(self.state()["config"]["keys"])
        self.configure(keys=current + [key for key in keys if key not in current])

    def mark(self) -> int:
        """Return the number of requests recorded so far."""
        return len(self.state()["requests"])

    def since(self, mark: int) -> list[dict[str, Any]]:
        """Return the requests recorded after ``mark``."""
        return list(self.state()["requests"][mark:])


class StackOperator:
    """Container-level operations on the compose project under test."""

    def __init__(self, config: LiveTestConfig) -> None:
        assert config.ai_compose_project is not None
        self.config = config
        self.engine = config.container_engine
        self.project = config.ai_compose_project

    def _run(
        self, argv: Sequence[str], *, check: bool = True, timeout: float = 120
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(  # nosec B603 - argv list, configured engine
            [self.engine, *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode != 0:
            raise AssertionError(
                f"stack operation {argv[0]} failed ({result.returncode}): "
                f"{result.stderr.strip()[:300]}"
            )
        return result

    def containers(self, service: str, *, all_states: bool = False) -> list[str]:
        """Return the ids of ``service``'s containers in the project."""
        argv = [
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={self.project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
        if all_states:
            argv.insert(1, "-a")
        return self._run(argv).stdout.split()

    def container(self, service: str) -> str:
        """Return the one running container of ``service``."""
        ids = self.containers(service)
        assert ids, f"no running container for service {service!r} in {self.project}"
        return ids[0]

    def exec(
        self, service: str, argv: Sequence[str], *, timeout: float = 120
    ) -> subprocess.CompletedProcess[str]:
        """Run ``argv`` inside ``service``'s running container."""
        return self._run(["exec", self.container(service), *argv], timeout=timeout)

    def psql(
        self, database: str, sql: str, *, user: str = "postgres", check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run one SQL statement through the stack's database container."""
        return self._run(
            [
                "exec",
                self.container(self.config.ai_db_service),
                "psql",
                "-U",
                user,
                "-d",
                database,
                "-v",
                "ON_ERROR_STOP=1",
                "-tAc",
                sql,
            ],
            check=check,
        )

    def query(self, sql: str) -> list[list[str]]:
        """Return the rows of a query on the gateway database (``|``-split)."""
        output = self.psql(self.config.ai_db_name, sql).stdout
        return [line.split("|") for line in output.splitlines() if line]

    def pg_dump(self, database: str) -> str:
        """Return a plain-text dump of ``database``."""
        return self.exec(
            self.config.ai_db_service,
            ["pg_dump", "-U", "postgres", database],
            timeout=300,
        ).stdout

    def logs(self, service: str) -> str:
        """Return every log line of ``service``'s containers (stdout and stderr)."""
        text = []
        for container in self.containers(service, all_states=True):
            result = self._run(["logs", container], check=False)
            text.append(result.stdout + result.stderr)
        return "\n".join(text)

    def lifecycle(self, action: str, service: str) -> None:
        """Run ``stop``, ``start``, ``restart``, ``kill``, ``pause`` or ``unpause``."""
        for container in self.containers(service, all_states=True):
            self._run([action, container])

    def inspect(self, container: str) -> dict[str, Any]:
        """Return ``docker inspect`` of one container."""
        return dict(json.loads(self._run(["inspect", container]).stdout)[0])

    def address(self, container: str, network_suffix: str) -> str:
        """Return ``container``'s address on the network named ``*network_suffix``."""
        networks = self.inspect(container)["NetworkSettings"]["Networks"]
        for name, settings in networks.items():
            if name.endswith(network_suffix):
                return str(settings["IPAddress"])
        raise AssertionError(f"{container} is not on a *{network_suffix} network")

    def run_copy(
        self,
        service: str,
        name: str,
        *,
        command: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 120,
    ) -> subprocess.CompletedProcess[str]:
        """Run a copy of ``service`` to completion (see :meth:`clone`)."""
        result = self.clone(service, name, command=command, env=env, timeout=timeout)
        assert not isinstance(result, str)
        return result

    def start_copy(self, service: str, name: str) -> str:
        """Start a detached copy of ``service``; return its id (see :meth:`clone`)."""
        result = self.clone(service, name, detach=True)
        assert isinstance(result, str)
        return result

    def clone(
        self,
        service: str,
        name: str,
        *,
        command: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        detach: bool = False,
        timeout: float = 120,
    ) -> subprocess.CompletedProcess[str] | str:
        """Run a copy of ``service``'s container.

        Same image, command, environment, mounts (its secrets included), user
        and networks; read-only and without capabilities. Returns the finished
        process, or the id of a detached copy (remove it with :meth:`remove`).

        The copy carries its own compose labels so neither Compose nor a dev
        container tool ever takes it for one of their containers.
        """
        source = self.inspect(self.containers(service, all_states=True)[0])
        config, host = source["Config"], source["HostConfig"]
        environment = dict(item.split("=", 1) for item in config["Env"] or [])
        environment.update(env or {})
        networks = list(source["NetworkSettings"]["Networks"])
        argv = [
            "create",
            "--name",
            name,
            "--label",
            "com.docker.compose.project=security-tests-m8",
            "--label",
            f"com.docker.compose.service={name}",
            "--volumes-from",
            source["Id"],
            "--user",
            config.get("User") or "1000:1000",
            "--read-only",
            "--tmpfs",
            "/tmp:size=16m,mode=1777",  # nosec B108 - the container's own tmpfs
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--network",
            networks[0],
        ]
        if host.get("Memory"):
            argv += ["--memory", str(host["Memory"])]
        for key, value in environment.items():
            argv += ["-e", f"{key}={value}"]
        if command is None:
            command = [*(config.get("Entrypoint") or []), *(config.get("Cmd") or [])]
        argv += ["--entrypoint", command[0], config["Image"], *command[1:]]
        container = self._run(argv).stdout.strip()
        for network in networks[1:]:
            self._run(["network", "connect", network, container])
        self._run(["start", container])
        if detach:
            return container
        try:
            waited = self._run(["wait", container], timeout=timeout)
            logs = self._run(["logs", container], check=False)
            return subprocess.CompletedProcess(
                waited.args,
                int(waited.stdout.strip() or 1),
                logs.stdout,
                logs.stderr,
            )
        finally:
            self.remove(container)

    def remove(self, container: str) -> None:
        """Force-remove a container this operator started."""
        self._run(["rm", "-f", container], check=False)

    def health(self, service: str) -> str:
        """Return the health status of ``service``'s first container."""
        ids = self.containers(service, all_states=True)
        assert ids, f"no container for service {service!r}"
        result = self._run(
            [
                "inspect",
                "--format",
                "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                ids[0],
            ]
        )
        return result.stdout.strip()

    def wait_healthy(self, service: str, timeout: float = 180) -> bool:
        """Wait until ``service`` reports ``running/healthy``."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.health(service) == "running/healthy":
                return True
            time.sleep(3)
        return False


def operator_or_none(config: LiveTestConfig) -> StackOperator | None:
    """Return a :class:`StackOperator` when a compose project is configured."""
    return StackOperator(config) if config.ai_compose_project else None


def wait_for(predicate: Callable[[], Any], timeout: float, interval: float = 3) -> Any:
    """Poll ``predicate`` until it is truthy or ``timeout`` seconds pass."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


def require_operator(operator: StackOperator | None) -> StackOperator:
    """Skip unless container-level access to the stack is configured."""
    if operator is None:
        pytest.skip(
            "this check needs container access to the stack: set "
            "LIVE_TEST_AI_COMPOSE_PROJECT (and LIVE_TEST_CONTAINER_ENGINE)"
        )
    return operator
