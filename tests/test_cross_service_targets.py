"""Regression checks for configuration-driven cross-service probe targets.

Category I (``CrossServiceTokenSuite``) used to probe one hardcoded route,
``{LIVE_TEST_SVC_BASE}/category/``. Any consumer that does not publish that
route answered ``404 {"detail": "Not Found"}`` — an *application* 404, which the
availability guard correctly refuses to treat as "target unreachable". The
rejection assertions therefore reported a missing route as a CRITICAL
authentication bypass, and the acceptance assertion failed on a healthy stack.

These tests pin the fix: probe routes come from live-test configuration only,
one per configured consumer service, and a service with no declared route is
skipped rather than probed on a guessed path.
"""

from __future__ import annotations

import pytest

from security_tests_m8 import configure


def _params() -> list:
    from security_tests_m8.suites import algorithms

    return algorithms._cross_service_params()


def _ids(params: list) -> list[str]:
    return [param.id for param in params]


def _values(params: list) -> list[tuple[object, ...]]:
    return [tuple(param.values) for param in params]


def test_targets_cover_every_configured_service_with_its_own_route() -> None:
    configure(
        service_base_url="http://gw/reparto",
        service_base_urls={
            "reparto": "http://gw/reparto",
            "media": "http://gw/media",
            "prompt": "http://gw/prompt",
        },
        default_service="reparto",
        protected_endpoints={
            "reparto": ["/schools/", "/departments/"],
            "media": ["/category/"],
            "prompt": ["/prompt-template/"],
        },
        cross_service_endpoints={},
    )

    params = _params()

    assert _ids(params) == ["reparto", "media", "prompt"]
    assert _values(params) == [
        ("reparto", "http://gw/reparto/schools/"),
        ("media", "http://gw/media/category/"),
        ("prompt", "http://gw/prompt/prompt-template/"),
    ]


def test_no_hardcoded_category_route_for_a_consumer_without_one() -> None:
    """A consumer with no /category/ route must never be probed on one."""
    configure(
        service_base_url="http://gw/reparto",
        service_base_urls={"reparto": "http://gw/reparto"},
        default_service="reparto",
        protected_endpoints={"reparto": ["/academic-years/"]},
        cross_service_endpoints={},
    )

    urls = [str(values[1]) for values in _values(_params())]

    assert urls == ["http://gw/reparto/academic-years/"]
    assert not any("/category/" in url for url in urls)


def test_explicit_override_pins_the_probe_route() -> None:
    configure(
        service_base_url="http://gw/reparto",
        service_base_urls={"reparto": "http://gw/reparto"},
        default_service="reparto",
        protected_endpoints={"reparto": ["/academic-years/"]},
        cross_service_endpoints={"reparto": "/teacher-profiles/"},
    )

    assert _values(_params()) == [("reparto", "http://gw/reparto/teacher-profiles/")]


def test_single_service_base_without_named_services_is_supported() -> None:
    configure(
        service_base_url="http://gw/svc",
        service_base_urls={},
        default_service=None,
        protected_endpoints={"default": ["/objects/"]},
        cross_service_endpoints={},
    )

    assert _values(_params()) == [("default", "http://gw/svc/objects/")]


def test_unconfigured_target_yields_an_explicit_skip_not_a_guessed_route() -> None:
    configure(
        service_base_url="http://gw/svc",
        service_base_urls={},
        default_service=None,
        protected_endpoints={},
        cross_service_endpoints={},
    )

    params = _params()

    assert _ids(params) == ["unconfigured"]
    marks = [mark for param in params for mark in param.marks]
    assert [mark.name for mark in marks] == ["skip"]
    assert "LIVE_TEST_PROTECTED_ENDPOINTS" in marks[0].kwargs["reason"]


def test_rejection_statuses_accept_401_and_403() -> None:
    """Consumers may answer 401 or 403; both are a refusal, 404 is not."""
    from security_tests_m8.suites import algorithms

    assert algorithms._REJECTED == (401, 403)
    assert 404 not in algorithms._REJECTED


@pytest.mark.parametrize(
    "method_name",
    [
        "test_i01_valid_auth_token_accepted_by_service",
        "test_i02_forged_token_rejected_by_service",
        "test_i03_alg_none_rejected_by_service",
        "test_i04_service_rejects_no_token",
        "test_i05_attacker_generated_key_rejected_by_service",
    ],
)
def test_every_cross_service_check_is_parametrized_by_service(
    method_name: str,
) -> None:
    from security_tests_m8.suites import algorithms

    method = getattr(algorithms.CrossServiceTokenSuite, method_name)
    marks = [mark for mark in method.pytestmark if mark.name == "parametrize"]

    assert marks, f"{method_name} is not parametrized over configured services"
    assert marks[0].args[0] == ("service", "url")
