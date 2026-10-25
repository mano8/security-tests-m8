"""AI gateway live security pytest suite (gateway only, no media stack).

Classes run in this order. The lifecycle rows (boot copies, a killed web
process, a second replica) follow the functional ones, and the restore row
runs last: its ratification leaves the stack's budget hold in force until the
next UTC day.
"""

# ruff: noqa: D101

from security_tests_m8.suites import (
    AiGatewayBootSuite,
    AiGatewayContextSuite,
    AiGatewayDestinationSuite,
    AiGatewayIngressSuite,
    AiGatewayPolicySuite,
    AiGatewayReplicaSuite,
    AiGatewayRestoreSuite,
    AiGatewaySecretsSuite,
    AiGatewaySettlementSuite,
    AiGatewayUserScopeSuite,
)


class TestAiGatewayIngress(AiGatewayIngressSuite):
    pass


class TestAiGatewayContexts(AiGatewayContextSuite):
    pass


class TestAiGatewayDestinations(AiGatewayDestinationSuite):
    pass


class TestAiGatewaySecrets(AiGatewaySecretsSuite):
    pass


class TestAiGatewayPolicy(AiGatewayPolicySuite):
    pass


class TestAiGatewayUserScope(AiGatewayUserScopeSuite):
    pass


class TestAiGatewayBoot(AiGatewayBootSuite):
    pass


class TestAiGatewaySettlement(AiGatewaySettlementSuite):
    pass


class TestAiGatewayReplicas(AiGatewayReplicaSuite):
    pass


class TestAiGatewayRestore(AiGatewayRestoreSuite):
    pass
