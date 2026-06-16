"""Reusable live security suite classes."""

from security_tests_m8.suites.algorithms import (
    AsymmetricJWTSuite,
    CrossServiceTokenSuite,
    HS256Suite,
    HS256WeakKeySuite,
    JWKSSuite,
)
from security_tests_m8.suites.deployment import DeploymentPreflightSuite
from security_tests_m8.suites.service import (
    ConfiguredProtectedEndpointsSuite,
    ConfiguredServiceInfoDisclosureSuite,
    ProtectedEndpointSuite,
    ServiceInfoDisclosureSuite,
)
from security_tests_m8.suites.token_modes import (
    HybridContractSuite,
    StatefulAccessRevocationSuite,
    StatefulRevocationSuite,
    StatelessContractSuite,
)
from security_tests_m8.suites.universal import (
    ApiKeySuite,
    AuthAttackSuite,
    AuthorizationSuite,
    AvatarUrlSuite,
    CookieSecuritySuite,
    CORSSuite,
    HealthAPISuite,
    InfoDisclosureSuite,
    JWTStructuralSuite,
    MetricsAPISuite,
    PrivateAPISuite,
    RateLimitingSuite,
    SecurityHeadersSuite,
)

__all__ = [
    "ApiKeySuite",
    "AsymmetricJWTSuite",
    "AuthAttackSuite",
    "AuthorizationSuite",
    "AvatarUrlSuite",
    "CookieSecuritySuite",
    "CORSSuite",
    "CrossServiceTokenSuite",
    "DeploymentPreflightSuite",
    "HealthAPISuite",
    "HS256Suite",
    "HS256WeakKeySuite",
    "HybridContractSuite",
    "InfoDisclosureSuite",
    "JWKSSuite",
    "JWTStructuralSuite",
    "MetricsAPISuite",
    "PrivateAPISuite",
    "ProtectedEndpointSuite",
    "ConfiguredProtectedEndpointsSuite",
    "ConfiguredServiceInfoDisclosureSuite",
    "RateLimitingSuite",
    "SecurityHeadersSuite",
    "ServiceInfoDisclosureSuite",
    "StatefulAccessRevocationSuite",
    "StatefulRevocationSuite",
    "StatelessContractSuite",
]
