"""Full reusable live security suite for the hardened_m8 compose stack."""
# ruff: noqa: D101

from security_tests_m8.suites import (
    ApiKeySuite,
    AsymmetricJWTSuite,
    AuthAttackSuite,
    AuthorizationSuite,
    AvatarUrlSuite,
    CookieSecuritySuite,
    CORSSuite,
    CrossServiceTokenSuite,
    DeploymentPreflightSuite,
    HealthAPISuite,
    HS256Suite,
    HS256WeakKeySuite,
    HybridContractSuite,
    InfoDisclosureSuite,
    JWKSSuite,
    JWTStructuralSuite,
    MetricsAPISuite,
    PrivateAPISuite,
    ProtectedEndpointSuite,
    RateLimitingSuite,
    SecurityHeadersSuite,
    StatefulAccessRevocationSuite,
    StatefulRevocationSuite,
    StatelessContractSuite,
)


class TestAuthAttacks(AuthAttackSuite):
    pass


class TestJWTStructure(JWTStructuralSuite):
    pass


class TestAuthorization(AuthorizationSuite):
    pass


class TestRateLimiting(RateLimitingSuite):
    pass


class TestCORS(CORSSuite):
    pass


class TestPrivateAPI(PrivateAPISuite):
    pass


class TestMetrics(MetricsAPISuite):
    pass


class TestHealth(HealthAPISuite):
    pass


class TestAvatarUrls(AvatarUrlSuite):
    pass


class TestInfoDisclosure(InfoDisclosureSuite):
    pass


class TestSecurityHeaders(SecurityHeadersSuite):
    pass


class TestCookieSecurity(CookieSecuritySuite):
    pass


class TestApiKeys(ApiKeySuite):
    pass


class TestStatelessMode(StatelessContractSuite):
    pass


class TestStatefulRevocation(StatefulRevocationSuite):
    pass


class TestStatefulAccessRevocation(StatefulAccessRevocationSuite):
    pass


class TestHybridMode(HybridContractSuite):
    pass


class TestAsymmetricJWT(AsymmetricJWTSuite):
    pass


class TestJWKS(JWKSSuite):
    pass


class TestCrossServiceTokens(CrossServiceTokenSuite):
    pass


class TestDeploymentPreflight(DeploymentPreflightSuite):
    pass


class TestHS256(HS256Suite):
    pass


class TestHS256WeakKeys(HS256WeakKeySuite):
    pass


class TestFastAPICategoryEndpoint(ProtectedEndpointSuite):
    service = "fastapi"
    endpoint = "/category/"


class TestFastAPIDashboardEndpoint(ProtectedEndpointSuite):
    service = "fastapi"
    endpoint = "/dashboard/users/activity/"
