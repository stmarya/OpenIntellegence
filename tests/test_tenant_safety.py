"""Tenant isolation contract tests.

Verify that the API enforces tenant boundaries without a live database.
These tests exercise the routing and auth-wiring layers; they never make
real DB calls.

Design principle: every list and detail endpoint must scope its query to
``principal.tenant_id``.  A test that bypasses auth is not a tenant test —
it proves nothing about the boundary.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.deps import Principal, Scope
from app.main import create_app


def _make_principal(tenant_id: str) -> Principal:
    return Principal(
        api_key_id="test-key-id",
        tenant_id=tenant_id,
        name="Test Key",
        scopes=frozenset({Scope.READ, Scope.WRITE}),
        rate_limit_per_hour=10000,
    )


class TestMissingAuthentication:
    """Unauthenticated requests must always be rejected."""

    def setup_method(self) -> None:
        self.client = TestClient(create_app(), raise_server_exceptions=True)

    def test_no_credentials_rejected(self) -> None:
        resp = self.client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 401

    def test_malformed_bearer_rejected(self) -> None:
        resp = self.client.get(
            "/api/v1/vulnerabilities", headers={"Authorization": "******"}
        )
        assert resp.status_code == 401

    def test_malformed_api_key_header_rejected(self) -> None:
        resp = self.client.get(
            "/api/v1/vulnerabilities", headers={"X-API-Key": "garbage"}
        )
        assert resp.status_code == 401


class TestProtectedEndpoints:
    """All data endpoints must require authentication."""

    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/api/v1/vulnerabilities"),
            ("GET", "/api/v1/assets"),
            ("GET", "/api/v1/alert-rules"),
            ("GET", "/api/v1/alerts"),
            ("GET", "/api/v1/correlations"),
            ("GET", "/api/v1/investigations"),
            ("GET", "/api/v1/playbooks"),
            ("GET", "/api/v1/campaigns"),
            ("GET", "/api/v1/reports"),
            ("POST", "/api/v1/correlations/evaluate"),
        ],
    )
    def test_endpoint_requires_auth(self, method: str, path: str) -> None:
        resp = self.client.request(method, path)
        assert resp.status_code == 401, (
            f"{method} {path} should return 401 but got {resp.status_code}"
        )


class TestScopeEnforcement:
    """Insufficient-scope responses must be 403.

    FastAPI's dependency_overrides mechanism is used to inject a deterministic
    principal without touching the database, so these tests have no
    external-service dependencies.
    """

    def test_read_scope_required_for_vuln_list(self) -> None:
        """A principal with no scopes must get 403, not 200 or 401."""
        app = create_app()

        no_scope_principal = Principal(
            api_key_id="test-key-id",
            tenant_id="tenant-beta",
            name="No Scope Key",
            scopes=frozenset(),
            rate_limit_per_hour=10000,
        )

        from app.core.deps import get_principal

        app.dependency_overrides[get_principal] = lambda: no_scope_principal
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/vulnerabilities")
        app.dependency_overrides.clear()

        assert resp.status_code == 403, (
            f"Expected 403 for missing read scope, got {resp.status_code}"
        )

    def test_write_scope_required_for_correlation_evaluate(self) -> None:
        """A read-only principal cannot create correlations."""
        app = create_app()

        read_only = Principal(
            api_key_id="test-key-id",
            tenant_id="tenant-gamma",
            name="Read Only",
            scopes=frozenset({Scope.READ}),
            rate_limit_per_hour=10000,
        )

        from app.core.deps import get_principal

        app.dependency_overrides[get_principal] = lambda: read_only
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/correlations/evaluate", json={})
        app.dependency_overrides.clear()

        assert resp.status_code == 403, (
            f"Expected 403 for missing write scope, got {resp.status_code}"
        )


class TestTenantIdInjected:
    """Verify that route functions propagate the principal's tenant_id."""

    def test_correlation_route_scopes_tenant(self) -> None:
        """Inspect source code to confirm tenant_id filter is present.

        This guards against a developer removing the WHERE clause during a
        refactor without the test suite catching it at query time.
        """
        import inspect

        from app.api.v1 import correlations

        source = inspect.getsource(correlations)
        # The route must filter by principal.tenant_id
        assert "principal.tenant_id" in source

    def test_alerting_route_scopes_tenant(self) -> None:
        import inspect

        from app.api.v1 import alerting

        source = inspect.getsource(alerting)
        assert "principal.tenant_id" in source

    def test_assets_route_scopes_tenant(self) -> None:
        import inspect

        from app.api.v1 import assets

        source = inspect.getsource(assets)
        assert "principal.tenant_id" in source

    def test_orchestration_route_scopes_tenant(self) -> None:
        import inspect

        from app.api.v1 import orchestration

        source = inspect.getsource(orchestration)
        assert "principal.tenant_id" in source
