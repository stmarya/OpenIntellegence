"""Executable contract for every public OpenIntelligence API route.

This test deliberately verifies the public catalog rather than only imports.
A module can import cleanly while a router was accidentally left out of the
aggregator, which would turn a documented endpoint into a production 404.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


# Keep this list user-facing: every item is a route the frontend, an endpoint
# agent, or an external integration is allowed to depend on.
EXPECTED_PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/health/ready"),
    ("GET", "/api/v1/vulnerabilities"),
    ("GET", "/api/v1/vulnerabilities/{cve_id}"),
    ("GET", "/api/v1/ransomware/victims"),
    ("GET", "/api/v1/actors"),
    ("GET", "/api/v1/iocs"),
    ("GET", "/api/v1/stats/summary"),
    ("GET", "/api/v1/assets"),
    ("GET", "/api/v1/assets/{asset_id}/exposure"),
    ("GET", "/api/v1/agents"),
    ("POST", "/api/v1/agents/enroll"),
    ("POST", "/api/v1/agents/heartbeat"),
    ("GET", "/api/v1/agents/{agent_id}/software"),
    ("GET", "/api/v1/api-keys"),
    ("POST", "/api/v1/api-keys"),
    ("DELETE", "/api/v1/api-keys/{key_id}"),
    ("GET", "/api/v1/feeds"),
    ("GET", "/api/v1/quarantine"),
    ("POST", "/api/v1/ingest/{source}/run"),
    ("GET", "/api/v1/runs"),
    ("POST", "/api/v1/chat/query"),
    ("GET", "/api/v1/reports/templates"),
    ("POST", "/api/v1/reports/generate"),
    ("GET", "/api/v1/reports"),
    ("GET", "/api/v1/reports/{report_id}"),
}


def test_every_public_endpoint_is_present_in_openapi() -> None:
    app = create_app()
    schema = app.openapi()
    actual = {
        (method.upper(), path)
        for path, operations in schema["paths"].items()
        for method in operations
        if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    }

    missing = EXPECTED_PUBLIC_ROUTES - actual
    unexpected = actual - EXPECTED_PUBLIC_ROUTES
    assert not missing, f"Public endpoint missing from OpenAPI: {sorted(missing)}"
    assert not unexpected, f"Undeclared public endpoint: {sorted(unexpected)}"


def test_liveness_endpoint_executes_with_real_application_lifespan() -> None:
    """Exercise startup, middleware, route registration, and shutdown.

    Redis is intentionally absent in this test. Development mode must select
    the in-memory limiter, while production would correctly refuse to start
    without a rate-limiting backend.
    """
    with TestClient(create_app()) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}
    assert float(response.headers["X-Request-Duration-Ms"]) >= 0
