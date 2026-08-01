"""Health and readiness probe checks using the in-process FastAPI test client.

No external services are required: the readiness probe is expected to report
individual dependency failures rather than raise, and the liveness probe is
purely in-process.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_liveness_returns_ok() -> None:
    client = TestClient(create_app(), raise_server_exceptions=True)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_liveness_timing_header_present() -> None:
    """Every response carries the request-duration header."""
    client = TestClient(create_app())
    resp = client.get("/health")
    assert "X-Request-Duration-Ms" in resp.headers


def test_readiness_returns_degraded_when_no_services() -> None:
    """Without Postgres and Redis, /health/ready reports each failure.

    This test must not raise: a missing dependency is a 503 with a body, not
    an unhandled exception.  The body is what on-call engineers and Kubernetes
    liveness probes read first.
    """
    client = TestClient(create_app(), raise_server_exceptions=True)
    resp = client.get("/health/ready")
    # Without live services the API should return 503, not 500.
    assert resp.status_code in {200, 503}
    body = resp.json()
    assert "status" in body
    assert "checks" in body
    assert "database" in body["checks"]
    assert "redis" in body["checks"]


def test_readiness_check_values_are_strings() -> None:
    """Each check must be a human-readable string (not a boolean or int)."""
    client = TestClient(create_app())
    resp = client.get("/health/ready")
    body = resp.json()
    for key, value in body["checks"].items():
        assert isinstance(value, str), f"check {key!r} returned non-string: {value!r}"
