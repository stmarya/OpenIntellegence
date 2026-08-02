"""API surface contract checks for the unified /api/v1 router."""

from __future__ import annotations

from app.main import create_app

EXPECTED_PATHS = {
    "/api/v1/vulnerabilities",
    "/api/v1/assets",
    "/api/v1/agents",
    "/api/v1/api-keys",
    "/api/v1/chat/query",
    "/api/v1/reports",
    "/api/v1/search",
    "/api/v1/actors/{canonical_name}",
    "/api/v1/campaigns",
    "/api/v1/investigations",
    "/api/v1/alert-rules",
    "/api/v1/correlations",
    "/api/v1/playbooks",
}

EXPECTED_FAMILIES = (
    "/api/v1/vulnerabilities",
    "/api/v1/ingest",
    "/api/v1/assets",
    "/api/v1/agents",
    "/api/v1/reports",
    "/api/v1/search",
    "/api/v1/actors",
    "/api/v1/campaigns",
    "/api/v1/investigations",
    "/api/v1/alert",
    "/api/v1/correlations",
    "/api/v1/playbooks",
    "/api/v1/automation-runs",
    "/api/v1/endpoint-command-requests",
)


def test_expected_endpoints_are_registered() -> None:
    schema = create_app().openapi()
    actual_paths = set(schema["paths"].keys())
    assert EXPECTED_PATHS.issubset(actual_paths)


def test_expected_endpoint_families_are_exposed() -> None:
    schema = create_app().openapi()
    actual_paths = tuple(schema["paths"].keys())

    for family in EXPECTED_FAMILIES:
        assert any(path.startswith(family) for path in actual_paths), family
