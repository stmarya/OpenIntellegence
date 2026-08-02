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
)

# Scoring factors that must NOT appear in the CorrelationEvaluate request body.
# The backend resolves these server-side; clients must not supply them.
_FORBIDDEN_EVALUATE_FIELDS = frozenset(
    {
        "cvss_score",
        "is_kev",
        "exploit_maturity",
        "asset_criticality",
        "internet_exposed",
        "sighting_count",
        "ransomware_relevant",
        "source_refs",
    }
)

# Identity fields that must be present in the evaluate request body.
_REQUIRED_EVALUATE_FIELDS = frozenset(
    {"title", "primary_entity_type", "primary_entity_id", "notes"}
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


def test_correlation_evaluate_contract_no_client_scoring_factors() -> None:
    """Evaluate endpoint must not expose client-supplied scoring factors.

    Risk evidence is resolved server-side from platform records.
    Clients supply only entity identity and optional analyst notes.
    """
    schema = create_app().openapi()
    components = schema.get("components", {}).get("schemas", {})
    evaluate_schema = components.get("CorrelationEvaluate", {})
    props = set(evaluate_schema.get("properties", {}).keys())

    for field in _FORBIDDEN_EVALUATE_FIELDS:
        assert field not in props, (
            f"Client-supplied scoring factor '{field}' must not be in the "
            "CorrelationEvaluate request body — the backend resolves it."
        )


def test_correlation_evaluate_contract_has_identity_fields() -> None:
    """Evaluate endpoint must include entity identity and notes fields."""
    schema = create_app().openapi()
    components = schema.get("components", {}).get("schemas", {})
    evaluate_schema = components.get("CorrelationEvaluate", {})
    props = set(evaluate_schema.get("properties", {}).keys())

    for field in _REQUIRED_EVALUATE_FIELDS:
        assert field in props, (
            f"Identity field '{field}' must be present in CorrelationEvaluate."
        )


def test_correlation_out_has_resolution_status() -> None:
    """Correlation response must include resolution_status for explainability."""
    schema = create_app().openapi()
    components = schema.get("components", {}).get("schemas", {})
    out_schema = components.get("CorrelationOut", {})
    props = set(out_schema.get("properties", {}).keys())
    assert "resolution_status" in props, (
        "CorrelationOut must expose resolution_status "
        "('resolved' | 'partial' | 'manual_input' | 'unavailable')."
    )


def test_correlation_evaluate_accepts_manual_evidence_field() -> None:
    """Evaluate contract must expose the optional manual_evidence override field."""
    schema = create_app().openapi()
    components = schema.get("components", {}).get("schemas", {})
    evaluate_schema = components.get("CorrelationEvaluate", {})
    props = set(evaluate_schema.get("properties", {}).keys())
    assert "manual_evidence" in props, (
        "CorrelationEvaluate must expose manual_evidence for privileged override."
    )
