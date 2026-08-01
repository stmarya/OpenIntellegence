"""ORM contract checks for critical schema fields and constraints."""

from __future__ import annotations

from app.db.base import Base


def _table(name: str):
    return Base.metadata.tables[name]


def test_core_mismatch_fields_exist() -> None:
    assert "description" in _table("threat_actors").c
    assert "actor_id" in _table("ransomware_victims").c
    assert "enriched_at" in _table("indicators").c
    assert "stix_pattern" in _table("indicators").c
    assert "exposed_cve_count" in _table("assets").c
    assert "meta" in _table("assets").c
    assert "last_seen_at" in _table("assets").c
    assert "masked_key" in _table("api_keys").c
    assert "single_use" in _table("api_keys").c
    assert "revoked_reason" in _table("api_keys").c
    assert "requested_by" in _table("reports").c


def test_document_chunks_contract_fields_exist() -> None:
    columns = _table("document_chunks").c
    for name in ("id", "tenant_id", "title", "source", "embedding"):
        assert name in columns


def test_unique_constraints_present() -> None:
    indicator_uniques = {
        tuple(col.name for col in constraint.columns)
        for constraint in _table("indicators").constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert ("indicator_type", "value") in indicator_uniques

    alert_uniques = {
        tuple(col.name for col in constraint.columns)
        for constraint in _table("alerts").constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert ("tenant_id", "fingerprint") in alert_uniques


def test_alert_evaluation_schema_fields_exist() -> None:
    """Phase 1-3 additions: resolved evidence column on alerts."""
    assert "evidence" in _table("alerts").c


def test_correlation_factor_provenance_column_exists() -> None:
    """Phase 2 addition: factor provenance for server-resolved evidence."""
    assert "factor_provenance" in _table("correlations").c


def test_timeline_events_table_exists() -> None:
    """Phase 3 addition: cross-entity append-only audit timeline."""
    cols = _table("timeline_events").c
    for name in ("id", "tenant_id", "object_type", "object_id", "event_type", "event_at", "created_at"):
        assert name in cols, f"Column {name!r} missing from timeline_events"
