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


def test_correlation_evidence_resolution_columns_exist() -> None:
    """resolution_status and manual_evidence must be present on correlations.

    Added in migration 0008.  resolution_status carries a server_default so
    pre-migration rows get a safe 'unavailable' value without a backfill.
    """
    cols = _table("correlations").c
    assert "resolution_status" in cols
    assert "manual_evidence" in cols


def test_correlation_resolution_status_has_server_default() -> None:
    """resolution_status must have a server_default so old rows stay valid."""
    col = _table("correlations").c["resolution_status"]
    assert col.server_default is not None, (
        "resolution_status must carry a server_default='unavailable' "
        "so rows written before migration 0008 remain valid."
    )
