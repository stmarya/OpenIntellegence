"""Deterministic unit tests for server-side correlation evidence resolution.

All tests run without a live database or external services. The mock database
implements the minimum async interface needed by the resolution functions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.correlations import CorrelationEvaluate, _resolve_evidence, evaluate
from app.core.deps import Principal
from app.services.correlation import assess


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _RowsResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalars(self):
        return self


class _CorrelationDb:
    """Minimal async session mock routing SELECT queries to fixture data."""

    def __init__(
        self,
        *,
        asset=None,
        vulnerability=None,
        indicator=None,
        exposures=None,
        sightings=None,
    ) -> None:
        self.asset = asset
        self.vulnerability = vulnerability
        self.indicator = indicator
        self.exposures = exposures or []
        self.sightings = sightings or []
        self.added = []
        self.seen_sql: list[str] = []

    async def execute(self, stmt):  # noqa: ANN001
        sql = str(stmt)
        self.seen_sql.append(sql)
        if "FROM assets" in sql:
            return _ScalarResult(self.asset)
        if "FROM asset_exposures" in sql:
            return _RowsResult(self.exposures)
        if "FROM sightings" in sql:
            return _RowsResult(self.sightings)
        if "FROM vulnerabilities" in sql:
            return _ScalarResult(self.vulnerability)
        if "FROM indicators" in sql:
            return _ScalarResult(self.indicator)
        if "FROM correlations" in sql:
            return _ScalarResult(None)
        raise AssertionError(f"Unhandled SQL: {sql}")

    def add(self, item):  # noqa: ANN001
        self.added.append(item)

    async def flush(self):
        if self.added:
            self.added[-1].id = getattr(self.added[-1], "id", None) or "corr-1"
            if not getattr(self.added[-1], "evaluated_at", None):
                self.added[-1].evaluated_at = datetime.now(UTC)


def _principal(*, admin: bool = False) -> Principal:
    scopes = {"write", "admin"} if admin else {"write"}
    return Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset(scopes),
        rate_limit_per_hour=1000,
    )


# ---------------------------------------------------------------------------
# Asset entity type – full resolution path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlation_evidence_resolved_and_deterministic() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    db = _CorrelationDb(
        asset=SimpleNamespace(
            id="asset-1",
            tenant_id="tenant-1",
            criticality="high",
            ip_address="1.2.3.4",
        ),
        exposures=[
            (
                SimpleNamespace(id="exp-1"),
                SimpleNamespace(
                    id="vuln-1",
                    cvss_score=9.8,
                    is_kev=True,
                    exploit_maturity=SimpleNamespace(value="active"),
                ),
            )
        ],
        sightings=[
            SimpleNamespace(
                id="sig-1",
                asset_id="asset-1",
                observed_at=now,
                context={"ransomware_relevant": True},
            )
        ],
    )
    out = await evaluate(
        CorrelationEvaluate(
            title="Asset risk",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["resolution_status"] == "resolved"
    assert out.evidence["vulnerability_context"]["cvss_score"] == 9.8
    assert out.evidence["ransomware_relevance"]["is_relevant"] is True
    assert any("assets.tenant_id" in sql for sql in db.seen_sql)
    expected_score = assess(
        {
            "cvss_score": 9.8,
            "is_kev": True,
            "exploit_maturity": "active",
            "asset_criticality": "high",
            "internet_exposed": True,
            "sighting_count": 1,
            "ransomware_relevant": True,
        }
    ).score
    assert out.risk_score == expected_score


@pytest.mark.asyncio
async def test_correlation_evidence_partial_and_unknowns_preserved() -> None:
    db = _CorrelationDb(
        asset=SimpleNamespace(
            id="asset-1",
            tenant_id="tenant-1",
            criticality="medium",
            ip_address=None,
        ),
        exposures=[
            (
                SimpleNamespace(id="exp-1"),
                SimpleNamespace(
                    id="vuln-1",
                    cvss_score=None,
                    is_kev=False,
                    exploit_maturity=SimpleNamespace(value="unknown"),
                ),
            )
        ],
        sightings=[],
    )
    out = await evaluate(
        CorrelationEvaluate(
            title="Asset risk",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["resolution_status"] == "partial"
    assert out.evidence["vulnerability_context"]["cvss_score"] is None
    assert out.evidence["asset_context"]["internet_exposed"] is None
    cvss_factor = [f for f in out.factor_breakdown if f["key"] == "cvss"][0]
    assert cvss_factor["state"] == "unknown"


@pytest.mark.asyncio
async def test_correlation_evidence_unavailable_without_supporting_records() -> None:
    out = await evaluate(
        CorrelationEvaluate(
            title="No support",
            primary_entity_type="asset",
            primary_entity_id="missing",
        ),
        db=_CorrelationDb(),  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["resolution_status"] == "unavailable"
    assert out.evidence["ioc_sightings"]["count"] is None


# ---------------------------------------------------------------------------
# Vulnerability entity type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vulnerability_evidence_resolved_from_vuln_record() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    db = _CorrelationDb(
        vulnerability=SimpleNamespace(
            id="vuln-1",
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
            is_kev=True,
            exploit_maturity=SimpleNamespace(value="functional"),
        ),
        exposures=[
            (
                SimpleNamespace(id="exp-1", detected_at=now),
                SimpleNamespace(
                    id="asset-1",
                    hostname="host-a",
                    criticality="critical",
                    ip_address="10.0.0.1",
                    tenant_id="tenant-1",
                ),
            )
        ],
        sightings=[],
    )
    out = await evaluate(
        CorrelationEvaluate(
            title="Vuln correlation",
            primary_entity_type="vulnerability",
            primary_entity_id="vuln-1",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["vulnerability_context"]["cvss_score"] == 8.5
    assert out.evidence["vulnerability_context"]["is_kev"] is True
    assert out.evidence["asset_context"]["criticality"] == "critical"
    # Tenant scoping must be applied for asset_exposure lookup
    assert any("assets.tenant_id" in sql or "asset_exposures" in sql for sql in db.seen_sql)


@pytest.mark.asyncio
async def test_vulnerability_evidence_unavailable_when_not_found() -> None:
    db = _CorrelationDb(vulnerability=None)
    out = await evaluate(
        CorrelationEvaluate(
            title="Unknown vuln",
            primary_entity_type="vulnerability",
            primary_entity_id="missing-vuln",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["resolution_status"] == "unavailable"


@pytest.mark.asyncio
async def test_vulnerability_unknown_cvss_preserved() -> None:
    db = _CorrelationDb(
        vulnerability=SimpleNamespace(
            id="vuln-2",
            cve_id="CVE-2024-9999",
            cvss_score=None,
            is_kev=False,
            exploit_maturity=SimpleNamespace(value="unknown"),
        ),
        exposures=[],
        sightings=[],
    )
    out = await evaluate(
        CorrelationEvaluate(
            title="Unscored vuln",
            primary_entity_type="vulnerability",
            primary_entity_id="vuln-2",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["vulnerability_context"]["cvss_score"] is None
    assert "cvss_score" in out.evidence["vulnerability_context"]["unknown_fields"]
    cvss_factor = [f for f in out.factor_breakdown if f["key"] == "cvss"][0]
    assert cvss_factor["state"] == "unknown"


# ---------------------------------------------------------------------------
# Indicator entity type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_indicator_evidence_resolved_from_sightings() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    db = _CorrelationDb(
        indicator=SimpleNamespace(
            id="ind-1",
            indicator_type="ip",
            value="192.168.1.1",
            verdict="malicious",
            confidence=0.9,
        ),
        sightings=[
            SimpleNamespace(
                id="sight-1",
                entity_type="ip",
                entity_id="192.168.1.1",
                asset_id=None,
                observed_at=now,
                context={"ransomware_relevant": True},
            )
        ],
    )
    out = await evaluate(
        CorrelationEvaluate(
            title="Indicator correlation",
            primary_entity_type="indicator",
            primary_entity_id="ind-1",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["ioc_sightings"]["count"] == 1
    assert out.evidence["ransomware_relevance"]["is_relevant"] is True
    # Sightings lookup must be tenant-scoped
    assert any("sightings.tenant_id" in sql for sql in db.seen_sql)


@pytest.mark.asyncio
async def test_indicator_evidence_unavailable_when_not_found() -> None:
    db = _CorrelationDb(indicator=None)
    out = await evaluate(
        CorrelationEvaluate(
            title="Unknown indicator",
            primary_entity_type="indicator",
            primary_entity_id="missing-ind",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.evidence["resolution_status"] == "unavailable"


# ---------------------------------------------------------------------------
# Unsupported entity type – must return 422, not silently unavailable
# ---------------------------------------------------------------------------


def test_unsupported_entity_type_rejected_with_422() -> None:
    """primary_entity_type values outside the supported set must raise a
    Pydantic ValidationError (HTTP 422), not silently return unavailable.
    """
    with pytest.raises(ValidationError):
        CorrelationEvaluate(
            title="Bad type",
            primary_entity_type="campaign",  # not in Literal["asset","vulnerability","indicator"]
            primary_entity_id="some-id",
        )


def test_host_entity_type_also_rejected() -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate(
            title="Bad type",
            primary_entity_type="host",
            primary_entity_id="some-id",
        )


# ---------------------------------------------------------------------------
# Legacy scoring fields are rejected (extra=forbid)
# ---------------------------------------------------------------------------


def test_legacy_scoring_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate(
            title="bad payload",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
            cvss_score=9.8,  # type: ignore[call-arg]
        )


def test_legacy_is_kev_field_rejected() -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate(
            title="bad payload",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
            is_kev=True,  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# Manual annotation – privileged, separate from server-resolved facts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_annotation_requires_admin_and_stays_separate() -> None:
    payload = CorrelationEvaluate(
        title="Manual note",
        primary_entity_type="asset",
        primary_entity_id="missing",
        manual_annotation={"confidence": "analyst override"},
    )
    with pytest.raises(HTTPException) as exc:
        await evaluate(payload, db=_CorrelationDb(), principal=_principal())  # type: ignore[arg-type]
    assert exc.value.status_code == 403

    out = await evaluate(
        payload,
        db=_CorrelationDb(),  # type: ignore[arg-type]
        principal=_principal(admin=True),
    )
    assert out.evidence["resolution_status"] == "manual_input"
    assert out.evidence["server_resolution_status"] == "unavailable"
    assert out.evidence["manual_annotation"] == {"confidence": "analyst override"}


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_asset_evidence_is_tenant_scoped() -> None:
    """Asset resolution must not return data from a different tenant."""
    db = _CorrelationDb(asset=None)  # asset not found for this tenant
    evidence = await _resolve_evidence(
        CorrelationEvaluate(
            title="Tenant check",
            primary_entity_type="asset",
            primary_entity_id="asset-other-tenant",
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert evidence["resolution_status"] == "unavailable"
    # The SQL must contain tenant_id filter
    assert any("assets.tenant_id" in sql for sql in db.seen_sql)
