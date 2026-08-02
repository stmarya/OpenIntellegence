from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.correlations import CorrelationEvaluate, evaluate
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
    def __init__(self, *, asset=None, exposures=None, sightings=None) -> None:
        self.asset = asset
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
        if "FROM correlations" in sql:
            return _ScalarResult(None)
        raise AssertionError(f"Unhandled SQL: {sql}")

    def add(self, item):  # noqa: ANN001
        self.added.append(item)

    async def flush(self):
        if self.added:
            self.added[-1].id = self.added[-1].id or "corr-1"
            self.added[-1].evaluated_at = self.added[-1].evaluated_at or datetime.now(UTC)


def _principal(*, admin: bool = False) -> Principal:
    scopes = {"write", "admin"} if admin else {"write"}
    return Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset(scopes),
        rate_limit_per_hour=1000,
    )


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
    assert out.risk_score == assess(
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
    cvss = [f for f in out.factor_breakdown if f["key"] == "cvss"][0]
    assert cvss["state"] == "unknown"


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


def test_legacy_scoring_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate(
            title="bad payload",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
            cvss_score=9.8,  # legacy input must fail
        )
