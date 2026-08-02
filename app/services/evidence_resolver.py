"""Tenant-safe, bounded evidence resolution for correlation evaluation."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.alert_models import Sighting
from app.db.models import Asset, AssetExposure, Indicator, Vulnerability

SUPPORTED_ENTITY_TYPES = frozenset({"asset", "vulnerability", "indicator"})
MAX_EVIDENCE_ROWS = 100


def empty_evidence(entity_type: str, entity_id: str, analyst_notes: str | None = None) -> dict:
    """Create an explicit unknown/unavailable evidence envelope."""
    return {
        "entity": {"type": entity_type, "id": entity_id},
        "analyst_notes": analyst_notes,
        "resolution_status": "unavailable",
        "vulnerability_context": {"available": False, "cvss_score": None, "is_kev": None, "exploit_maturity": None, "unknown_fields": []},
        "asset_context": {"available": False, "asset_id": None, "criticality": None, "internet_exposed": None, "unknown_fields": []},
        "asset_exposure": {"available": False, "active_exposure_count": None, "truncated": False, "unknown_fields": []},
        "ioc_sightings": {"available": False, "count": None, "truncated": False, "unknown_fields": []},
        "ransomware_relevance": {"available": False, "is_relevant": None, "unknown_fields": []},
        "provenance_references": [],
    }


def _status(evidence: dict) -> str:
    sections = ("vulnerability_context", "asset_context", "asset_exposure", "ioc_sightings", "ransomware_relevance")
    available = [evidence[name] for name in sections if evidence[name]["available"]]
    if not available:
        return "unavailable"
    return "partial" if any(section["unknown_fields"] for section in available) else "resolved"


async def _attach_sightings(
    evidence: dict, session: AsyncSession, tenant_id: str, *, asset_id: str | None = None, entity_type: str | None = None, entity_id: str | None = None
) -> None:
    stmt = select(Sighting).where(Sighting.tenant_id == tenant_id)
    if asset_id is not None:
        stmt = stmt.where(Sighting.asset_id == asset_id)
    elif entity_type is not None and entity_id is not None:
        stmt = stmt.where(Sighting.entity_type == entity_type, Sighting.entity_id == entity_id)
    else:
        return
    rows = (await session.execute(stmt.order_by(Sighting.observed_at.desc()).limit(MAX_EVIDENCE_ROWS + 1))).scalars().all()
    truncated = len(rows) > MAX_EVIDENCE_ROWS
    rows = rows[:MAX_EVIDENCE_ROWS]
    if not rows:
        return
    relevance = [row.context.get("ransomware_relevant") for row in rows if isinstance(row.context, dict) and "ransomware_relevant" in row.context]
    evidence["ioc_sightings"] = {"available": True, "count": len(rows), "truncated": truncated, "unknown_fields": []}
    evidence["ransomware_relevance"] = {
        "available": True,
        "is_relevant": True if any(value is True for value in relevance) else False if relevance else None,
        "unknown_fields": [] if relevance else ["is_relevant"],
    }
    evidence["provenance_references"].append({"kind": "tenant_sighting", "count": len(rows), "truncated": truncated})


async def resolve_evidence(
    session: AsyncSession, *, tenant_id: str, entity_type: str, entity_id: str, analyst_notes: str | None = None
) -> dict:
    """Resolve only persisted, authorized facts; never query SourceRun data.

    Every tenant-owned lookup is filtered by ``tenant_id``. Result sets are
    bounded and expose a truncation marker instead of silently dropping rows.
    """
    evidence = empty_evidence(entity_type, entity_id, analyst_notes)
    if entity_type not in SUPPORTED_ENTITY_TYPES:
        raise ValueError(f"Unsupported correlation entity type: {entity_type}")

    if entity_type == "asset":
        asset = (await session.execute(select(Asset).where(Asset.id == entity_id, Asset.tenant_id == tenant_id))).scalar_one_or_none()
        if asset is None:
            return evidence
        evidence["asset_context"] = {
            "available": True, "asset_id": asset.id, "criticality": asset.criticality,
            "internet_exposed": None, "unknown_fields": ["internet_exposed"],
        }
        rows = (await session.execute(
            select(AssetExposure, Vulnerability).join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(AssetExposure.asset_id == asset.id, AssetExposure.resolved_at.is_(None))
            .order_by(AssetExposure.detected_at.desc()).limit(MAX_EVIDENCE_ROWS + 1)
        )).all()
        truncated = len(rows) > MAX_EVIDENCE_ROWS
        rows = rows[:MAX_EVIDENCE_ROWS]
        if rows:
            vulnerabilities = [row[1] for row in rows]
            cvss = [item.cvss_score for item in vulnerabilities if item.cvss_score is not None]
            maturity = [item.exploit_maturity.value for item in vulnerabilities if item.exploit_maturity is not None]
            evidence["asset_exposure"] = {"available": True, "active_exposure_count": len(rows), "truncated": truncated, "unknown_fields": []}
            evidence["vulnerability_context"] = {
                "available": True, "cvss_score": max(cvss) if cvss else None,
                "is_kev": any(item.is_kev for item in vulnerabilities),
                "exploit_maturity": maturity[0] if maturity else None,
                "unknown_fields": (["cvss_score"] if not cvss else []) + (["exploit_maturity"] if not maturity else []),
            }
        await _attach_sightings(evidence, session, tenant_id, asset_id=asset.id)

    elif entity_type == "vulnerability":
        vulnerability = (await session.execute(select(Vulnerability).where(Vulnerability.id == entity_id))).scalar_one_or_none()
        if vulnerability is None:
            return evidence
        evidence["vulnerability_context"] = {
            "available": True, "cvss_score": vulnerability.cvss_score, "is_kev": vulnerability.is_kev,
            "exploit_maturity": vulnerability.exploit_maturity.value if vulnerability.exploit_maturity else None,
            "unknown_fields": (["cvss_score"] if vulnerability.cvss_score is None else []) + (["exploit_maturity"] if vulnerability.exploit_maturity is None else []),
        }
        rows = (await session.execute(
            select(AssetExposure, Asset).join(Asset, Asset.id == AssetExposure.asset_id)
            .where(AssetExposure.vulnerability_id == vulnerability.id, AssetExposure.resolved_at.is_(None), Asset.tenant_id == tenant_id)
            .order_by(AssetExposure.detected_at.desc()).limit(MAX_EVIDENCE_ROWS + 1)
        )).all()
        truncated = len(rows) > MAX_EVIDENCE_ROWS
        rows = rows[:MAX_EVIDENCE_ROWS]
        if rows:
            asset = rows[0][1]
            evidence["asset_exposure"] = {"available": True, "active_exposure_count": len(rows), "truncated": truncated, "unknown_fields": []}
            evidence["asset_context"] = {"available": True, "asset_id": asset.id, "criticality": asset.criticality, "internet_exposed": None, "unknown_fields": ["internet_exposed"]}

    else:
        indicator = (await session.execute(select(Indicator).where(Indicator.id == entity_id))).scalar_one_or_none()
        if indicator is None:
            return evidence
        await _attach_sightings(evidence, session, tenant_id, entity_type=indicator.indicator_type, entity_id=indicator.value)

    evidence["resolution_status"] = _status(evidence)
    return evidence
