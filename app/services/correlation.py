"""Deterministic correlation with server-resolved evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Asset,
    AssetExposure,
    CorrelationRecord,
    Indicator,
    RansomwareVictim,
    Vulnerability,
)


@dataclass(slots=True)
class CorrelationScoreResult:
    score: int
    evidence: dict[str, Any]


class CorrelationScoringService:
    """Deterministic score from platform-owned facts only."""

    def score(self, evidence: dict[str, Any]) -> int:
        vuln = evidence.get("vulnerability", {})
        exposure = evidence.get("tenant_exposure", {})
        ioc = evidence.get("ioc_sightings", {})
        ransom = evidence.get("ransomware_relevance", {})

        score = 0
        if vuln.get("is_kev") is True:
            score += 40
        maturity = vuln.get("exploit_maturity")
        if maturity == "weaponized":
            score += 30
        elif maturity == "functional":
            score += 20
        elif maturity == "poc":
            score += 10

        open_exposure_count = exposure.get("open_asset_exposures")
        if isinstance(open_exposure_count, int):
            score += min(open_exposure_count * 2, 20)

        ioc_count = ioc.get("count")
        if isinstance(ioc_count, int):
            score += min(ioc_count * 2, 20)

        victim_count = ransom.get("recent_victim_count")
        if isinstance(victim_count, int):
            score += min(victim_count, 20)

        return max(0, min(100, score))


async def resolve_platform_evidence(
    db: AsyncSession, tenant_id: str, primary_entity_type: str, primary_entity_id: str
) -> dict[str, Any]:
    now = datetime.now(UTC)
    evidence: dict[str, Any] = {
        "entity": {
            "type": primary_entity_type,
            "id": primary_entity_id,
        },
        "resolved_at": now.isoformat(),
        "vulnerability": {
            "source": "vulnerabilities",
            "cve_id": None,
            "cvss_score": None,
            "is_kev": None,
            "exploit_maturity": None,
        },
        "tenant_exposure": {
            "source": "asset_exposures",
            "open_asset_exposures": None,
        },
        "ioc_sightings": {
            "source": "indicators",
            "count": None,
        },
        "ransomware_relevance": {
            "source": "ransomware_victims",
            "recent_victim_count": None,
        },
    }

    vuln: Vulnerability | None = None
    if primary_entity_type == "vulnerability":
        vuln = (
            await db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == primary_entity_id.upper())
            )
        ).scalar_one_or_none()
    elif primary_entity_type == "vulnerability_id":
        vuln = await db.get(Vulnerability, int(primary_entity_id))

    if vuln is not None:
        evidence["vulnerability"] = {
            "source": "vulnerabilities",
            "id": vuln.id,
            "cve_id": vuln.cve_id,
            "cvss_score": vuln.cvss_score,
            "is_kev": vuln.is_kev,
            "exploit_maturity": vuln.exploit_maturity.value,
            "sources": vuln.sources,
        }

        open_exposure_count = await db.scalar(
            select(func.count(AssetExposure.id))
            .join(Asset, Asset.id == AssetExposure.asset_id)
            .where(
                AssetExposure.vulnerability_id == vuln.id,
                AssetExposure.resolved_at.is_(None),
                Asset.tenant_id == tenant_id,
            )
        )
        evidence["tenant_exposure"]["open_asset_exposures"] = int(open_exposure_count or 0)

        ioc_count = await db.scalar(
            select(func.count(Indicator.id)).where(
                Indicator.verdict.in_(["malicious", "suspicious"]),
            )
        )
        evidence["ioc_sightings"]["count"] = int(ioc_count or 0)

        recent_cutoff = now - timedelta(days=30)
        ransomware_count = await db.scalar(
            select(func.count(RansomwareVictim.id)).where(
                RansomwareVictim.discovered_at >= recent_cutoff
            )
        )
        evidence["ransomware_relevance"]["recent_victim_count"] = int(ransomware_count or 0)

    return evidence


def merge_resolved_and_caller_evidence(
    resolved_evidence: dict[str, Any], caller_evidence: dict[str, Any] | None
) -> dict[str, Any]:
    """Platform facts stay authoritative; caller evidence is analyst context only."""
    return {
        **resolved_evidence,
        "analyst_context": caller_evidence or {},
    }


async def correlate_entity(
    db: AsyncSession,
    *,
    tenant_id: str,
    primary_entity_type: str,
    primary_entity_id: str,
    caller_evidence: dict[str, Any] | None = None,
) -> CorrelationScoreResult:
    resolved = await resolve_platform_evidence(
        db, tenant_id, primary_entity_type, primary_entity_id
    )
    merged = merge_resolved_and_caller_evidence(resolved, caller_evidence)

    service = CorrelationScoringService()
    score = service.score(resolved)

    record = CorrelationRecord(
        tenant_id=tenant_id,
        primary_entity_type=primary_entity_type,
        primary_entity_id=primary_entity_id,
        score=score,
        evidence=resolved,
        analyst_context=caller_evidence or {},
    )
    db.add(record)
    await db.flush()

    return CorrelationScoreResult(score=score, evidence=merged)
