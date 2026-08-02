"""Pure, explainable correlation scoring and server-side evidence resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class CorrelationAssessment:
    score: int
    tier: str
    factors: list[dict]
    automation_candidates: list[dict]


def assess(evidence: dict) -> CorrelationAssessment:
    factors: list[dict] = []

    def add(key: str, label: str, points: int, present: bool) -> None:
        if present:
            factors.append({"key": key, "label": label, "points": points, "state": "present"})

    cvss = evidence.get("cvss_score")
    if cvss is not None:
        add(
            "cvss",
            f"CVSS {cvss}",
            20 if cvss >= 9 else 14 if cvss >= 7 else 6 if cvss >= 4 else 0,
            True,
        )
    else:
        factors.append({"key": "cvss", "label": "CVSS unknown", "points": 0, "state": "unknown"})

    add("kev", "Known Exploited Vulnerability", 25, bool(evidence.get("is_kev")))
    add(
        "exploit",
        "Public or active exploit evidence",
        15,
        evidence.get("exploit_maturity") in {"poc", "functional", "weaponized", "active"},
    )
    criticality = {
        "critical": 20,
        "high": 14,
        "medium": 8,
        "low": 3,
    }.get(str(evidence.get("asset_criticality", "")).lower(), 0)
    add(
        "asset_criticality",
        f"Asset criticality: {evidence.get('asset_criticality')}",
        criticality,
        criticality > 0,
    )
    add("internet_exposure", "Internet-exposed asset", 15, bool(evidence.get("internet_exposed")))
    sightings = max(0, min(int(evidence.get("sighting_count") or 0), 3))
    add("sightings", f"{sightings} corroborating sighting(s)", sightings * 5, sightings > 0)
    add(
        "ransomware",
        "Ransomware or sector relevance",
        10,
        bool(evidence.get("ransomware_relevant")),
    )

    score = min(100, sum(int(x["points"]) for x in factors))
    tier = (
        "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    )

    candidates: list[dict] = []
    if score >= 80:
        candidates += [
            {
                "action": "create_case",
                "reason": "Critical correlated risk",
                "requires_approval": True,
            },
            {
                "action": "notify_owner",
                "reason": "Critical exposure requires ownership",
                "requires_approval": True,
            },
        ]
    elif score >= 60:
        candidates += [
            {"action": "create_case", "reason": "High correlated risk", "requires_approval": True},
        ]
    if evidence.get("internet_exposed") and evidence.get("is_kev"):
        candidates += [
            {
                "action": "request_containment_review",
                "reason": "Internet-exposed KEV",
                "requires_approval": True,
            }
        ]

    return CorrelationAssessment(
        score=score,
        tier=tier,
        factors=factors,
        automation_candidates=candidates,
    )


# ---------------------------------------------------------------------------
# Server-side evidence resolver
# ---------------------------------------------------------------------------


@dataclass
class ResolvedEvidence:
    """Evidence resolved from server-side DB records.

    Each field carries a ``state`` of "present", "unknown", or "partial" so
    callers can distinguish a known-false from a not-yet-known value and
    surface that distinction in the UI / audit trail.
    """

    # Merged evidence dict ready for ``assess()``
    evidence: dict = field(default_factory=dict)
    # Provenance list: one entry per factor, naming the DB table / record used
    factor_provenance: list[dict] = field(default_factory=list)


async def resolve_evidence(
    db: "AsyncSession",
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    client_hints: dict | None = None,
) -> ResolvedEvidence:
    """Resolve correlation evidence from server-side DB records.

    Client-supplied hints are merged in only as *optional context* for fields
    that the server cannot determine on its own (e.g. a client-reported
    sighting count from an external feed not yet ingested). Server-resolved
    values always override client hints for the same key.

    Parameters
    ----------
    db:
        Async SQLAlchemy session (read-only queries, no writes).
    tenant_id:
        The tenant whose asset/exposure records to scope the lookup to.
    entity_type:
        "cve", "asset", "indicator", or "host" — selects the resolution path.
    entity_id:
        The CVE ID, asset hostname / ID, indicator value, or host IP.
    client_hints:
        Optional extra context from the caller, used only for fields the
        server cannot resolve independently. Must not be trusted for
        security-sensitive decisions.
    """
    from app.db.alert_models import Sighting
    from app.db.models import Asset, AssetExposure, RansomwareVictim, Vulnerability

    hints = dict(client_hints or {})
    evidence: dict = {}
    provenance: list[dict] = []

    def _prov(factor: str, source: str, record_id: str | None, state: str) -> None:
        provenance.append(
            {
                "factor": factor,
                "source": source,
                "record_id": record_id,
                "state": state,
                "resolved_at": datetime.now(UTC).isoformat(),
            }
        )

    # ------------------------------------------------------------------
    # Resolve by entity type
    # ------------------------------------------------------------------

    if entity_type == "cve":
        # Look up the vulnerability record directly.
        vuln = (
            await db.execute(select(Vulnerability).where(Vulnerability.cve_id == entity_id))
        ).scalar_one_or_none()

        if vuln is not None:
            evidence["cvss_score"] = vuln.cvss_score  # may be None (unknown)
            evidence["is_kev"] = vuln.is_kev
            evidence["exploit_maturity"] = (
                vuln.exploit_maturity.value
                if hasattr(vuln.exploit_maturity, "value")
                else str(vuln.exploit_maturity)
            )
            _prov("cvss", "vulnerabilities", vuln.id, "present" if vuln.cvss_score is not None else "partial")
            _prov("kev", "vulnerabilities", vuln.id, "present")
            _prov("exploit", "vulnerabilities", vuln.id, "present")
        else:
            evidence["cvss_score"] = hints.get("cvss_score")
            evidence["is_kev"] = hints.get("is_kev", False)
            evidence["exploit_maturity"] = hints.get("exploit_maturity", "unknown")
            _prov("cvss", "client_hint", None, "unknown")
            _prov("kev", "client_hint", None, "unknown")
            _prov("exploit", "client_hint", None, "unknown")

        # Find assets exposed to this CVE within the tenant.
        exposure_stmt = (
            select(AssetExposure, Asset)
            .join(Asset, Asset.id == AssetExposure.asset_id)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(
                Asset.tenant_id == tenant_id,
                Vulnerability.cve_id == entity_id,
                AssetExposure.resolved_at.is_(None),
            )
            .limit(50)
        )
        exposures = (await db.execute(exposure_stmt)).all()
        if exposures:
            # Pick the most critical asset.
            criticality_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            best_asset = max(
                exposures, key=lambda row: criticality_rank.get(row[1].criticality, 0)
            )[1]
            evidence["asset_criticality"] = best_asset.criticality
            _prov("asset_criticality", "assets", best_asset.id, "present")
        else:
            evidence["asset_criticality"] = hints.get("asset_criticality")
            _prov("asset_criticality", "client_hint", None, "unknown")

    elif entity_type in {"asset", "host"}:
        # Look up the asset by hostname or by ID.
        asset_stmt = select(Asset).where(Asset.tenant_id == tenant_id)
        if entity_type == "asset":
            asset_stmt = asset_stmt.where(Asset.id == entity_id)
        else:
            asset_stmt = asset_stmt.where(Asset.hostname == entity_id)
        asset = (await db.execute(asset_stmt)).scalar_one_or_none()

        if asset is not None:
            evidence["asset_criticality"] = asset.criticality
            _prov("asset_criticality", "assets", asset.id, "present")

            # Check KEV exposures for this asset.
            kev_exposure = (
                await db.execute(
                    select(AssetExposure)
                    .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
                    .where(
                        AssetExposure.asset_id == asset.id,
                        Vulnerability.is_kev.is_(True),
                        AssetExposure.resolved_at.is_(None),
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            evidence["is_kev"] = kev_exposure is not None
            _prov("kev", "asset_exposures+vulnerabilities", asset.id, "present")

            # Use highest CVSS among open KEV exposures.
            best_vuln = (
                await db.execute(
                    select(Vulnerability)
                    .join(AssetExposure, AssetExposure.vulnerability_id == Vulnerability.id)
                    .where(
                        AssetExposure.asset_id == asset.id,
                        AssetExposure.resolved_at.is_(None),
                    )
                    .order_by(Vulnerability.cvss_score.desc().nulls_last())
                    .limit(1)
                )
            ).scalar_one_or_none()
            evidence["cvss_score"] = best_vuln.cvss_score if best_vuln else None
            _prov(
                "cvss",
                "vulnerabilities",
                best_vuln.id if best_vuln else None,
                "present" if best_vuln and best_vuln.cvss_score is not None else "partial",
            )
        else:
            evidence["asset_criticality"] = hints.get("asset_criticality")
            evidence["is_kev"] = hints.get("is_kev", False)
            evidence["cvss_score"] = hints.get("cvss_score")
            _prov("asset_criticality", "client_hint", None, "unknown")
            _prov("kev", "client_hint", None, "unknown")
            _prov("cvss", "client_hint", None, "unknown")

    else:
        # For other entity types (indicator, etc.), fall back to client hints.
        for key in ("cvss_score", "is_kev", "exploit_maturity", "asset_criticality"):
            evidence[key] = hints.get(key)
            _prov(key, "client_hint", None, "unknown")

    # ------------------------------------------------------------------
    # Sighting count — always resolved server-side within tenant scope.
    # ------------------------------------------------------------------
    sighting_count_row = await db.execute(
        select(func.count())
        .select_from(Sighting)
        .where(
            Sighting.tenant_id == tenant_id,
            Sighting.entity_id == entity_id,
            Sighting.observed_at >= datetime.now(UTC) - timedelta(days=30),
        )
    )
    sighting_count = sighting_count_row.scalar() or 0
    # Accept client hint only if server has nothing.
    if sighting_count == 0 and hints.get("sighting_count"):
        evidence["sighting_count"] = int(hints["sighting_count"])
        _prov("sightings", "client_hint", None, "partial")
    else:
        evidence["sighting_count"] = sighting_count
        _prov("sightings", "sightings", None, "present")

    # ------------------------------------------------------------------
    # Ransomware relevance — check by domain or sector match.
    # ------------------------------------------------------------------
    ransomware_relevant = False
    domain_hint = hints.get("domain") or entity_id
    rv = (
        await db.execute(
            select(RansomwareVictim)
            .where(RansomwareVictim.domain == domain_hint)
            .limit(1)
        )
    ).scalar_one_or_none()
    if rv is not None:
        ransomware_relevant = True
        _prov("ransomware", "ransomware_victims", rv.id, "present")
    else:
        ransomware_relevant = bool(hints.get("ransomware_relevant", False))
        _prov("ransomware", "client_hint", None, "partial" if ransomware_relevant else "unknown")
    evidence["ransomware_relevant"] = ransomware_relevant

    # ------------------------------------------------------------------
    # Internet exposure — accept client hint (agents report this).
    # ------------------------------------------------------------------
    evidence["internet_exposed"] = bool(hints.get("internet_exposed", False))
    _prov("internet_exposure", "client_hint", None, "partial")

    return ResolvedEvidence(evidence=evidence, factor_provenance=provenance)
