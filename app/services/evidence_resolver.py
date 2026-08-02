"""Server-side correlation evidence resolver.

Resolves scoring factors from persisted platform records keyed by a
tenant-scoped entity reference.  Client callers provide only entity
identity; the resolver fetches:

* vulnerability / KEV / exploit context from the ``vulnerabilities`` table
* asset criticality and exposure from the ``assets`` table
  (tenant-scoped — a caller cannot infer cross-tenant existence)
* corroborating sightings from the ``sightings`` table (tenant-scoped)
* provenance references from matched records

Resolution status reflects how complete the lookup was:

``resolved``      All key scoring fields were found in platform records.
``partial``       Some fields resolved; others remain unknown (null, not zero).
``manual_input``  Caller supplied raw evidence (requires admin scope).
                  Values are preserved separately; never blended with
                  source-resolved evidence and never represented as
                  source-resolved.
``unavailable``   No matching platform records found for this entity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.alert_models import Sighting
from app.db.models import Asset, AssetExposure, Indicator, RansomwareVictim, Vulnerability

ResolutionStatus = Literal["resolved", "partial", "manual_input", "unavailable"]

# The set of scoring factors that must all be non-null for status == "resolved".
_KEY_FACTORS = frozenset(
    {
        "cvss_score",
        "is_kev",
        "exploit_maturity",
        "asset_criticality",
        "internet_exposed",
        "sighting_count",
        "ransomware_relevant",
    }
)


@dataclass
class ResolvedEvidence:
    """Evidence resolved from persisted platform records for a single entity.

    ``None`` on any scoring field means *unknown / not assessed*, never
    "absent / clean".  Callers that render these values must honour that
    distinction.  A UI must show an em-dash or "—" for a null field, not 0.
    """

    entity_type: str
    entity_id: str
    tenant_id: str

    # Vulnerability / KEV / exploit context  (None = not yet assessed by NVD)
    cvss_score: float | None = None
    is_kev: bool | None = None
    exploit_maturity: str | None = None

    # Asset properties  (None = entity not found or concept not applicable)
    asset_criticality: str | None = None
    internet_exposed: bool | None = None

    # Corroborating sightings  (None = not looked up for this entity type)
    sighting_count: int | None = None

    # Ransomware relevance  (None = not assessed)
    ransomware_relevant: bool | None = None

    # Provenance / source references from matched platform records
    source_refs: list[dict] = field(default_factory=list)

    # Resolution metadata
    resolution_status: ResolutionStatus = "unavailable"
    resolved_fields: list[str] = field(default_factory=list)
    unresolved_fields: list[str] = field(default_factory=list)

    # Analyst annotations — never feed scoring
    analyst_notes: str | None = None

    # Manual evidence — preserved separately; never merged with resolved path
    manual_evidence: dict | None = None

    def to_scoring_dict(self) -> dict:
        """Return the evidence dict consumed by ``assess()``.

        Unknown fields (``None``) are passed as their neutral value so the
        scorer omits them rather than rewarding or penalising them.
        ``cvss_score`` is kept as ``None`` so the scorer can emit a
        ``state: "unknown"`` marker in the factor breakdown.
        """
        return {
            "cvss_score": self.cvss_score,
            "is_kev": bool(self.is_kev) if self.is_kev is not None else False,
            "exploit_maturity": self.exploit_maturity,
            "asset_criticality": self.asset_criticality,
            "internet_exposed": (
                bool(self.internet_exposed) if self.internet_exposed is not None else False
            ),
            "sighting_count": self.sighting_count if self.sighting_count is not None else 0,
            "ransomware_relevant": (
                bool(self.ransomware_relevant) if self.ransomware_relevant is not None else False
            ),
            "source_refs": self.source_refs,
        }

    def to_snapshot(self) -> dict:
        """Return an explainable evidence snapshot for storage and API responses.

        All values are preserved exactly, including ``None``, so a consumer
        can distinguish "not yet assessed" from "assessed as safe".
        """
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "cvss_score": self.cvss_score,
            "is_kev": self.is_kev,
            "exploit_maturity": self.exploit_maturity,
            "asset_criticality": self.asset_criticality,
            "internet_exposed": self.internet_exposed,
            "sighting_count": self.sighting_count,
            "ransomware_relevant": self.ransomware_relevant,
            "source_refs": self.source_refs,
            "resolution_status": self.resolution_status,
            "resolved_fields": self.resolved_fields,
            "unresolved_fields": self.unresolved_fields,
        }


class EvidenceResolver:
    """Resolves scoring evidence from persisted platform records.

    All lookups are scoped to ``tenant_id`` so a caller cannot correlate
    an entity in another tenant or infer cross-tenant existence.
    """

    def __init__(self, db: AsyncSession, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    async def resolve(
        self,
        entity_type: str,
        entity_id: str,
        *,
        analyst_notes: str | None = None,
    ) -> ResolvedEvidence:
        """Resolve evidence for a tenant-scoped entity reference.

        Unknown entity types return ``resolution_status="unavailable"``
        rather than raising, so new entity types degrade gracefully.
        """
        ev = ResolvedEvidence(
            entity_type=entity_type,
            entity_id=entity_id,
            tenant_id=self._tenant_id,
            analyst_notes=analyst_notes,
        )

        et = entity_type.lower()
        if et in {"vulnerability", "cve"}:
            await self._resolve_vulnerability(ev, entity_id)
        elif et == "asset":
            await self._resolve_asset(ev, entity_id)
        elif et in {"indicator", "ioc"}:
            await self._resolve_indicator(ev, entity_id)
        # Unknown entity types produce "unavailable" — no further lookups.

        ev.resolution_status = _compute_status(ev)
        return ev

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _resolve_vulnerability(self, ev: ResolvedEvidence, cve_id: str) -> None:
        """Populate vulnerability / KEV / exploit context."""
        vuln = (
            await self._db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
        ).scalar_one_or_none()

        if vuln is None:
            ev.unresolved_fields.extend(
                ["cvss_score", "is_kev", "exploit_maturity"]
            )
            return

        # cvss_score may legitimately be None (NVD has not published a score yet).
        ev.cvss_score = vuln.cvss_score
        ev.is_kev = vuln.is_kev
        ev.exploit_maturity = (
            str(vuln.exploit_maturity) if vuln.exploit_maturity else None
        )

        ev.resolved_fields.extend(["is_kev", "exploit_maturity"])
        if vuln.cvss_score is not None:
            ev.resolved_fields.append("cvss_score")
        else:
            ev.unresolved_fields.append("cvss_score")

        for src in vuln.sources or []:
            ev.source_refs.append({"type": "vulnerability", "id": vuln.id, "source": src})

        # Asset criticality and exposure come from the tenant's asset inventory.
        await self._resolve_asset_exposure_for_vuln(ev, vuln.id)
        # Sighting count from tenant sightings for this CVE.
        await self._resolve_sightings(ev, "vulnerability", cve_id)
        # Ransomware relevance from victim table (sector heuristic).
        await self._resolve_ransomware_relevance(ev)

    async def _resolve_asset_exposure_for_vuln(
        self, ev: ResolvedEvidence, vuln_id: str
    ) -> None:
        """Find the highest-criticality tenant asset exposed to this vulnerability."""
        _CRIT_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        stmt = (
            select(Asset)
            .join(AssetExposure, AssetExposure.asset_id == Asset.id)
            .where(
                AssetExposure.vulnerability_id == vuln_id,
                Asset.tenant_id == self._tenant_id,  # tenant isolation
                AssetExposure.resolved_at.is_(None),
            )
        )
        assets = (await self._db.execute(stmt)).scalars().all()

        if not assets:
            ev.unresolved_fields.extend(["asset_criticality", "internet_exposed"])
            return

        # Pick the most critical exposed asset.
        best = max(assets, key=lambda a: _CRIT_ORDER.get(a.criticality, 0))
        ev.asset_criticality = best.criticality
        # Use ip_address presence as the best available internet-exposure proxy.
        ev.internet_exposed = best.ip_address is not None
        ev.resolved_fields.extend(["asset_criticality", "internet_exposed"])
        ev.source_refs.append(
            {"type": "asset", "id": best.id, "tenant_id": self._tenant_id}
        )

    async def _resolve_asset(self, ev: ResolvedEvidence, asset_id: str) -> None:
        """Populate asset-centred evidence (strictly tenant-scoped)."""
        asset = (
            await self._db.execute(
                select(Asset).where(
                    Asset.id == asset_id,
                    Asset.tenant_id == self._tenant_id,  # tenant isolation
                )
            )
        ).scalar_one_or_none()

        if asset is None:
            ev.unresolved_fields.extend(["asset_criticality", "internet_exposed"])
            return

        ev.asset_criticality = asset.criticality
        ev.internet_exposed = asset.ip_address is not None
        ev.resolved_fields.extend(["asset_criticality", "internet_exposed"])
        ev.source_refs.append(
            {"type": "asset", "id": asset.id, "tenant_id": self._tenant_id}
        )

        # Sightings for this asset entity within the tenant.
        await self._resolve_sightings(ev, "asset", asset_id)
        await self._resolve_ransomware_relevance(ev)

    async def _resolve_indicator(self, ev: ResolvedEvidence, value: str) -> None:
        """Populate IOC evidence."""
        ioc = (
            await self._db.execute(
                select(Indicator).where(Indicator.value == value)
            )
        ).scalar_one_or_none()

        if ioc is None:
            ev.unresolved_fields.append("sighting_count")
            return

        ev.sighting_count = len(ioc.sources or [])
        ev.resolved_fields.append("sighting_count")
        for src in ioc.sources or []:
            ev.source_refs.append({"type": "indicator", "id": ioc.id, "source": src})

        # Ransomware relevance for an IOC: tag-based heuristic.
        tags_lower = [t.lower() for t in (ioc.tags or [])]
        if any("ransomware" in t for t in tags_lower):
            ev.ransomware_relevant = True
            ev.resolved_fields.append("ransomware_relevant")
        else:
            ev.unresolved_fields.append("ransomware_relevant")

    async def _resolve_sightings(
        self, ev: ResolvedEvidence, entity_type: str, entity_id: str
    ) -> None:
        """Count tenant-scoped sightings for this entity."""
        count = (
            await self._db.scalar(
                select(func.count()).where(
                    Sighting.tenant_id == self._tenant_id,
                    Sighting.entity_type == entity_type,
                    Sighting.entity_id == entity_id,
                )
            )
        ) or 0

        ev.sighting_count = int(count)
        ev.resolved_fields.append("sighting_count")

    async def _resolve_ransomware_relevance(self, ev: ResolvedEvidence) -> None:
        """Set ransomware_relevant if any recent victims exist in the platform.

        This is a platform-level signal rather than an entity-specific one:
        the presence of any ransomware victim records indicates the threat is
        active.  Entity-specific mapping (e.g. CVE → group toolchain) requires
        additional intelligence not yet in the schema; when available it should
        refine this heuristic.
        """
        count = (
            await self._db.scalar(select(func.count()).select_from(RansomwareVictim))
        ) or 0

        ev.ransomware_relevant = count > 0
        ev.resolved_fields.append("ransomware_relevant")


def _compute_status(ev: ResolvedEvidence) -> ResolutionStatus:
    """Derive resolution status from resolved/unresolved field lists."""
    if not ev.resolved_fields and not ev.unresolved_fields:
        return "unavailable"
    if ev.unresolved_fields:
        return "partial"
    return "resolved"


def build_from_manual(
    entity_type: str,
    entity_id: str,
    tenant_id: str,
    manual: dict,
    *,
    analyst_notes: str | None = None,
) -> ResolvedEvidence:
    """Build a ``ResolvedEvidence`` from caller-supplied manual evidence.

    The supplied values are forwarded to scoring but preserved separately in
    ``manual_evidence``.  The resolution status is always ``manual_input``
    and is never upgraded to ``resolved`` or ``partial``, so dashboards can
    distinguish operator-supplied values from source-resolved facts.
    """
    return ResolvedEvidence(
        entity_type=entity_type,
        entity_id=entity_id,
        tenant_id=tenant_id,
        cvss_score=manual.get("cvss_score"),
        is_kev=manual.get("is_kev"),
        exploit_maturity=manual.get("exploit_maturity"),
        asset_criticality=manual.get("asset_criticality"),
        internet_exposed=manual.get("internet_exposed"),
        sighting_count=manual.get("sighting_count"),
        ransomware_relevant=manual.get("ransomware_relevant"),
        source_refs=list(manual.get("source_refs") or []),
        resolution_status="manual_input",
        resolved_fields=[],  # manual evidence is not source-resolved
        unresolved_fields=[],
        analyst_notes=analyst_notes,
        manual_evidence=dict(manual),
    )
