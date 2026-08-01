"""Cross-entity search backing the Intelligence Explorer workspace."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.models import Asset, Indicator, RansomwareVictim, ThreatActor, Vulnerability
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]

SearchEntityType = Literal["vulnerability", "indicator", "actor", "ransomware_victim", "asset"]
_ALLOWED_TYPES: set[str] = {
    "vulnerability",
    "indicator",
    "actor",
    "ransomware_victim",
    "asset",
}


class SearchHit(BaseModel):
    """A compact, routable entity returned by cross-entity search."""

    entity_type: SearchEntityType
    entity_id: str
    title: str
    subtitle: str | None = None
    sources: list[str] = Field(default_factory=list)
    confidence: float | None = None


class SearchResponse(BaseModel):
    query: str
    data: list[SearchHit]
    returned: int
    provenance: object


@router.get(
    "/search",
    response_model=SearchResponse,
    summary="Search CVEs, indicators, actors, victims, and tenant assets",
)
async def search(
    db: DbSession,
    principal: ReadPrincipal,
    q: Annotated[str, Query(min_length=2, max_length=256, description="Case-insensitive entity query")],
    entity_type: Annotated[
        list[str] | None,
        Query(alias="type", description="Optional repeatable entity family filter"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> SearchResponse:
    """Return a compact cross-entity result set for analyst pivoting.

    Threat intelligence is shared corpus data. Assets are different: the
    asset query is always scoped to the authenticated tenant, so global search
    cannot reveal another tenant's hostnames or endpoint metadata.
    """
    requested = set(entity_type or _ALLOWED_TYPES)
    invalid = requested - _ALLOWED_TYPES
    if invalid:
        # This is intentionally a validation-shaped response rather than
        # quietly ignoring a misspelled filter and returning broad results.
        from fastapi import HTTPException, status

        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "Unknown entity type.", "invalid": sorted(invalid), "allowed": sorted(_ALLOWED_TYPES)},
        )

    pattern = f"%{q.lower()}%"
    per_type_limit = min(limit, 25)
    hits: list[SearchHit] = []

    if "vulnerability" in requested:
        rows = (
            await db.execute(
                select(Vulnerability)
                .where(
                    or_(
                        func.lower(Vulnerability.cve_id).like(pattern),
                        func.lower(Vulnerability.title).like(pattern),
                        func.lower(Vulnerability.vendor).like(pattern),
                        func.lower(Vulnerability.product).like(pattern),
                    )
                )
                .order_by(Vulnerability.is_kev.desc(), Vulnerability.cvss_score.desc().nulls_last())
                .limit(per_type_limit)
            )
        ).scalars()
        hits.extend(
            SearchHit(
                entity_type="vulnerability",
                entity_id=v.cve_id,
                title=v.cve_id,
                subtitle=v.title or v.description,
                sources=v.sources,
            )
            for v in rows
        )

    if "indicator" in requested:
        rows = (
            await db.execute(
                select(Indicator)
                .where(func.lower(Indicator.value).like(pattern))
                .order_by(Indicator.confidence.desc().nulls_last(), Indicator.last_seen.desc().nulls_last())
                .limit(per_type_limit)
            )
        ).scalars()
        hits.extend(
            SearchHit(
                entity_type="indicator",
                entity_id=str(i.id),
                title=i.value,
                subtitle=f"{i.indicator_type} · {i.verdict or 'unenriched'}",
                sources=i.sources,
                confidence=i.confidence,
            )
            for i in rows
        )

    if "actor" in requested:
        rows = (
            await db.execute(
                select(ThreatActor)
                .where(
                    or_(
                        func.lower(ThreatActor.canonical_name).like(pattern),
                        func.lower(ThreatActor.display_name).like(pattern),
                    )
                )
                .order_by(ThreatActor.last_seen.desc().nulls_last())
                .limit(per_type_limit)
            )
        ).scalars()
        hits.extend(
            SearchHit(
                entity_type="actor",
                entity_id=str(a.id),
                title=a.display_name,
                subtitle=a.actor_type or "Threat actor",
                sources=a.sources,
            )
            for a in rows
        )

    if "ransomware_victim" in requested:
        rows = (
            await db.execute(
                select(RansomwareVictim)
                .where(
                    or_(
                        func.lower(RansomwareVictim.display_name).like(pattern),
                        func.lower(RansomwareVictim.domain).like(pattern),
                        func.lower(RansomwareVictim.group_name).like(pattern),
                    )
                )
                .order_by(RansomwareVictim.discovered_at.desc())
                .limit(per_type_limit)
            )
        ).scalars()
        hits.extend(
            SearchHit(
                entity_type="ransomware_victim",
                entity_id=str(v.id),
                title=v.display_name,
                subtitle=f"{v.group_name} · {v.country or 'unknown country'}",
                sources=v.sources,
            )
            for v in rows
        )

    if "asset" in requested:
        rows = (
            await db.execute(
                select(Asset)
                .where(
                    Asset.tenant_id == principal.tenant_id,
                    or_(
                        func.lower(Asset.hostname).like(pattern),
                        func.lower(Asset.ip_address).like(pattern),
                    ),
                )
                .order_by(Asset.risk_score.desc().nulls_last(), Asset.hostname)
                .limit(per_type_limit)
            )
        ).scalars()
        hits.extend(
            SearchHit(
                entity_type="asset",
                entity_id=str(a.id),
                title=a.hostname,
                subtitle=f"{a.os_family or 'unknown OS'} · {a.criticality}",
                sources=["endpoint_agent"],
            )
            for a in rows
        )

    # A family-first order is stable and predictable for keyboard navigation.
    # The final cap applies across all families, not per individual query.
    return SearchResponse(
        query=q,
        data=hits[:limit],
        returned=min(len(hits), limit),
        provenance=await build_provenance(db, sources=None),
    )
