"""Detail endpoints for existing CTI entity families.

These routes deliberately sit beside list endpoints. A list is optimized for
triage; a detail response is optimized for pivoting, evidence review, and a
stable entity-specific UI route.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.schemas import IndicatorOut, Provenance, ThreatActorOut
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.models import Indicator, RansomwareVictim, ThreatActor
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
IocPrincipal = Annotated[Principal, Depends(require_scope(Scope.IOC))]


class RelatedVictim(BaseModel):
    """Compact ransomware victim relation shown on an actor profile."""

    id: str
    display_name: str
    group_name: str
    country: str | None = None
    sector: str | None = None
    discovered_at: datetime
    needs_review: bool
    sources: list[str] = Field(default_factory=list)


class ThreatActorDetail(ThreatActorOut):
    description: str | None = None
    sources: list[str] = Field(default_factory=list)
    related_victims: list[RelatedVictim] = Field(default_factory=list)
    provenance: Provenance


class IndicatorDetail(IndicatorOut):
    id: str
    enriched_at: datetime | None = None
    stix_pattern: str | None = None
    provenance: Provenance


@router.get(
    "/actors/{canonical_name}",
    response_model=ThreatActorDetail,
    summary="Threat actor profile with linked ransomware victims",
)
async def get_actor(
    canonical_name: str, db: DbSession, principal: ReadPrincipal
) -> ThreatActorDetail:
    """Load one actor plus the victim relations stored in the platform.

    Actor names are resolved case-insensitively because analysts commonly
    search for "Play", while canonical entity keys are normalised to "play".
    The response does not fabricate attribution: only victims with an actual
    actor foreign key are returned.
    """
    actor = (
        await db.execute(
            select(ThreatActor).where(
                func.lower(ThreatActor.canonical_name) == canonical_name.lower()
            )
        )
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat actor not found.")

    victims = (
        await db.execute(
            select(RansomwareVictim)
            .where(RansomwareVictim.actor_id == actor.id)
            .order_by(RansomwareVictim.discovered_at.desc())
            .limit(100)
        )
    ).scalars().all()

    return ThreatActorDetail(
        **ThreatActorOut.model_validate(actor).model_dump(),
        description=actor.description,
        sources=actor.sources,
        related_victims=[
            RelatedVictim(
                id=str(victim.id),
                display_name=victim.display_name,
                group_name=victim.group_name,
                country=victim.country,
                sector=victim.sector,
                discovered_at=victim.discovered_at,
                needs_review=victim.needs_review,
                sources=victim.sources,
            )
            for victim in victims
        ],
        provenance=await build_provenance(db, sources=("threat_actors", "ransomlook", "ransomware_live", "dls_monitor")),
    )


@router.get(
    "/iocs/{indicator_id}",
    response_model=IndicatorDetail,
    summary="Indicator detail including enrichment and STIX pattern",
)
async def get_indicator(
    indicator_id: str, db: DbSession, principal: IocPrincipal
) -> IndicatorDetail:
    """Load one indicator without equating un-enriched with clean.

    ``verdict=None`` is preserved all the way to the response. Consumers must
    render this as "not yet enriched", not as a benign indicator.
    """
    indicator = await db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found.")

    return IndicatorDetail(
        **IndicatorOut.model_validate(indicator).model_dump(),
        id=str(indicator.id),
        enriched_at=indicator.enriched_at,
        stix_pattern=indicator.stix_pattern,
        provenance=await build_provenance(db, sources=tuple(indicator.sources)),
    )
