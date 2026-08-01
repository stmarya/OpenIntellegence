"""Campaign and malware intelligence endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import Field
from sqlalchemy import func, select

from app.api.schemas import ListResponse, ORMModel, Page
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.domain_models import Campaign, Malware
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]


class CampaignOut(ORMModel):
    id: str
    name: str
    description: str | None = None
    status: str
    confidence: float | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    actor_names: list[str] = Field(default_factory=list)
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_countries: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class MalwareOut(ORMModel):
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    malware_type: str | None = None
    description: str | None = None
    confidence: float | None = None
    platforms: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)
    actor_names: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@router.get("/campaigns", response_model=ListResponse[CampaignOut], summary="List campaigns")
async def list_campaigns(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> ListResponse[CampaignOut]:
    stmt = select(Campaign)
    if status_filter:
        stmt = stmt.where(Campaign.status == status_filter)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(Campaign.last_seen.desc().nulls_last()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return ListResponse(
        data=[CampaignOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut, summary="Campaign detail")
async def get_campaign(campaign_id: str, db: DbSession, principal: ReadPrincipal) -> CampaignOut:
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found.")
    return CampaignOut.model_validate(campaign)


@router.get("/malware", response_model=ListResponse[MalwareOut], summary="List malware and tools")
async def list_malware(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    malware_type: str | None = None,
    platform: str | None = None,
) -> ListResponse[MalwareOut]:
    stmt = select(Malware)
    if malware_type:
        stmt = stmt.where(Malware.malware_type == malware_type)
    if platform:
        stmt = stmt.where(Malware.platforms.any(platform))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(Malware.last_seen.desc().nulls_last()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return ListResponse(
        data=[MalwareOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/malware/{malware_id}", response_model=MalwareOut, summary="Malware detail")
async def get_malware(malware_id: str, db: DbSession, principal: ReadPrincipal) -> MalwareOut:
    malware = await db.get(Malware, malware_id)
    if malware is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Malware not found.")
    return MalwareOut.model_validate(malware)
