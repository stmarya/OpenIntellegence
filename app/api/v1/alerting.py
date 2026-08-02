"""Alert-rule, alert-triage, and sighting-intake APIs."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from app.api.schemas import ListResponse, Page
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.alert_models import Alert, AlertRule, Sighting
from app.services.alerting import alert_fingerprint
from app.services.provenance import build_provenance
router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]
class ORM(BaseModel): model_config = ConfigDict(from_attributes=True)
class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255); description: str | None = None
    trigger_type: Literal["kev_exposure","ioc_sighting","agent_stale","ransomware_relevance","feed_degraded","custom"]
    condition: dict = Field(default_factory=dict); severity: Literal["low","medium","high","critical"] = "medium"
    cooldown_minutes: int = Field(default=60, ge=1, le=10080); auto_create_case: bool = False
class AlertRuleOut(ORM):
    id: str; name: str; description: str | None = None; trigger_type: str; condition: dict; severity: str; enabled: bool; cooldown_minutes: int; auto_create_case: bool; created_at: datetime
class AlertCreate(BaseModel):
    rule_id: str | None = None; title: str = Field(min_length=3,max_length=512); summary: str | None = None
    severity: Literal["low","medium","high","critical"]; entity_type: str | None = Field(default=None,max_length=64); entity_id: str | None = Field(default=None,max_length=255); risk_score: int | None = Field(default=None,ge=0,le=100); payload: dict = Field(default_factory=dict)
class AlertOut(ORM):
    id: str; rule_id: str | None = None; title: str; summary: str | None = None; severity: str; status: str; entity_type: str | None = None; entity_id: str | None = None; risk_score: int | None = None; first_triggered_at: datetime; last_triggered_at: datetime; occurrences: int; acknowledged_at: datetime | None = None; acknowledged_by: str | None = None
class SightingCreate(BaseModel):
    entity_type: str = Field(min_length=2,max_length=64); entity_id: str = Field(min_length=1,max_length=255); asset_id: str | None = Field(default=None,max_length=255); source: str = Field(min_length=2,max_length=64); observed_at: datetime; confidence: int | None = Field(default=None,ge=0,le=100); context: dict = Field(default_factory=dict)
class SightingOut(ORM):
    id: str; entity_type: str; entity_id: str; asset_id: str | None = None; source: str; observed_at: datetime; confidence: int | None = None; context: dict


class AlertDetail(BaseModel):
    """One alert with the rule that raised it and the matching sightings."""

    alert: AlertOut
    rule: AlertRuleOut | None = None
    sightings: list[SightingOut]
    rule_basis: str
    sighting_match_basis: str


@router.get("/alert-rules",response_model=ListResponse[AlertRuleOut])
async def list_rules(db: DbSession,principal: ReadPrincipal,limit: Annotated[int,Query(ge=1,le=200)]=50,offset: Annotated[int,Query(ge=0)]=0)->ListResponse[AlertRuleOut]:
    stmt=select(AlertRule).where(AlertRule.tenant_id==principal.tenant_id); total=await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows=(await db.execute(stmt.order_by(AlertRule.created_at.desc()).limit(limit).offset(offset))).scalars().all(); return ListResponse(data=[AlertRuleOut.model_validate(x) for x in rows],page=Page(limit=limit,offset=offset,total=total,has_more=offset+limit<total),provenance=await build_provenance(db,sources=None))
@router.post("/alert-rules",response_model=AlertRuleOut,status_code=status.HTTP_201_CREATED)
async def create_rule(payload: AlertRuleCreate,db: DbSession,principal: WritePrincipal)->AlertRuleOut:
    item=AlertRule(tenant_id=principal.tenant_id,**payload.model_dump()); db.add(item); await db.flush(); await db.refresh(item); return AlertRuleOut.model_validate(item)
@router.get("/alerts",response_model=ListResponse[AlertOut])
async def list_alerts(db: DbSession,principal: ReadPrincipal,limit: Annotated[int,Query(ge=1,le=500)]=50,offset: Annotated[int,Query(ge=0)]=0,alert_status: Annotated[str|None,Query(alias="status")]=None,severity: str|None=None)->ListResponse[AlertOut]:
    stmt=select(Alert).where(Alert.tenant_id==principal.tenant_id)
    if alert_status: stmt=stmt.where(Alert.status==alert_status)
    if severity: stmt=stmt.where(Alert.severity==severity)
    total=await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows=(await db.execute(stmt.order_by(Alert.risk_score.desc().nulls_last(),Alert.last_triggered_at.desc()).limit(limit).offset(offset))).scalars().all(); return ListResponse(data=[AlertOut.model_validate(x) for x in rows],page=Page(limit=limit,offset=offset,total=total,has_more=offset+limit<total),provenance=await build_provenance(db,sources=None))
@router.post("/alerts",response_model=AlertOut,status_code=status.HTTP_201_CREATED)
async def create_alert(payload: AlertCreate,db: DbSession,principal: WritePrincipal)->AlertOut:
    if payload.rule_id:
        rule=(await db.execute(select(AlertRule).where(AlertRule.id==payload.rule_id,AlertRule.tenant_id==principal.tenant_id,AlertRule.enabled.is_(True)))).scalar_one_or_none()
        if rule is None: raise HTTPException(status.HTTP_404_NOT_FOUND,"Enabled alert rule not found.")
    now=datetime.now(UTC); fingerprint=alert_fingerprint(principal.tenant_id,rule_id=payload.rule_id,entity_type=payload.entity_type,entity_id=payload.entity_id,severity=payload.severity,bucket=now); item=Alert(tenant_id=principal.tenant_id,fingerprint=fingerprint,first_triggered_at=now,last_triggered_at=now,**payload.model_dump())
    try:
        async with db.begin_nested(): db.add(item); await db.flush()
        return AlertOut.model_validate(item)
    except IntegrityError:
        existing=(await db.execute(select(Alert).where(Alert.tenant_id==principal.tenant_id,Alert.fingerprint==fingerprint).with_for_update())).scalar_one(); existing.occurrences+=1; existing.last_triggered_at=now; existing.payload=payload.payload; await db.flush(); return AlertOut.model_validate(existing)


@router.get("/alerts/{alert_id}", response_model=AlertDetail, summary="Alert detail")
async def get_alert(alert_id: str, db: DbSession, principal: ReadPrincipal) -> AlertDetail:
    """Return one alert with the rule that raised it and related sightings.

    Sightings are matched on the alert's entity reference. When an alert
    carries no entity, no sighting list is claimed at all rather than
    showing an unrelated selection that would read as corroboration.
    """
    alert = (
        await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == principal.tenant_id)
        )
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")

    rule = None
    if alert.rule_id:
        rule = (
            await db.execute(
                select(AlertRule).where(
                    AlertRule.id == alert.rule_id,
                    AlertRule.tenant_id == principal.tenant_id,
                )
            )
        ).scalar_one_or_none()

    rule_basis = (
        "This alert records a rule id whose rule is no longer present, so the "
        "triggering condition cannot be shown."
        if alert.rule_id and rule is None
        else "This alert was raised without a rule reference."
        if not alert.rule_id
        else "The rule shown is the current definition, which may have been "
        "edited since this alert fired."
    )

    sightings: list[Sighting] = []
    if alert.entity_id:
        stmt = select(Sighting).where(
            Sighting.tenant_id == principal.tenant_id,
            Sighting.entity_id == alert.entity_id,
        )
        if alert.entity_type:
            stmt = stmt.where(Sighting.entity_type == alert.entity_type)
        sightings = list(
            (
                await db.execute(stmt.order_by(Sighting.observed_at.desc()).limit(100))
            ).scalars().all()
        )
        sighting_basis = (
            "Sightings are matched on this alert's entity reference within the "
            "tenant. An empty list means none was reported, not that the entity "
            "was never present."
        )
    else:
        sighting_basis = (
            "This alert carries no entity reference, so no sighting can be tied "
            "to it without guessing."
        )

    return AlertDetail(
        alert=AlertOut.model_validate(alert),
        rule=AlertRuleOut.model_validate(rule) if rule is not None else None,
        sightings=[SightingOut.model_validate(s) for s in sightings],
        rule_basis=rule_basis,
        sighting_match_basis=sighting_basis,
    )


@router.post("/alerts/{alert_id}/acknowledge",response_model=AlertOut)
async def acknowledge_alert(alert_id: str,db: DbSession,principal: WritePrincipal)->AlertOut:
    item=(await db.execute(select(Alert).where(Alert.id==alert_id,Alert.tenant_id==principal.tenant_id))).scalar_one_or_none()
    if item is None: raise HTTPException(status.HTTP_404_NOT_FOUND,"Alert not found.")
    item.status="acknowledged"; item.acknowledged_at=datetime.now(UTC); item.acknowledged_by=f"api_key:{principal.api_key_id}"; await db.flush(); return AlertOut.model_validate(item)
@router.get("/sightings",response_model=ListResponse[SightingOut])
async def list_sightings(db: DbSession,principal: ReadPrincipal,limit: Annotated[int,Query(ge=1,le=500)]=50,offset: Annotated[int,Query(ge=0)]=0,entity_type: str|None=None)->ListResponse[SightingOut]:
    stmt=select(Sighting).where(Sighting.tenant_id==principal.tenant_id)
    if entity_type: stmt=stmt.where(Sighting.entity_type==entity_type)
    total=await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows=(await db.execute(stmt.order_by(Sighting.observed_at.desc()).limit(limit).offset(offset))).scalars().all(); return ListResponse(data=[SightingOut.model_validate(x) for x in rows],page=Page(limit=limit,offset=offset,total=total,has_more=offset+limit<total),provenance=await build_provenance(db,sources=None))
@router.post("/sightings",response_model=SightingOut,status_code=status.HTTP_201_CREATED)
async def create_sighting(payload:SightingCreate,db:DbSession,principal:WritePrincipal)->SightingOut:
    item=Sighting(tenant_id=principal.tenant_id,**payload.model_dump()); db.add(item); await db.flush(); return SightingOut.model_validate(item)
