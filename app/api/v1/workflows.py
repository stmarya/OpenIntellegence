"""Investigation and case workspace APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.schemas import ListResponse, Page
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.workflow_models import Case, CaseEvent, CaseTask, Investigation, InvestigationEntity
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=512)
    hypothesis: str | None = None
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = Field(default=None, max_length=255)


class EntityLinkCreate(BaseModel):
    entity_type: str = Field(min_length=2, max_length=64)
    entity_id: str = Field(min_length=1, max_length=255)
    relationship: str = Field(default="related_to", max_length=64)
    evidence: str | None = None
    source_refs: list[dict] = Field(default_factory=list)


class InvestigationEntityOut(ORM):
    id: str
    entity_type: str
    entity_id: str
    relationship: str
    evidence: str | None = None
    source_refs: list = Field(default_factory=list)
    created_at: datetime


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=512)
    case_type: str = Field(min_length=2, max_length=64)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = Field(default=None, max_length=255)
    investigation_id: str | None = None
    sla_due_at: datetime | None = None


class CaseTaskCreate(BaseModel):
    title: str = Field(min_length=3, max_length=512)
    assignee: str | None = Field(default=None, max_length=255)
    due_at: datetime | None = None


class CaseEventCreate(BaseModel):
    event_type: str = Field(min_length=2, max_length=64)
    body: str = Field(min_length=1, max_length=8000)


class CaseTaskOut(ORM):
    id: str
    title: str
    status: str
    assignee: str | None = None
    due_at: datetime | None = None
    completed_at: datetime | None = None


class CaseEventOut(ORM):
    id: str
    event_type: str
    body: str
    actor: str | None = None
    event_at: datetime


class CaseOut(ORM):
    id: str
    investigation_id: str | None = None
    title: str
    case_type: str
    status: str
    priority: str
    owner: str | None = None
    sla_due_at: datetime | None = None
    closed_at: datetime | None = None
    closure_reason: str | None = None
    created_at: datetime


class InvestigationOut(ORM):
    id: str
    title: str
    hypothesis: str | None = None
    status: str
    priority: str
    confidence: int | None = None
    owner: str | None = None
    opened_at: datetime
    closed_at: datetime | None = None
    created_at: datetime


class InvestigationDetail(InvestigationOut):
    entities: list[InvestigationEntityOut] = Field(default_factory=list)
    cases: list[CaseOut] = Field(default_factory=list)


class CaseDetail(CaseOut):
    tasks: list[CaseTaskOut] = Field(default_factory=list)
    events: list[CaseEventOut] = Field(default_factory=list)


@router.get("/investigations", response_model=ListResponse[InvestigationOut])
async def list_investigations(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    workflow_status: Annotated[str | None, Query(alias="status")] = None,
) -> ListResponse[InvestigationOut]:
    stmt = select(Investigation).where(Investigation.tenant_id == principal.tenant_id)
    if workflow_status:
        stmt = stmt.where(Investigation.status == workflow_status)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Investigation.opened_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ListResponse(
        data=[InvestigationOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.post(
    "/investigations", response_model=InvestigationOut, status_code=status.HTTP_201_CREATED
)
async def create_investigation(
    payload: InvestigationCreate, db: DbSession, principal: WritePrincipal
) -> InvestigationOut:
    item = Investigation(
        tenant_id=principal.tenant_id,
        title=payload.title,
        hypothesis=payload.hypothesis,
        priority=payload.priority,
        owner=payload.owner or f"api_key:{principal.api_key_id}",
    )
    db.add(item)
    await db.flush()
    return InvestigationOut.model_validate(item)


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: str, db: DbSession, principal: ReadPrincipal
) -> InvestigationDetail:
    item = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found.")
    entities = (
        (
            await db.execute(
                select(InvestigationEntity)
                .where(InvestigationEntity.investigation_id == item.id)
                .order_by(InvestigationEntity.created_at)
            )
        )
        .scalars()
        .all()
    )
    cases = (
        (
            await db.execute(
                select(Case)
                .where(Case.investigation_id == item.id)
                .order_by(Case.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return InvestigationDetail(
        **InvestigationOut.model_validate(item).model_dump(),
        entities=[InvestigationEntityOut.model_validate(x) for x in entities],
        cases=[CaseOut.model_validate(x) for x in cases],
    )


@router.post(
    "/investigations/{investigation_id}/entities",
    response_model=InvestigationEntityOut,
    status_code=status.HTTP_201_CREATED,
)
async def attach_entity(
    investigation_id: str, payload: EntityLinkCreate, db: DbSession, principal: WritePrincipal
) -> InvestigationEntityOut:
    owner = (
        await db.execute(
            select(Investigation.id).where(
                Investigation.id == investigation_id,
                Investigation.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found.")
    link = InvestigationEntity(investigation_id=investigation_id, **payload.model_dump())
    db.add(link)
    await db.flush()
    return InvestigationEntityOut.model_validate(link)


@router.get("/cases", response_model=ListResponse[CaseOut])
async def list_cases(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    workflow_status: Annotated[str | None, Query(alias="status")] = None,
) -> ListResponse[CaseOut]:
    stmt = select(Case).where(Case.tenant_id == principal.tenant_id)
    if workflow_status:
        stmt = stmt.where(Case.status == workflow_status)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Case.sla_due_at.asc().nulls_last(), Case.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ListResponse(
        data=[CaseOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.post("/cases", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(payload: CaseCreate, db: DbSession, principal: WritePrincipal) -> CaseOut:
    if payload.investigation_id:
        exists = (
            await db.execute(
                select(Investigation.id).where(
                    Investigation.id == payload.investigation_id,
                    Investigation.tenant_id == principal.tenant_id,
                )
            )
        ).scalar_one_or_none()
        if exists is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Linked investigation not found.")
    item = Case(tenant_id=principal.tenant_id, **payload.model_dump())
    db.add(item)
    await db.flush()
    return CaseOut.model_validate(item)


@router.get("/cases/{case_id}", response_model=CaseDetail)
async def get_case(case_id: str, db: DbSession, principal: ReadPrincipal) -> CaseDetail:
    item = (
        await db.execute(
            select(Case).where(Case.id == case_id, Case.tenant_id == principal.tenant_id)
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found.")
    tasks = (
        (
            await db.execute(
                select(CaseTask)
                .where(CaseTask.case_id == item.id)
                .order_by(CaseTask.due_at.asc().nulls_last())
            )
        )
        .scalars()
        .all()
    )
    events = (
        (
            await db.execute(
                select(CaseEvent)
                .where(CaseEvent.case_id == item.id)
                .order_by(CaseEvent.event_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return CaseDetail(
        **CaseOut.model_validate(item).model_dump(),
        tasks=[CaseTaskOut.model_validate(x) for x in tasks],
        events=[CaseEventOut.model_validate(x) for x in events],
    )


@router.post(
    "/cases/{case_id}/tasks", response_model=CaseTaskOut, status_code=status.HTTP_201_CREATED
)
async def add_task(
    case_id: str, payload: CaseTaskCreate, db: DbSession, principal: WritePrincipal
) -> CaseTaskOut:
    exists = (
        await db.execute(
            select(Case.id).where(Case.id == case_id, Case.tenant_id == principal.tenant_id)
        )
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found.")
    task = CaseTask(case_id=case_id, **payload.model_dump())
    db.add(task)
    await db.flush()
    return CaseTaskOut.model_validate(task)


@router.post(
    "/cases/{case_id}/events", response_model=CaseEventOut, status_code=status.HTTP_201_CREATED
)
async def add_event(
    case_id: str, payload: CaseEventCreate, db: DbSession, principal: WritePrincipal
) -> CaseEventOut:
    exists = (
        await db.execute(
            select(Case.id).where(Case.id == case_id, Case.tenant_id == principal.tenant_id)
        )
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found.")
    event = CaseEvent(
        case_id=case_id, actor=f"api_key:{principal.api_key_id}", **payload.model_dump()
    )
    db.add(event)
    await db.flush()
    return CaseEventOut.model_validate(event)
