"""Cross-cutting APIs for identity, graph, search, agent control, AI, and detection."""
from __future__ import annotations

from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select

from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.endpoint_intent_models import EndpointIntent
from app.db.models import Asset, Indicator, ThreatActor, Vulnerability
from app.db.platform_models import (
    AiEvaluation,
    AgentCommand,
    DetectionRule,
    EntityRelationship,
    EntityRevision,
    Role,
    RoleAssignment,
    SavedSearch,
    User,
)
from app.services.agents import resolve_agent_from_request

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]
AdminPrincipal = Annotated[Principal, Depends(require_scope(Scope.ADMIN))]


class UserCreate(BaseModel):
    email: str = Field(max_length=320)
    display_name: str = Field(min_length=1, max_length=255)
    oidc_subject: str | None = None
    mfa_required: bool = False


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    scopes: list[str] = Field(min_length=1)


class AssignmentCreate(BaseModel):
    user_id: str
    role_id: str


class RelationshipCreate(BaseModel):
    source_type: str
    source_id: str
    relationship_type: str
    target_type: str
    target_id: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence: dict = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class SavedSearchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    query: str = Field(min_length=2, max_length=2000)
    filters: dict = Field(default_factory=dict)
    is_shared: bool = False


class DetectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    rule_format: Literal["sigma", "yara", "suricata", "snort"]
    content: str = Field(min_length=1)
    version: str = Field(default="1", max_length=32)
    attack_techniques: list[str] = Field(default_factory=list)


class EvaluationCreate(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    expected_refs: list[str] = Field(default_factory=list)
    actual_refs: list[str] = Field(default_factory=list)
    model: str | None = None


class CommandAck(BaseModel):
    nonce: str
    state: Literal["completed", "failed", "rejected"]
    result: dict = Field(default_factory=dict)


def actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


def row(item) -> dict:
    return {column.name: getattr(item, column.name) for column in item.__table__.columns}


def aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@router.get("/users")
async def users(db: DbSession, principal: ReadPrincipal) -> dict:
    items = (
        await db.execute(
            select(User).where(User.tenant_id == principal.tenant_id).order_by(User.email)
        )
    ).scalars().all()
    return {"data": [row(item) for item in items], "identity_model": "user_role"}


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, db: DbSession, principal: AdminPrincipal) -> dict:
    exists = await db.scalar(
        select(func.count()).select_from(User).where(
            User.tenant_id == principal.tenant_id,
            func.lower(User.email) == payload.email.lower(),
        )
    )
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exists in this tenant.")
    item = User(
        tenant_id=principal.tenant_id,
        email=payload.email.lower(),
        display_name=payload.display_name,
        oidc_subject=payload.oidc_subject,
        mfa_required=payload.mfa_required,
        status="active",
    )
    db.add(item)
    await db.flush()
    return row(item)


@router.get("/roles")
async def roles(db: DbSession, principal: ReadPrincipal) -> dict:
    items = (
        await db.execute(
            select(Role).where(Role.tenant_id == principal.tenant_id).order_by(Role.name)
        )
    ).scalars().all()
    return {"data": [row(item) for item in items]}


@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(payload: RoleCreate, db: DbSession, principal: AdminPrincipal) -> dict:
    known = {
        Scope.READ,
        Scope.WRITE,
        Scope.IOC,
        Scope.ENROLL,
        Scope.APIKEY_READ,
        Scope.APIKEY_WRITE,
        Scope.REPORT_WRITE,
        Scope.ADMIN,
    }
    unknown = sorted(set(payload.scopes) - known)
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "Unknown scopes", "unknown": unknown},
        )
    item = Role(
        tenant_id=principal.tenant_id,
        name=payload.name,
        description=payload.description,
        scopes=sorted(set(payload.scopes)),
        built_in=False,
    )
    db.add(item)
    await db.flush()
    return row(item)


@router.post("/role-assignments", status_code=status.HTTP_201_CREATED)
async def assign_role(
    payload: AssignmentCreate,
    db: DbSession,
    principal: AdminPrincipal,
) -> dict:
    user = await db.get(User, payload.user_id)
    role = await db.get(Role, payload.role_id)
    if (
        user is None
        or role is None
        or user.tenant_id != principal.tenant_id
        or role.tenant_id != principal.tenant_id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant user or role not found.")
    item = RoleAssignment(
        tenant_id=principal.tenant_id,
        user_id=user.id,
        role_id=role.id,
        assigned_by=actor(principal),
    )
    db.add(item)
    await db.flush()
    return row(item)


@router.get("/relationships")
async def relationships(
    db: DbSession,
    principal: ReadPrincipal,
    entity_type: str,
    entity_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    source = and_(
        EntityRelationship.source_type == entity_type,
        EntityRelationship.source_id == entity_id,
    )
    target = and_(
        EntityRelationship.target_type == entity_type,
        EntityRelationship.target_id == entity_id,
    )
    statement = select(EntityRelationship).where(
        or_(
            EntityRelationship.tenant_id.is_(None),
            EntityRelationship.tenant_id == principal.tenant_id,
        ),
        or_(source, target),
    ).limit(limit)
    items = (await db.execute(statement)).scalars().all()
    return {"data": [row(item) for item in items], "count": len(items), "basis": "typed_edges"}


@router.post("/relationships", status_code=status.HTTP_201_CREATED)
async def create_relationship(
    payload: RelationshipCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> dict:
    if payload.source_type == payload.target_type and payload.source_id == payload.target_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Self-edge is not allowed.")
    item = EntityRelationship(
        tenant_id=principal.tenant_id,
        created_by=actor(principal),
        **payload.model_dump(),
    )
    db.add(item)
    await db.flush()
    return row(item)


@router.get("/entities/{entity_type}/{entity_id}/revisions")
async def revisions(
    entity_type: str,
    entity_id: str,
    db: DbSession,
    principal: ReadPrincipal,
) -> dict:
    items = (
        await db.execute(
            select(EntityRevision).where(
                or_(
                    EntityRevision.tenant_id.is_(None),
                    EntityRevision.tenant_id == principal.tenant_id,
                ),
                EntityRevision.entity_type == entity_type,
                EntityRevision.entity_id == entity_id,
            ).order_by(EntityRevision.revision.desc())
        )
    ).scalars().all()
    return {"data": [row(item) for item in items]}


@router.get("/search/global")
async def global_search(
    db: DbSession,
    principal: ReadPrincipal,
    q: Annotated[str, Query(min_length=2, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> dict:
    pattern = f"%{q.lower()}%"
    results: list[dict] = []
    vulnerabilities = (
        await db.execute(
            select(Vulnerability).where(
                or_(
                    func.lower(Vulnerability.cve_id).like(pattern),
                    func.lower(Vulnerability.description).like(pattern),
                )
            ).limit(limit)
        )
    ).scalars().all()
    results.extend(
        {"type": "vulnerability", "id": item.cve_id, "title": item.cve_id, "summary": item.title}
        for item in vulnerabilities
    )
    indicators = (
        await db.execute(
            select(Indicator).where(func.lower(Indicator.value).like(pattern)).limit(limit)
        )
    ).scalars().all()
    results.extend(
        {"type": "indicator", "id": item.id, "title": item.value, "summary": item.indicator_type}
        for item in indicators
    )
    actors = (
        await db.execute(
            select(ThreatActor).where(
                or_(
                    func.lower(ThreatActor.display_name).like(pattern),
                    func.lower(ThreatActor.canonical_name).like(pattern),
                )
            ).limit(limit)
        )
    ).scalars().all()
    results.extend(
        {"type": "threat_actor", "id": item.id, "title": item.display_name, "summary": item.actor_type}
        for item in actors
    )
    assets = (
        await db.execute(
            select(Asset).where(
                Asset.tenant_id == principal.tenant_id,
                func.lower(Asset.hostname).like(pattern),
            ).limit(limit)
        )
    ).scalars().all()
    results.extend(
        {"type": "asset", "id": item.id, "title": item.hostname, "summary": item.os_family}
        for item in assets
    )
    return {
        "query": q,
        "data": results[:limit],
        "has_more": len(results) > limit,
        "search_basis": "database_exact_and_substring",
    }


@router.get("/saved-searches")
async def saved_searches(db: DbSession, principal: ReadPrincipal) -> dict:
    items = (
        await db.execute(
            select(SavedSearch)
            .where(SavedSearch.tenant_id == principal.tenant_id)
            .order_by(SavedSearch.name)
        )
    ).scalars().all()
    return {"data": [row(item) for item in items]}


@router.post("/saved-searches", status_code=status.HTTP_201_CREATED)
async def save_search(
    payload: SavedSearchCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> dict:
    item = SavedSearch(tenant_id=principal.tenant_id, user_id=None, **payload.model_dump())
    db.add(item)
    await db.flush()
    return row(item)


@router.post("/agent-commands/{intent_id}/publish", status_code=status.HTTP_201_CREATED)
async def publish_command(
    intent_id: str,
    db: DbSession,
    principal: AdminPrincipal,
) -> dict:
    intent = (
        await db.execute(
            select(EndpointIntent).where(
                EndpointIntent.id == intent_id,
                EndpointIntent.tenant_id == principal.tenant_id,
            ).with_for_update()
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Intent not found.")
    existing = (
        await db.execute(select(AgentCommand).where(AgentCommand.intent_id == intent.id))
    ).scalar_one_or_none()
    if existing is not None:
        return row(existing)
    if intent.state != "approved":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only approved intents can be published.")
    if intent.intent_type != "collect_inventory":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Only non-destructive collect_inventory is enabled in this release.",
        )
    expires_at = aware(intent.expires_at)
    if expires_at <= datetime.now(UTC):
        raise HTTPException(status.HTTP_409_CONFLICT, "Intent has expired.")
    nonce = token_urlsafe(32)
    envelope = {
        "command": "collect_inventory",
        "agent_id": intent.agent_id,
        "nonce": nonce,
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    item = AgentCommand(
        tenant_id=principal.tenant_id,
        agent_id=intent.agent_id,
        intent_id=intent.id,
        nonce=nonce,
        envelope=envelope,
        state="available",
        available_at=datetime.now(UTC),
        expires_at=expires_at,
    )
    db.add(item)
    intent.delivery_state = "available"
    await db.flush()
    return row(item)


@router.get("/agents/commands/poll")
async def poll_commands(request: Request, db: DbSession) -> dict:
    agent = await resolve_agent_from_request(request, db, get_settings())
    now = datetime.now(UTC)
    items = (
        await db.execute(
            select(AgentCommand).where(
                AgentCommand.agent_id == agent.id,
                AgentCommand.state == "available",
                AgentCommand.available_at <= now,
                AgentCommand.expires_at > now,
            ).order_by(AgentCommand.available_at).limit(10)
        )
    ).scalars().all()
    return {"commands": [{"id": item.id, **item.envelope} for item in items]}


@router.post("/agents/commands/{command_id}/ack")
async def acknowledge_command(
    command_id: str,
    payload: CommandAck,
    request: Request,
    db: DbSession,
) -> dict:
    agent = await resolve_agent_from_request(request, db, get_settings())
    item = (
        await db.execute(
            select(AgentCommand).where(
                AgentCommand.id == command_id,
                AgentCommand.agent_id == agent.id,
            ).with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Command not found.")
    if item.nonce != payload.nonce:
        raise HTTPException(status.HTTP_409_CONFLICT, "Nonce mismatch.")
    if item.state != "available":
        return row(item)
    if aware(item.expires_at) <= datetime.now(UTC):
        item.state = "expired"
        raise HTTPException(status.HTTP_409_CONFLICT, "Command has expired.")
    item.state = payload.state
    item.result = payload.result
    item.acknowledged_at = datetime.now(UTC)
    intent = await db.get(EndpointIntent, item.intent_id)
    if intent is not None:
        intent.delivery_state = payload.state
        intent.delivery_result = payload.result
    await db.flush()
    return row(item)


@router.get("/ai/evaluations")
async def evaluations(db: DbSession, principal: ReadPrincipal) -> dict:
    items = (
        await db.execute(
            select(AiEvaluation).where(
                or_(
                    AiEvaluation.tenant_id.is_(None),
                    AiEvaluation.tenant_id == principal.tenant_id,
                )
            ).order_by(AiEvaluation.created_at.desc()).limit(200)
        )
    ).scalars().all()
    return {"data": [row(item) for item in items]}


@router.post("/ai/evaluations", status_code=status.HTTP_201_CREATED)
async def create_evaluation(
    payload: EvaluationCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> dict:
    expected = set(payload.expected_refs)
    actual = set(payload.actual_refs)
    score = len(expected & actual) / len(expected) if expected else None
    item = AiEvaluation(
        tenant_id=principal.tenant_id,
        question=payload.question,
        expected_refs=payload.expected_refs,
        actual_refs=payload.actual_refs,
        grounded=bool(actual),
        score=score,
        model=payload.model,
        detail={"metric": "reference_recall"},
    )
    db.add(item)
    await db.flush()
    return row(item)


@router.get("/detection-rules")
async def detection_rules(db: DbSession, principal: ReadPrincipal) -> dict:
    items = (
        await db.execute(
            select(DetectionRule)
            .where(DetectionRule.tenant_id == principal.tenant_id)
            .order_by(DetectionRule.updated_at.desc())
        )
    ).scalars().all()
    return {"data": [row(item) for item in items]}


@router.post("/detection-rules", status_code=status.HTTP_201_CREATED)
async def create_detection(
    payload: DetectionCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> dict:
    checks = {"non_empty": bool(payload.content.strip()), "format": payload.rule_format, "validated": False}
    item = DetectionRule(
        tenant_id=principal.tenant_id,
        name=payload.name,
        rule_format=payload.rule_format,
        content=payload.content,
        version=payload.version,
        status="draft",
        attack_techniques=payload.attack_techniques,
        validation=checks,
        author=actor(principal),
    )
    db.add(item)
    await db.flush()
    return row(item)
