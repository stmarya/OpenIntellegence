"""Read surfaces for detection content, collections, requirements, audit and policy."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from app.api.schemas import ListResponse, Page
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.endpoint_intent_models import EndpointIntent, EndpointIntentAudit
from app.db.governance_models import DetectionContent, IntelCollection, IntelligenceRequirement
from app.services.automation_capabilities import capabilities
from app.services.dead_letter_replay import NON_REPLAYABLE
from app.services.endpoint_intents import ALLOWED_INTENTS
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class DetectionContentOut(ORM):
    id: str
    name: str
    content_format: str
    external_id: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str
    attack_techniques: list = []
    data_sources: list = []
    version: str | None = None
    author: str | None = None
    last_validated_at: datetime | None = None


class CollectionOut(ORM):
    id: str
    name: str
    description: str | None = None
    purpose: str | None = None
    owner: str | None = None
    member_refs: list = []
    is_shared: bool
    last_curated_at: datetime | None = None


class RequirementOut(ORM):
    id: str
    code: str
    title: str
    description: str | None = None
    priority: str
    status: str
    owner: str | None = None
    covering_sources: list = []
    coverage_note: str | None = None
    review_due_at: datetime | None = None


class AuditEntryOut(BaseModel):
    id: str
    source: str
    subject: str
    subject_id: str
    actor: str
    event_type: str
    detail: dict
    event_at: datetime


async def _paginate(db: DbSession, stmt, limit: int, offset: int, order) -> tuple[list, int]:
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (await db.execute(stmt.order_by(order).limit(limit).offset(offset))).scalars().all()
    return list(rows), total


@router.get("/detection-content", response_model=ListResponse[DetectionContentOut])
async def list_detection_content(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: str | None = None,
) -> ListResponse[DetectionContentOut]:
    stmt = select(DetectionContent).where(DetectionContent.tenant_id == principal.tenant_id)
    if status:
        stmt = stmt.where(DetectionContent.status == status)
    rows, total = await _paginate(db, stmt, limit, offset, DetectionContent.name.asc())
    return ListResponse(
        data=[DetectionContentOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/collections", response_model=ListResponse[CollectionOut])
async def list_collections(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[CollectionOut]:
    stmt = select(IntelCollection).where(IntelCollection.tenant_id == principal.tenant_id)
    rows, total = await _paginate(db, stmt, limit, offset, IntelCollection.name.asc())
    return ListResponse(
        data=[CollectionOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/intelligence-requirements", response_model=ListResponse[RequirementOut])
async def list_requirements(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status: str | None = None,
) -> ListResponse[RequirementOut]:
    stmt = select(IntelligenceRequirement).where(IntelligenceRequirement.tenant_id == principal.tenant_id)
    if status:
        stmt = stmt.where(IntelligenceRequirement.status == status)
    rows, total = await _paginate(db, stmt, limit, offset, IntelligenceRequirement.code.asc())
    return ListResponse(
        data=[RequirementOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/audit-log", response_model=ListResponse[AuditEntryOut])
async def list_audit_log(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[AuditEntryOut]:
    """Return recorded audit events for this tenant.

    Coverage is deliberately limited to subsystems that actually persist audit
    rows. Presenting this as a complete account of platform activity would be
    a false assurance, so the provenance note names what is included.
    """
    stmt = (
        select(EndpointIntentAudit, EndpointIntent.intent_type, EndpointIntent.id)
        .join(EndpointIntent, EndpointIntent.id == EndpointIntentAudit.intent_id)
        .where(EndpointIntent.tenant_id == principal.tenant_id)
    )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(EndpointIntentAudit.event_at.desc()).limit(limit).offset(offset)
        )
    ).all()

    entries = [
        AuditEntryOut(
            id=audit.id,
            source="endpoint_intent",
            subject=intent_type,
            subject_id=intent_id,
            actor=audit.actor,
            event_type=audit.event_type,
            detail=audit.detail or {},
            event_at=audit.event_at,
        )
        for audit, intent_type, intent_id in rows
    ]

    provenance = await build_provenance(db, sources=None)
    provenance.note = (
        "Audit coverage currently spans endpoint intent control-plane events only. "
        "Other subsystems do not yet persist audit rows, so their absence here is a "
        "gap in recording rather than evidence that nothing happened."
    )
    return ListResponse(
        data=entries,
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=provenance,
    )


@router.get("/system-health", summary="Platform component state, probed and declared")
async def system_health(db: DbSession, principal: ReadPrincipal) -> dict:
    """Report component state, separating what was probed from what was declared.

    A component that is merely configured is never reported as healthy. The
    distinction matters because a monitoring gap and a working component look
    identical to a dashboard that does not draw the line.
    """
    settings = get_settings()
    components: list[dict] = []

    try:
        await db.scalar(select(1))
        components.append(
            {
                "component": "database",
                "state": "reachable",
                "observation": "probed",
                "detail": "A trivial query completed on the request session.",
            }
        )
    except Exception as exc:  # noqa: BLE001 - the failure itself is the finding
        components.append(
            {
                "component": "database",
                "state": "unreachable",
                "observation": "probed",
                "detail": f"The probe raised {type(exc).__name__}.",
            }
        )

    for name, attribute in (
        ("redis", "redis_url"),
        ("llm_provider", "llm_api_key"),
        ("embedding_provider", "embedding_model"),
    ):
        configured = bool(getattr(settings, attribute, None))
        components.append(
            {
                "component": name,
                "state": "configured" if configured else "not_configured",
                "observation": "declared",
                "detail": (
                    "Read from configuration only. No connection was attempted, so "
                    "this does not assert the component is reachable."
                ),
            }
        )

    return {
        "tenant_id": principal.tenant_id,
        "components": components,
        "note": (
            "Only components marked probed were contacted during this request. "
            "Ingestion connector state is reported separately on the connector "
            "surface and is not repeated here."
        ),
        "generated_at": datetime.now(UTC),
    }


@router.get("/settings")
async def get_policy_settings(principal: ReadPrincipal) -> dict:
    """Expose the policy constants that govern this workspace.

    Only decisions are returned. No credential, connection string, or secret
    value is read here, and capability state is derived from configuration
    without probing anything.
    """
    from app.api.v1.admin import GRANTABLE_SCOPES

    def scope_name(scope: object) -> str:
        return str(getattr(scope, "value", scope))

    return {
        "tenant_id": principal.tenant_id,
        "policy": {
            "grantable_api_key_scopes": sorted(scope_name(scope) for scope in GRANTABLE_SCOPES),
            "allowed_endpoint_intents": sorted(ALLOWED_INTENTS),
            "endpoint_command_delivery": "not_implemented",
            "required_intent_approvers": 2,
            "requester_may_approve": False,
            "non_replayable_actions": sorted(NON_REPLAYABLE),
        },
        "automation_capabilities": [item.as_dict() for item in capabilities(get_settings()).values()],
        "generated_at": datetime.now(UTC),
    }
