"""Approval-first orchestration APIs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.schemas import ListResponse, Page
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.orchestration_models import AutomationOutbox, AutomationPlaybook, AutomationRun
from app.services.provenance import build_provenance
from app.workers.connector_delivery import P0_DELIVERABLE_ACTIONS, enabled_delivery_actions

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


def _allowed_actions() -> frozenset[str]:
    # Explicit P0 capability boundary until a dedicated capability registry lands.
    return P0_DELIVERABLE_ACTIONS


def _configured_actions() -> frozenset[str]:
    return enabled_delivery_actions(get_settings())


def _unconfigured_actions(steps: list[dict], configured: frozenset[str]) -> list[str]:
    return sorted(
        {
            step["action"]
            for step in steps
            if isinstance(step, dict) and step.get("action") not in configured
        }
    )


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PlaybookStep(BaseModel):
    action: str
    target: str = Field(min_length=2, max_length=128)
    payload: dict = Field(default_factory=dict)


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    description: str | None = None
    trigger_type: Literal["correlation", "alert", "sighting", "manual"]
    steps: list[PlaybookStep] = Field(min_length=1, max_length=20)


class PlaybookOut(ORM):
    id: str
    name: str
    description: str | None = None
    trigger_type: str
    steps: list
    enabled: bool
    created_at: datetime


class RunCreate(BaseModel):
    playbook_id: str
    source_type: str = Field(min_length=2, max_length=64)
    source_id: str = Field(min_length=1, max_length=255)
    idempotency_key: str = Field(min_length=8, max_length=255)
    context: dict = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class RunOut(ORM):
    id: str
    playbook_id: str
    source_type: str
    source_id: str
    state: str
    required_approvals: int
    approvals: list
    context: dict
    requested_by: str
    rejected_reason: str | None = None
    dispatched_at: datetime | None = None
    created_at: datetime


class OutboxOut(ORM):
    id: str
    run_id: str
    step_index: int
    action: str
    target: str
    state: str
    idempotency_key: str
    created_at: datetime


def _actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


@router.get("/playbooks", response_model=ListResponse[PlaybookOut])
async def list_playbooks(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[PlaybookOut]:
    stmt = select(AutomationPlaybook).where(AutomationPlaybook.tenant_id == principal.tenant_id)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(AutomationPlaybook.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ListResponse(
        data=[PlaybookOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.post("/playbooks", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate, db: DbSession, principal: WritePrincipal
) -> PlaybookOut:
    invalid = [step.action for step in payload.steps if step.action not in _allowed_actions()]
    if invalid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unsupported action(s): {', '.join(invalid)}",
        )

    item = AutomationPlaybook(
        tenant_id=principal.tenant_id,
        name=payload.name,
        description=payload.description,
        trigger_type=payload.trigger_type,
        steps=[x.model_dump() for x in payload.steps],
    )
    db.add(item)
    await db.flush()
    return PlaybookOut.model_validate(item)


@router.post("/automation-runs", response_model=RunOut, status_code=status.HTTP_201_CREATED)
async def propose_run(payload: RunCreate, db: DbSession, principal: WritePrincipal) -> RunOut:
    existing = (
        await db.execute(
            select(AutomationRun).where(
                AutomationRun.tenant_id == principal.tenant_id,
                AutomationRun.idempotency_key == payload.idempotency_key,
            )
        )
    ).scalar_one_or_none()
    if existing:
        return RunOut.model_validate(existing)

    playbook = (
        await db.execute(
            select(AutomationPlaybook).where(
                AutomationPlaybook.id == payload.playbook_id,
                AutomationPlaybook.tenant_id == principal.tenant_id,
                AutomationPlaybook.enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Enabled playbook not found.")

    run = AutomationRun(
        tenant_id=principal.tenant_id,
        playbook_id=playbook.id,
        source_type=payload.source_type,
        source_id=payload.source_id,
        idempotency_key=payload.idempotency_key,
        context=payload.context,
        requested_by=_actor(principal),
        required_approvals=1,
    )
    db.add(run)
    await db.flush()
    return RunOut.model_validate(run)


@router.get("/automation-runs", response_model=ListResponse[RunOut])
async def list_runs(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    run_state: Annotated[str | None, Query(alias="state")] = None,
) -> ListResponse[RunOut]:
    stmt = select(AutomationRun).where(AutomationRun.tenant_id == principal.tenant_id)
    if run_state:
        stmt = stmt.where(AutomationRun.state == run_state)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(AutomationRun.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ListResponse(
        data=[RunOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.post("/automation-runs/{run_id}/approve", response_model=RunOut)
async def approve_run(
    run_id: str, payload: ApprovalRequest, db: DbSession, principal: WritePrincipal
) -> RunOut:
    run = (
        await db.execute(
            select(AutomationRun).where(
                AutomationRun.id == run_id, AutomationRun.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Automation run not found.")
    if run.state not in {"proposed", "partially_approved"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run is not awaiting approval.")

    actor = _actor(principal)
    if any(entry["actor"] == actor for entry in run.approvals):
        raise HTTPException(status.HTTP_409_CONFLICT, "This approver has already approved the run.")

    run.approvals = [
        *run.approvals,
        {"actor": actor, "note": payload.note, "approved_at": datetime.now(UTC).isoformat()},
    ]
    run.state = "approved" if len(run.approvals) >= run.required_approvals else "partially_approved"
    await db.flush()
    return RunOut.model_validate(run)


@router.post("/automation-runs/{run_id}/reject", response_model=RunOut)
async def reject_run(
    run_id: str, payload: ApprovalRequest, db: DbSession, principal: WritePrincipal
) -> RunOut:
    run = (
        await db.execute(
            select(AutomationRun).where(
                AutomationRun.id == run_id, AutomationRun.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Automation run not found.")
    if run.state not in {"proposed", "partially_approved"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Run cannot be rejected in its current state."
        )

    run.state = "rejected"
    run.rejected_reason = payload.note or "Rejected by approver."
    await db.flush()
    return RunOut.model_validate(run)


@router.post(
    "/automation-runs/{run_id}/dispatch",
    response_model=list[OutboxOut],
    status_code=status.HTTP_202_ACCEPTED,
)
async def dispatch_run(run_id: str, db: DbSession, principal: WritePrincipal) -> list[OutboxOut]:
    run = (
        await db.execute(
            select(AutomationRun).where(
                AutomationRun.id == run_id, AutomationRun.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Automation run not found.")

    if run.state == "dispatched":
        rows = (
            (
                await db.execute(
                    select(AutomationOutbox)
                    .where(AutomationOutbox.run_id == run.id)
                    .order_by(AutomationOutbox.step_index)
                )
            )
            .scalars()
            .all()
        )
        return [OutboxOut.model_validate(x) for x in rows]

    if run.state != "approved":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only fully approved runs may be dispatched.")

    playbook = await db.get(AutomationPlaybook, run.playbook_id)
    if playbook is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Playbook is unavailable.")
    configured = _configured_actions()
    unavailable = _unconfigured_actions(playbook.steps, configured)
    if unavailable:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Delivery connector is not configured for action(s): {', '.join(unavailable)}",
        )

    items = []
    for index, step in enumerate(playbook.steps):
        item = AutomationOutbox(
            tenant_id=run.tenant_id,
            run_id=run.id,
            step_index=index,
            action=step["action"],
            target=step["target"],
            payload={"run_context": run.context, "step_payload": step.get("payload", {})},
            idempotency_key=f"{run.id}:{index}",
        )
        db.add(item)
        items.append(item)

    run.state = "dispatched"
    run.dispatched_at = datetime.now(UTC)
    await db.flush()
    return [OutboxOut.model_validate(x) for x in items]
