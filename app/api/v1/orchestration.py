"""Approval-first orchestration APIs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.schemas import ListResponse, Page
from app.core.config import Settings, get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.orchestration_models import AutomationOutbox, AutomationPlaybook, AutomationRun
from app.services.capabilities import (
    ALL_ACTIONS,
    all_enabled_actions,
    build_capability_registry,
    connector_health,
)
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]

#: Legacy alias — kept for backward compat in the playbook validator.
_ALLOWED_ACTIONS = ALL_ACTIONS


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
    attempts: int
    replay_count: int
    created_at: datetime


class CapabilityOut(BaseModel):
    action: str
    connector_type: str
    enabled: bool
    config_state: str
    config_reason: str


class ConnectorHealthOut(BaseModel):
    action: str
    connector_type: str
    status: str
    config_state: str
    config_reason: str
    active_probe: str


class OutboxStateCountsOut(BaseModel):
    queued: int = 0
    delivering: int = 0
    retry: int = 0
    dead_letter: int = 0
    delivered: int = 0
    oldest_queued_seconds: float | None = None


class HealthSummaryOut(BaseModel):
    capabilities: list[CapabilityOut]
    connectors: list[ConnectorHealthOut]
    outbox: OutboxStateCountsOut


class ReplayRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


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
    invalid = [step.action for step in payload.steps if step.action not in _ALLOWED_ACTIONS]
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

    required = (
        2 if any(step.get("action") == "endpoint.command.request" for step in playbook.steps) else 1
    )
    run = AutomationRun(
        tenant_id=principal.tenant_id,
        playbook_id=playbook.id,
        source_type=payload.source_type,
        source_id=payload.source_id,
        idempotency_key=payload.idempotency_key,
        context=payload.context,
        requested_by=_actor(principal),
        required_approvals=required,
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
async def dispatch_run(
    run_id: str,
    db: DbSession,
    principal: WritePrincipal,
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[OutboxOut]:
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

    # Reject dispatch if any step uses an action that is not currently enabled.
    # This covers both unconfigured delivery adapters and unimplemented internal
    # actions (case.create, report.generate, endpoint.command.request are all
    # enabled=False / config_state="planned" until their workers are integrated).
    available = all_enabled_actions(settings)
    unavailable = [
        step["action"]
        for step in playbook.steps
        if step["action"] not in available
    ]
    if unavailable:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": (
                    "Dispatch rejected: the following action(s) are not currently available. "
                    "Configure the required connector or wait for the worker implementation "
                    "before dispatching."
                ),
                "unavailable_actions": sorted(set(unavailable)),
            },
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


# ---------------------------------------------------------------------------
# Capability registry and operational health
# ---------------------------------------------------------------------------


@router.get("/orchestration/capabilities", response_model=list[CapabilityOut])
async def list_capabilities(
    principal: ReadPrincipal,
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[CapabilityOut]:
    """Return the capability registry derived from configured adapters.

    Safe metadata only — no URLs, tokens, or secrets are included.
    """
    entries = build_capability_registry(settings)
    return [
        CapabilityOut(
            action=e.action,
            connector_type=e.connector_type,
            enabled=e.enabled,
            config_state=e.config_state,
            config_reason=e.config_reason,
        )
        for e in entries
    ]


@router.get("/orchestration/health", response_model=HealthSummaryOut)
async def orchestration_health(
    db: DbSession,
    principal: ReadPrincipal,
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthSummaryOut:
    """Return operational health summary for the orchestration subsystem.

    Outbox counts are scoped to the calling tenant — cross-tenant data is
    never included.
    """
    capabilities = [
        CapabilityOut(
            action=e.action,
            connector_type=e.connector_type,
            enabled=e.enabled,
            config_state=e.config_state,
            config_reason=e.config_reason,
        )
        for e in build_capability_registry(settings)
    ]
    connectors = [ConnectorHealthOut(**h) for h in connector_health(settings)]

    # Outbox counts — tenant-scoped
    state_counts_result = await db.execute(
        select(AutomationOutbox.state, func.count(AutomationOutbox.id))
        .where(AutomationOutbox.tenant_id == principal.tenant_id)
        .group_by(AutomationOutbox.state)
    )
    counts: dict[str, int] = {row[0]: row[1] for row in state_counts_result.all()}

    # Oldest queued/retry item age (seconds since created_at)
    oldest_result = await db.execute(
        select(func.min(AutomationOutbox.created_at))
        .where(
            AutomationOutbox.tenant_id == principal.tenant_id,
            AutomationOutbox.state.in_(["queued", "retry"]),
        )
    )
    oldest_dt: datetime | None = oldest_result.scalar_one_or_none()
    oldest_age: float | None = None
    if oldest_dt is not None:
        now = datetime.now(UTC)
        if oldest_dt.tzinfo is None:

            oldest_dt = oldest_dt.replace(tzinfo=UTC)
        oldest_age = (now - oldest_dt).total_seconds()

    outbox = OutboxStateCountsOut(
        queued=counts.get("queued", 0),
        delivering=counts.get("delivering", 0),
        retry=counts.get("retry", 0),
        dead_letter=counts.get("dead_letter", 0),
        delivered=counts.get("delivered", 0),
        oldest_queued_seconds=oldest_age,
    )
    return HealthSummaryOut(capabilities=capabilities, connectors=connectors, outbox=outbox)


# ---------------------------------------------------------------------------
# Dead-letter replay
# ---------------------------------------------------------------------------


@router.post(
    "/automation-outbox/{outbox_id}/replay",
    response_model=OutboxOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def replay_dead_letter(
    outbox_id: str,
    payload: ReplayRequest,
    db: DbSession,
    principal: WritePrincipal,
) -> OutboxOut:
    """Re-queue a dead-lettered outbox item for delivery.

    Rules:
    * Caller must hold write scope.
    * The item must belong to the calling tenant.
    * Only items in ``dead_letter`` state may be replayed.
    * ``endpoint.command.request`` actions are never replayed automatically;
      a new run with fresh approvals is required.
    * A new idempotency key is generated to prevent duplicate remote
      side effects from the original delivery attempt.
    * Attempt counter is reset so retry back-off starts fresh.
    * Replay audit data (actor, timestamp, reason, previous idempotency key)
      is appended to ``replay_history``.
    """
    item = (
        await db.execute(
            select(AutomationOutbox).where(
                AutomationOutbox.id == outbox_id,
                AutomationOutbox.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Outbox item not found.")

    if item.state != "dead_letter":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only dead_letter items may be replayed; current state is '{item.state}'.",
        )

    if item.action == "endpoint.command.request":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "endpoint.command.request actions cannot be replayed automatically. "
            "Create a new automation run with fresh approvals.",
        )


    original_key = item.idempotency_key
    new_key = f"{original_key}:replay:{item.replay_count + 1}"

    audit_entry = {
        "actor": _actor(principal),
        "replayed_at": datetime.now(UTC).isoformat(),
        "reason": payload.reason,
        "previous_idempotency_key": original_key,
        "previous_attempts": item.attempts,
    }

    item.idempotency_key = new_key
    item.state = "queued"
    item.attempts = 0
    item.last_error = None
    item.available_at = None
    item.lease_token = None
    item.lease_until = None
    item.delivery_result = None
    item.replay_count = item.replay_count + 1
    item.replay_history = [*item.replay_history, audit_entry]

    await db.flush()
    return OutboxOut.model_validate(item)
