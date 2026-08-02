"""Approval-first orchestration APIs.

Includes:
- Capability / health registry (Stage 3)
- Dead-letter replay with row-locking (Stage 3)
- Playbook / run / dispatch management
"""

from __future__ import annotations

from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ListResponse, Page
from app.core.config import Settings, get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.orchestration_models import (
    AutomationOutbox,
    AutomationOutboxReplayHistory,
    AutomationPlaybook,
    AutomationRun,
)
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]

# Actions with enabled delivery workers (connector or internal).
_ALLOWED_ACTIONS = {
    "slack.notify",
    "jira.issue.create",
    "siem.push",
    "case.create",
    "report.generate",
}

# Actions with no delivery worker in this release.
# Accepting them would produce undeliverable outbox records.
_DEFERRED_ACTIONS = {
    "endpoint.command.request",
}

# Action kinds — used by the capability registry to describe handler types.
_CONNECTOR_ACTIONS = {"slack.notify", "jira.issue.create", "siem.push"}
_INTERNAL_ACTIONS = {"case.create", "report.generate"}

# Settings fields that determine whether a connector is configured.
_CONNECTOR_CONFIGURED_CHECK: dict[str, list[str]] = {
    "slack.notify": ["slack_webhook_url"],
    "jira.issue.create": ["jira_base_url", "jira_email", "jira_api_token"],
    "siem.push": ["siem_webhook_url"],
}


def _connector_configured(action: str, settings: Settings) -> bool:
    fields = _CONNECTOR_CONFIGURED_CHECK.get(action, [])
    return all(getattr(settings, f, None) is not None for f in fields)


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
    attempts: int | None = None
    last_error: str | None = None
    created_at: datetime


# ---------------------------------------------------------------------------
# Capability / health schemas (Stage 3)
# ---------------------------------------------------------------------------


class CapabilityOut(BaseModel):
    action: str
    handler_type: str
    state: str
    reason: str | None = None


class OutboxStateCounts(BaseModel):
    queued: int = 0
    retry: int = 0
    delivering: int = 0
    dead_letter: int = 0
    delivered: int = 0


class OutboxHealthOut(BaseModel):
    counts: OutboxStateCounts
    oldest_queued_age_seconds: float | None = None


class ReplayOut(ORM):
    id: str
    run_id: str
    step_index: int
    action: str
    target: str
    state: str
    idempotency_key: str
    attempts: int | None = None
    last_error: str | None = None
    created_at: datetime


def _actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


def _invalid_actions_from_steps(steps: list) -> list[str]:
    invalid: list[str] = []
    for step in steps:
        action = step.get("action") if isinstance(step, dict) else None
        if action not in _ALLOWED_ACTIONS:
            invalid.append(str(action))
    return list(dict.fromkeys(invalid))


def _raise_for_invalid_actions(invalid_actions: list[str]) -> None:
    if invalid_actions:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unsupported action(s): {', '.join(invalid_actions)}",
        )


# ---------------------------------------------------------------------------
# Capability registry (Stage 3)
# ---------------------------------------------------------------------------


@router.get("/capabilities", response_model=list[CapabilityOut])
async def list_capabilities(
    settings: Annotated[Settings, Depends(get_settings)],
    principal: ReadPrincipal,
) -> list[CapabilityOut]:
    """Return safe capability metadata for all known actions.

    Only action name, handler type, configured/unconfigured state, and an
    optional human-readable reason are returned.  URLs, tokens, SecretStr
    values, and secret-derived content are never included.
    """
    result: list[CapabilityOut] = []

    for action in sorted(_CONNECTOR_ACTIONS):
        configured = _connector_configured(action, settings)
        result.append(
            CapabilityOut(
                action=action,
                handler_type="connector",
                state="enabled" if configured else "unconfigured",
                reason=None if configured else "Connector credentials are not configured.",
            )
        )

    for action in sorted(_INTERNAL_ACTIONS):
        result.append(
            CapabilityOut(
                action=action,
                handler_type="internal",
                state="enabled",
                reason=None,
            )
        )

    for action in sorted(_DEFERRED_ACTIONS):
        result.append(
            CapabilityOut(
                action=action,
                handler_type="planned",
                state="unavailable",
                reason="This action is not yet wired to a delivery worker.",
            )
        )

    return result


@router.get("/capabilities/health", response_model=OutboxHealthOut)
async def outbox_health(
    db: DbSession,
    principal: ReadPrincipal,
) -> OutboxHealthOut:
    """Return tenant-scoped outbox state counts and oldest queued age.

    Counts are bucketed by state: queued, retry, delivering, dead_letter,
    delivered.  The oldest_queued_age_seconds value is bounded and reflects
    the age of the oldest non-delivered, non-dead-letter record.

    No active network probes are performed.
    """
    state_col = AutomationOutbox.state
    count_stmt = (
        select(state_col, func.count().label("n"))
        .where(AutomationOutbox.tenant_id == principal.tenant_id)
        .group_by(state_col)
    )
    rows = (await db.execute(count_stmt)).all()
    counts = OutboxStateCounts()
    for row in rows:
        state_val, n = row[0], row[1]
        if state_val == "queued":
            counts.queued = n
        elif state_val == "retry":
            counts.retry = n
        elif state_val == "delivering":
            counts.delivering = n
        elif state_val == "dead_letter":
            counts.dead_letter = n
        elif state_val == "delivered":
            counts.delivered = n

    # Oldest item that is still in-flight (queued or retry).
    oldest_stmt = select(func.min(AutomationOutbox.created_at)).where(
        AutomationOutbox.tenant_id == principal.tenant_id,
        AutomationOutbox.state.in_(["queued", "retry"]),
    )
    oldest_ts = await db.scalar(oldest_stmt)
    oldest_age: float | None = None
    if oldest_ts is not None:
        now = datetime.now(UTC)
        ts = oldest_ts if oldest_ts.tzinfo else oldest_ts.replace(tzinfo=UTC)
        oldest_age = (now - ts).total_seconds()

    return OutboxHealthOut(counts=counts, oldest_queued_age_seconds=oldest_age)


# ---------------------------------------------------------------------------
# Dead-letter replay (Stage 3)
# ---------------------------------------------------------------------------


@router.post("/automation-outbox/{outbox_id}/replay", response_model=ReplayOut)
async def replay_dead_letter(
    outbox_id: str,
    db: DbSession,
    principal: WritePrincipal,
) -> ReplayOut:
    """Replay a single dead-lettered outbox record.

    The row is locked with SELECT FOR UPDATE so concurrent replay requests
    cannot duplicate or reuse idempotency keys.  A replay history record is
    written in the same transaction.

    Endpoint command actions (endpoint.command.request) are never replayed
    automatically.
    """
    # Lock the target row inside this transaction.
    locked_stmt = (
        select(AutomationOutbox)
        .where(
            AutomationOutbox.id == outbox_id,
            AutomationOutbox.tenant_id == principal.tenant_id,
        )
        .with_for_update()
    )
    item = (await db.execute(locked_stmt)).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Outbox record not found.")
    if item.state != "dead_letter":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only dead_letter records may be replayed; current state is '{item.state}'.",
        )
    if item.action in _DEFERRED_ACTIONS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Action '{item.action}' may not be replayed.",
        )

    actor = _actor(principal)
    original_key = item.idempotency_key
    new_key = f"{item.run_id}:{item.step_index}:replay:{token_urlsafe(12)}"

    history = AutomationOutboxReplayHistory(
        outbox_id=item.id,
        tenant_id=item.tenant_id,
        replayed_by=actor,
        original_idempotency_key=original_key,
        new_idempotency_key=new_key,
        replayed_at=datetime.now(UTC),
    )
    db.add(history)

    item.idempotency_key = new_key
    item.state = "queued"
    item.attempts = 0
    item.last_error = None
    item.available_at = None
    item.lease_token = None
    item.lease_until = None

    await db.flush()
    await db.refresh(item)
    return ReplayOut.model_validate(item)


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
    steps = [x.model_dump() for x in payload.steps]
    _raise_for_invalid_actions(_invalid_actions_from_steps(steps))

    item = AutomationPlaybook(
        tenant_id=principal.tenant_id,
        name=payload.name,
        description=payload.description,
        trigger_type=payload.trigger_type,
        steps=steps,
    )
    db.add(item)
    await db.flush()
    await db.refresh(item)
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
    _raise_for_invalid_actions(_invalid_actions_from_steps(playbook.steps))

    required = 1
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
    await db.refresh(run)
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
    _raise_for_invalid_actions(_invalid_actions_from_steps(playbook.steps))

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
    for item in items:
        await db.refresh(item)
    return [OutboxOut.model_validate(x) for x in items]
