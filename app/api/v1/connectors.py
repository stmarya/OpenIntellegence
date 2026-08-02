"""Connector capability, health, and dead-letter replay APIs.

Phase 4 — Capability registry endpoint.
Phase 5 — Connector health state, delivery metrics, dead-letter replay.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select

from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.orchestration_models import AutomationOutbox
from app.workers.capability_registry import ActionCapability, capability_registry

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------


class CapabilityOut(BaseModel):
    action: str
    kind: str
    enabled: bool
    description: str


class ConnectorHealthOut(BaseModel):
    action: str
    kind: str
    enabled: bool
    total: int
    delivered: int
    delivering: int
    dead_letter: int
    retry: int
    queued: int


class ReplayRequest(BaseModel):
    note: str | None = None


class OutboxOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    step_index: int
    action: str
    target: str
    state: str
    idempotency_key: str
    attempts: int
    last_error: str | None = None
    replayed_from_id: str | None = None
    replayed_by: str | None = None
    replayed_at: datetime | None = None
    replay_note: str | None = None
    created_at: datetime


def _cap_out(cap: ActionCapability) -> CapabilityOut:
    return CapabilityOut(
        action=cap.action,
        kind=cap.kind,
        enabled=cap.enabled,
        description=cap.description,
    )


def _actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


# ---------------------------------------------------------------------------
# Phase 4: Capability registry
# ---------------------------------------------------------------------------


@router.get(
    "/connectors/capabilities",
    response_model=list[CapabilityOut],
    summary="List all known action adapters and their enablement state",
)
async def list_capabilities(principal: ReadPrincipal) -> list[CapabilityOut]:
    """Return every registered action with its kind and enabled flag.

    A playbook step whose action is *not* enabled here will be rejected at
    creation time and again at dispatch time — it will never be silently
    queued for an unavailable adapter.
    """
    return [_cap_out(c) for c in capability_registry.all_capabilities()]


# ---------------------------------------------------------------------------
# Phase 5: Connector health
# ---------------------------------------------------------------------------


@router.get(
    "/connectors/health",
    response_model=list[ConnectorHealthOut],
    summary="Per-action delivery metrics across the automation outbox",
)
async def connector_health(db: DbSession, principal: ReadPrincipal) -> list[ConnectorHealthOut]:
    """Aggregate outbox state counts per action.

    Returned for every registered action, even those with no outbox rows yet,
    so an absent action does not hide its zero-delivery state.
    """
    # Aggregate outbox counts per (action, state) for the requesting tenant only.
    stmt = (
        select(AutomationOutbox.action, AutomationOutbox.state, func.count())
        .where(AutomationOutbox.tenant_id == principal.tenant_id)
        .group_by(AutomationOutbox.action, AutomationOutbox.state)
    )
    rows = (await db.execute(stmt)).all()

    # Build a nested dict: action → state → count
    counts: dict[str, dict[str, int]] = {}
    for action, state, n in rows:
        counts.setdefault(action, {})[state] = n

    result: list[ConnectorHealthOut] = []
    for cap in capability_registry.all_capabilities():
        c = counts.get(cap.action, {})
        delivered = c.get("delivered", 0)
        delivering = c.get("delivering", 0)
        dead_letter = c.get("dead_letter", 0)
        retry = c.get("retry", 0)
        queued = c.get("queued", 0)
        # total is the sum of all known states so it is always internally
        # consistent, including any future states that share the same prefix.
        total = delivered + delivering + dead_letter + retry + queued
        result.append(
            ConnectorHealthOut(
                action=cap.action,
                kind=cap.kind,
                enabled=cap.enabled,
                total=total,
                delivered=delivered,
                delivering=delivering,
                dead_letter=dead_letter,
                retry=retry,
                queued=queued,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Phase 5: Dead-letter replay
# ---------------------------------------------------------------------------


@router.post(
    "/automation-outbox/{item_id}/replay",
    response_model=OutboxOut,
    status_code=status.HTTP_201_CREATED,
    summary="Replay a dead_letter outbox item",
)
async def replay_outbox_item(
    item_id: str,
    payload: ReplayRequest,
    db: DbSession,
    principal: WritePrincipal,
) -> OutboxOut:
    """Re-queue a dead_letter item for delivery.

    Idempotency: a second call for the same *item_id* returns the existing
    replay record rather than creating a duplicate.

    Audit: the replaying actor is recorded on the new outbox row.  The
    original dead_letter row is left unchanged as the immutable failure
    record.
    """
    original = (
        await db.execute(
            select(AutomationOutbox).where(
                AutomationOutbox.id == item_id,
                AutomationOutbox.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if original is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Outbox item not found.")

    if original.state != "dead_letter":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only dead_letter items may be replayed; current state is '{original.state}'.",
        )

    # Idempotency: check whether a replay already exists for this item.
    existing_replay = (
        await db.execute(
            select(AutomationOutbox).where(
                AutomationOutbox.replayed_from_id == item_id,
                AutomationOutbox.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if existing_replay is not None:
        return OutboxOut.model_validate(existing_replay)

    # Validate the action is still available before queuing.
    if not capability_registry.is_enabled(original.action):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Action '{original.action}' is no longer enabled; cannot replay.",
        )

    actor = _actor(principal)
    replay = AutomationOutbox(
        tenant_id=original.tenant_id,
        run_id=original.run_id,
        step_index=original.step_index,
        action=original.action,
        target=original.target,
        payload=original.payload,
        # New idempotency key for the replay so it is processed independently.
        idempotency_key=f"{original.idempotency_key}:replay",
        replayed_from_id=original.id,
        replayed_by=actor,
        replayed_at=datetime.now(UTC),
        replay_note=payload.note,
    )
    db.add(replay)
    await db.flush()
    return OutboxOut.model_validate(replay)


# ---------------------------------------------------------------------------
# Dead-letter listing (convenience for operators)
# ---------------------------------------------------------------------------


@router.get(
    "/automation-outbox/dead-letter",
    response_model=list[OutboxOut],
    summary="List dead_letter outbox items eligible for replay",
)
async def list_dead_letter(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[OutboxOut]:
    stmt = (
        select(AutomationOutbox)
        .where(
            and_(
                AutomationOutbox.state == "dead_letter",
                AutomationOutbox.tenant_id == principal.tenant_id,
            )
        )
        .order_by(AutomationOutbox.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [OutboxOut.model_validate(r) for r in rows]
