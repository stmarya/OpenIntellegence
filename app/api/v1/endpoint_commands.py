"""Endpoint command intent control plane — Stage 4.

Request lifecycle only.  No endpoint delivery, no mTLS transport, no shell
execution, no connector outbox action.

State machine (all transitions are explicit):
  proposed  ──approve(1st)──►  partially_approved
            ──approve(2nd)──►  approved        (when required_approvals==1, goes straight to approved)
            ──reject        ──►  rejected        (terminal)
            ──cancel        ──►  cancelled       (terminal)
            ──expiry check  ──►  expired         (terminal, enforced on read/mutate)

  partially_approved:
            ──approve(Nth)  ──►  approved
            ──reject        ──►  rejected
            ──cancel        ──►  cancelled
            ──expiry check  ──►  expired

  approved:
            ──cancel        ──►  cancelled       (admin cancel only in this release)

API-key identity limitation
---------------------------
The current implementation records ``api_key:<id>`` as the actor identity.
This means requester-exclusion and the two-person rule are enforced using
API key IDs only; two operations from the same physical person using different
keys would not be detected.  Production separation of duties requires
OIDC/RBAC subjects with verified identity binding.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ListResponse, Page
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.endpoint_models import ENDPOINT_INTENT_ALLOWLIST, REQUIRED_APPROVALS, EndpointCommandIntent
from app.db.models import Agent, Asset
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class IntentCreate(BaseModel):
    """Create a new endpoint command intent.

    At least one of target_asset_id / target_agent_id must be supplied.
    If both are supplied their linkage (agent.asset_id == target_asset_id)
    is validated.
    """

    target_asset_id: str | None = Field(default=None, max_length=36)
    target_agent_id: str | None = Field(default=None, max_length=36)
    reason: str = Field(min_length=10, max_length=4000)
    intent_type: str = Field(min_length=2, max_length=64)
    parameters: dict = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=255)
    expires_at: datetime | None = None


class ApprovalRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=4000)


class CancelRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class IntentOut(ORM):
    id: str
    tenant_id: str
    target_asset_id: str | None = None
    target_agent_id: str | None = None
    requester: str
    reason: str
    intent_type: str
    parameters: dict
    state: str
    idempotency_key: str
    required_approvals: int
    approvals: list
    audit_timeline: list
    requested_at: datetime
    expires_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancellation_note: str | None = None
    cancelled_by: str | None = None
    rejected_reason: str | None = None
    rejected_by: str | None = None
    rejected_at: datetime | None = None
    # Delivery placeholders — always null in this release.
    delivered_at: datetime | None = None
    delivery_receipt: dict | None = None
    created_at: datetime

    # Remind callers that this is pending / not dispatched.
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "x-delivery-note": (
                "Approved intents are NOT automatically delivered. "
                "Delivery requires a separate, out-of-scope integration. "
                "delivered_at and delivery_receipt will be null in this release."
            )
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


def _now() -> datetime:
    return datetime.now(UTC)


def _append_timeline(intent: EndpointCommandIntent, event: str, actor: str, detail: str) -> None:
    intent.audit_timeline = [
        *intent.audit_timeline,
        {"event": event, "actor": actor, "at": _now().isoformat(), "detail": detail},
    ]


def _check_expiry(intent: EndpointCommandIntent) -> None:
    """Transition to expired if the intent has passed its expiry timestamp."""
    if intent.expires_at is None:
        return
    now = _now()
    expires = intent.expires_at if intent.expires_at.tzinfo else intent.expires_at.replace(tzinfo=UTC)
    if expires <= now and intent.state not in {"rejected", "cancelled", "expired"}:
        intent.state = "expired"
        _append_timeline(intent, "expired", "system", "Intent expired at its scheduled expiry time.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/endpoint-command-intents",
    response_model=IntentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_intent(
    payload: IntentCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> IntentOut:
    """Create a new endpoint command intent.

    Strict allowlist: intent_type must be from the published set.
    At least one target must be supplied; both are validated for tenant
    ownership.  If both asset and agent are given, their linkage is checked.

    The created intent is in 'proposed' state.  AI output cannot trigger
    delivery.  Two distinct approvers are required (requester excluded).
    """
    if payload.intent_type not in ENDPOINT_INTENT_ALLOWLIST:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"intent_type '{payload.intent_type}' is not in the allowlist. "
            f"Permitted values: {sorted(ENDPOINT_INTENT_ALLOWLIST)}",
        )

    if payload.target_asset_id is None and payload.target_agent_id is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "At least one of target_asset_id or target_agent_id must be supplied.",
        )

    # Idempotency check.
    existing = (
        await db.execute(
            select(EndpointCommandIntent).where(
                EndpointCommandIntent.tenant_id == principal.tenant_id,
                EndpointCommandIntent.idempotency_key == payload.idempotency_key,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        _check_expiry(existing)
        return IntentOut.model_validate(existing)

    # Validate asset ownership.
    if payload.target_asset_id is not None:
        asset = (
            await db.execute(
                select(Asset).where(
                    Asset.id == payload.target_asset_id,
                    Asset.tenant_id == principal.tenant_id,
                )
            )
        ).scalar_one_or_none()
        if asset is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "target_asset_id does not exist or does not belong to this tenant.",
            )

    # Validate agent ownership.
    agent: Agent | None = None
    if payload.target_agent_id is not None:
        agent = (
            await db.execute(
                select(Agent).where(
                    Agent.id == payload.target_agent_id,
                    Agent.tenant_id == principal.tenant_id,
                )
            )
        ).scalar_one_or_none()
        if agent is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "target_agent_id does not exist or does not belong to this tenant.",
            )

    # If both are supplied, validate linkage.
    if payload.target_asset_id is not None and payload.target_agent_id is not None:
        if agent is not None and agent.asset_id != payload.target_asset_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "The supplied agent is not linked to the supplied asset.",
            )

    actor = _actor(principal)
    now = _now()

    intent = EndpointCommandIntent(
        tenant_id=principal.tenant_id,
        target_asset_id=payload.target_asset_id,
        target_agent_id=payload.target_agent_id,
        requester=actor,
        reason=payload.reason,
        intent_type=payload.intent_type,
        parameters=payload.parameters,
        state="proposed",
        idempotency_key=payload.idempotency_key,
        required_approvals=REQUIRED_APPROVALS,
        approvals=[],
        audit_timeline=[
            {"event": "created", "actor": actor, "at": now.isoformat(), "detail": "Intent proposed."}
        ],
        requested_at=now,
        expires_at=payload.expires_at,
    )
    db.add(intent)
    await db.flush()
    await db.refresh(intent)
    return IntentOut.model_validate(intent)


@router.get("/endpoint-command-intents", response_model=ListResponse[IntentOut])
async def list_intents(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    state: Annotated[str | None, Query()] = None,
) -> ListResponse[IntentOut]:
    stmt = select(EndpointCommandIntent).where(
        EndpointCommandIntent.tenant_id == principal.tenant_id
    )
    if state:
        stmt = stmt.where(EndpointCommandIntent.state == state)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(EndpointCommandIntent.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    for intent in rows:
        _check_expiry(intent)
    return ListResponse(
        data=[IntentOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/endpoint-command-intents/{intent_id}", response_model=IntentOut)
async def get_intent(
    intent_id: str,
    db: DbSession,
    principal: ReadPrincipal,
) -> IntentOut:
    intent = (
        await db.execute(
            select(EndpointCommandIntent).where(
                EndpointCommandIntent.id == intent_id,
                EndpointCommandIntent.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Intent not found.")
    _check_expiry(intent)
    return IntentOut.model_validate(intent)


@router.post("/endpoint-command-intents/{intent_id}/approve", response_model=IntentOut)
async def approve_intent(
    intent_id: str,
    payload: ApprovalRequest,
    db: DbSession,
    principal: WritePrincipal,
) -> IntentOut:
    """Approve an endpoint command intent.

    Enforces:
    - Requester cannot approve their own intent.
    - Each approver can only approve once.
    - Requires two distinct approvers (REQUIRED_APPROVALS == 2).
    """
    intent = (
        await db.execute(
            select(EndpointCommandIntent).where(
                EndpointCommandIntent.id == intent_id,
                EndpointCommandIntent.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Intent not found.")

    _check_expiry(intent)
    if intent.state not in {"proposed", "partially_approved"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Intent is not awaiting approval; current state is '{intent.state}'.",
        )

    actor = _actor(principal)

    # Requester exclusion: the requester cannot approve their own intent.
    if actor == intent.requester:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The requester cannot approve their own intent.",
        )

    # Each approver can only vote once.
    if any(entry["actor"] == actor for entry in intent.approvals):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This approver has already approved the intent.",
        )

    now = _now()
    new_approval = {"actor": actor, "approved_at": now.isoformat(), "note": payload.note}
    intent.approvals = [*intent.approvals, new_approval]
    _append_timeline(intent, "approved", actor, payload.note or "Approved.")

    if len(intent.approvals) >= intent.required_approvals:
        intent.state = "approved"
    else:
        intent.state = "partially_approved"

    await db.flush()
    return IntentOut.model_validate(intent)


@router.post("/endpoint-command-intents/{intent_id}/reject", response_model=IntentOut)
async def reject_intent(
    intent_id: str,
    payload: RejectRequest,
    db: DbSession,
    principal: WritePrincipal,
) -> IntentOut:
    intent = (
        await db.execute(
            select(EndpointCommandIntent).where(
                EndpointCommandIntent.id == intent_id,
                EndpointCommandIntent.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Intent not found.")

    _check_expiry(intent)
    if intent.state not in {"proposed", "partially_approved"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Intent cannot be rejected in its current state ('{intent.state}').",
        )

    actor = _actor(principal)
    intent.state = "rejected"
    intent.rejected_reason = payload.reason
    intent.rejected_by = actor
    intent.rejected_at = _now()
    _append_timeline(intent, "rejected", actor, payload.reason)

    await db.flush()
    return IntentOut.model_validate(intent)


@router.post("/endpoint-command-intents/{intent_id}/cancel", response_model=IntentOut)
async def cancel_intent(
    intent_id: str,
    payload: CancelRequest,
    db: DbSession,
    principal: WritePrincipal,
) -> IntentOut:
    """Cancel an endpoint command intent.

    Proposed, partially_approved, and approved intents may be cancelled.
    Cancellation uses a dedicated cancellation_note field and does NOT
    populate rejected_reason to avoid ambiguity.

    An admin can cancel an approved intent; the cancellation is recorded
    with the admin's actor identity (not misattributed to the requester).
    """
    intent = (
        await db.execute(
            select(EndpointCommandIntent).where(
                EndpointCommandIntent.id == intent_id,
                EndpointCommandIntent.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if intent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Intent not found.")

    _check_expiry(intent)
    if intent.state in {"rejected", "cancelled", "expired"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Intent is already in a terminal state ('{intent.state}').",
        )

    actor = _actor(principal)
    now = _now()
    intent.state = "cancelled"
    intent.cancelled_at = now
    intent.cancellation_note = payload.note
    intent.cancelled_by = actor
    _append_timeline(intent, "cancelled", actor, payload.note or "Cancelled.")

    await db.flush()
    return IntentOut.model_validate(intent)
