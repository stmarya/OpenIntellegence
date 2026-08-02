"""Endpoint command request control-plane APIs.

Design contract
---------------
This module creates, inspects, approves, rejects, and cancels *requests* to
send a command to an endpoint agent.  It does **not** execute commands,
dispatch instructions to agents, open network connections, or run shell code.
Every response that represents a live request explicitly states that it is
``pending`` and ``not_dispatched``.

Delivery limitation
-------------------
Even a fully-approved request remains in ``approved`` state and is never
forwarded to an agent.  Real delivery requires a signed mTLS channel
(separate repository) and an explicit dispatch layer that is out of scope
for this control-plane slice.

Approval-gate limitation
------------------------
Two distinct API-key identities are required.  Because callers authenticate
with API keys, the ``requester`` and ``approver`` tokens are ``api_key:<id>``
strings.  This is *not* equivalent to human / role separation of duties.  A
single human can hold two API keys and self-approve.  A production deployment
must enforce OIDC/SSO subject identity and RBAC-role gates before treating
two approvals as satisfying two-person-integrity.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from app.api.schemas import ListResponse, Page
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.endpoint_command_models import (
    ALLOWED_COMMAND_TYPES,
    APPROVAL_PENDING_STATES,
    CANCELLABLE_STATES,
    EndpointCommandRequest,
)
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CommandRequestCreate(BaseModel):
    """Propose a new endpoint command request.

    ``command_type`` must be one of the platform allowlist values.
    Arbitrary shell or script text is rejected at schema validation time.
    """

    target_asset_id: str | None = Field(default=None, max_length=36)
    target_agent_id: str | None = Field(default=None, max_length=36)
    command_type: str = Field(min_length=1, max_length=64)
    parameters: dict = Field(default_factory=dict)
    reason: str = Field(min_length=10, max_length=4000)
    idempotency_key: str = Field(min_length=8, max_length=255)
    expires_in_minutes: int = Field(default=60, ge=5, le=10_080)  # 5 min – 1 week

    @model_validator(mode="after")
    def _require_target(self) -> CommandRequestCreate:
        if self.target_asset_id is None and self.target_agent_id is None:
            raise ValueError("At least one of target_asset_id or target_agent_id is required.")
        return self

    @model_validator(mode="after")
    def _allowlist_command_type(self) -> CommandRequestCreate:
        if self.command_type not in ALLOWED_COMMAND_TYPES:
            raise ValueError(
                f"command_type '{self.command_type}' is not on the allowlist. "
                f"Allowed values: {sorted(ALLOWED_COMMAND_TYPES)}"
            )
        return self


class ApprovalNote(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class CommandRequestOut(_ORM):
    id: str
    tenant_id: str
    target_asset_id: str | None = None
    target_agent_id: str | None = None
    command_type: str
    parameters: dict
    requester: str
    reason: str
    expires_at: datetime
    state: str
    idempotency_key: str
    required_approvals: int
    approvals: list
    rejected_reason: str | None = None
    audit_timeline: list
    # Delivery placeholders — always null in this control-plane slice.
    result: dict | None = None
    receipt: dict | None = None
    dispatched_at: datetime | None = None
    # Explicit pending notice returned in every live response.
    delivery_status: str = "pending"
    delivery_note: str = (
        "This request has not been dispatched. "
        "No command has been sent to any endpoint. "
        "Dispatch requires a future signed-delivery layer (not yet implemented)."
    )
    created_at: datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _actor(principal: Principal) -> str:
    return f"api_key:{principal.api_key_id}"


def _timeline_event(event: str, actor: str, **extra: object) -> dict:
    return {"event": event, "actor": actor, "at": datetime.now(UTC).isoformat(), **extra}


def _check_expiry(req: EndpointCommandRequest) -> EndpointCommandRequest:
    """Apply expiry transition in-place and return the request.

    This is evaluated lazily on read rather than by a background sweeper so
    no background process is required for correctness.
    """
    if req.state not in {"proposed", "partially_approved"} or req.expires_at is None:
        return req
    if datetime.now(UTC) >= req.expires_at.replace(tzinfo=UTC):
        req.state = "expired"
        req.audit_timeline = [
            *req.audit_timeline,
            _timeline_event("expired", actor="system"),
        ]
    return req


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/endpoint-command-requests",
    response_model=CommandRequestOut,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an endpoint command request",
    description=(
        "Creates a command request in `proposed` state. "
        "No command is sent to any endpoint. "
        "Two distinct approvals are required before the request reaches `approved` state. "
        "Even then, no dispatch occurs until a separate delivery layer is implemented."
    ),
)
async def create_command_request(
    payload: CommandRequestCreate,
    db: DbSession,
    principal: WritePrincipal,
) -> CommandRequestOut:
    # Idempotency: return the existing row for the same tenant+key.
    existing = (
        await db.execute(
            select(EndpointCommandRequest).where(
                EndpointCommandRequest.tenant_id == principal.tenant_id,
                EndpointCommandRequest.idempotency_key == payload.idempotency_key,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        _check_expiry(existing)
        return CommandRequestOut.model_validate(existing)

    requester = _actor(principal)
    expires_at = datetime.now(UTC) + timedelta(minutes=payload.expires_in_minutes)

    req = EndpointCommandRequest(
        tenant_id=principal.tenant_id,
        target_asset_id=payload.target_asset_id,
        target_agent_id=payload.target_agent_id,
        command_type=payload.command_type,
        parameters=payload.parameters,
        requester=requester,
        reason=payload.reason,
        expires_at=expires_at,
        idempotency_key=payload.idempotency_key,
        audit_timeline=[_timeline_event("proposed", actor=requester)],
    )
    db.add(req)
    await db.flush()
    return CommandRequestOut.model_validate(req)


@router.get(
    "/endpoint-command-requests",
    response_model=ListResponse[CommandRequestOut],
    summary="List endpoint command requests",
)
async def list_command_requests(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    req_state: Annotated[str | None, Query(alias="state")] = None,
    command_type: Annotated[str | None, Query()] = None,
) -> ListResponse[CommandRequestOut]:
    stmt = select(EndpointCommandRequest).where(
        EndpointCommandRequest.tenant_id == principal.tenant_id
    )
    if req_state:
        stmt = stmt.where(EndpointCommandRequest.state == req_state)
    if command_type:
        stmt = stmt.where(EndpointCommandRequest.command_type == command_type)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(EndpointCommandRequest.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    # Apply lazy expiry to each result.
    for row in rows:
        _check_expiry(row)

    return ListResponse(
        data=[CommandRequestOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get(
    "/endpoint-command-requests/{request_id}",
    response_model=CommandRequestOut,
    summary="Get a single endpoint command request",
)
async def get_command_request(
    request_id: str,
    db: DbSession,
    principal: ReadPrincipal,
) -> CommandRequestOut:
    req = (
        await db.execute(
            select(EndpointCommandRequest).where(
                EndpointCommandRequest.id == request_id,
                EndpointCommandRequest.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint command request not found.")
    _check_expiry(req)
    return CommandRequestOut.model_validate(req)


@router.post(
    "/endpoint-command-requests/{request_id}/approve",
    response_model=CommandRequestOut,
    summary="Approve an endpoint command request",
    description=(
        "Records an approval from the current caller. "
        "The caller must not be the requester and must not have already approved. "
        "Two approvals from distinct principals are required to reach `approved` state. "
        "**Important:** API-key identity is not equivalent to human/role separation of duties. "
        "A production deployment must enforce OIDC/SSO subjects and RBAC roles."
    ),
)
async def approve_command_request(
    request_id: str,
    payload: ApprovalNote,
    db: DbSession,
    principal: WritePrincipal,
) -> CommandRequestOut:
    req = (
        await db.execute(
            select(EndpointCommandRequest).where(
                EndpointCommandRequest.id == request_id,
                EndpointCommandRequest.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint command request not found.")

    _check_expiry(req)

    if req.state not in APPROVAL_PENDING_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Request is not awaiting approval (current state: {req.state}).",
        )

    actor = _actor(principal)

    # Requester/approver distinction
    if actor == req.requester:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The requester may not also approve the same request (separation of duties).",
        )

    # Duplicate-approver check
    if any(entry["actor"] == actor for entry in req.approvals):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This principal has already approved this request.",
        )

    now_iso = datetime.now(UTC).isoformat()
    new_approval = {"actor": actor, "note": payload.note, "approved_at": now_iso}
    req.approvals = [*req.approvals, new_approval]

    new_state = (
        "approved" if len(req.approvals) >= req.required_approvals else "partially_approved"
    )
    req.state = new_state
    req.audit_timeline = [
        *req.audit_timeline,
        _timeline_event("approved", actor=actor, note=payload.note, new_state=new_state),
    ]
    await db.flush()
    return CommandRequestOut.model_validate(req)


@router.post(
    "/endpoint-command-requests/{request_id}/reject",
    response_model=CommandRequestOut,
    summary="Reject an endpoint command request",
)
async def reject_command_request(
    request_id: str,
    payload: ApprovalNote,
    db: DbSession,
    principal: WritePrincipal,
) -> CommandRequestOut:
    req = (
        await db.execute(
            select(EndpointCommandRequest).where(
                EndpointCommandRequest.id == request_id,
                EndpointCommandRequest.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint command request not found.")

    _check_expiry(req)

    if req.state not in APPROVAL_PENDING_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Request cannot be rejected in its current state ({req.state}).",
        )

    actor = _actor(principal)
    req.state = "rejected"
    req.rejected_reason = payload.note or "Rejected."
    req.audit_timeline = [
        *req.audit_timeline,
        _timeline_event("rejected", actor=actor, note=payload.note),
    ]
    await db.flush()
    return CommandRequestOut.model_validate(req)


@router.post(
    "/endpoint-command-requests/{request_id}/cancel",
    response_model=CommandRequestOut,
    summary="Cancel an endpoint command request",
    description=(
        "Cancels a request that has not yet been dispatched. "
        "Only the original requester or an admin-scoped principal may cancel."
    ),
)
async def cancel_command_request(
    request_id: str,
    payload: ApprovalNote,
    db: DbSession,
    principal: WritePrincipal,
) -> CommandRequestOut:
    req = (
        await db.execute(
            select(EndpointCommandRequest).where(
                EndpointCommandRequest.id == request_id,
                EndpointCommandRequest.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint command request not found.")

    _check_expiry(req)

    if req.state not in CANCELLABLE_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Request cannot be cancelled in its current state ({req.state}).",
        )

    actor = _actor(principal)
    # Only the requester or an admin-scoped key may cancel.
    if actor != req.requester and not principal.has(Scope.ADMIN):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only the original requester or an admin may cancel this request.",
        )

    req.state = "cancelled"
    req.rejected_reason = payload.note or "Cancelled by requester."
    req.audit_timeline = [
        *req.audit_timeline,
        _timeline_event("cancelled", actor=actor, note=payload.note),
    ]
    await db.flush()
    return CommandRequestOut.model_validate(req)
