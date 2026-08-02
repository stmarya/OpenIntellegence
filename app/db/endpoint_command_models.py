"""ORM models for the endpoint command request control plane.

Design notes
------------
An endpoint command request is a *proposal* to send a command to an agent.
It must be approved by two distinct principals before it may be considered
for delivery, and delivery is not implemented here.  The model enforces the
separation of duties and provides an immutable audit trail.

No command is ever executed from this module.  The ``result`` and ``receipt``
fields are reserved for a future delivery layer that requires mTLS-signed
channel handoff and is explicitly out of scope for this control-plane slice.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType

# ---------------------------------------------------------------------------
# Allowlisted command types
# ---------------------------------------------------------------------------
# Arbitrary shell / script text is never accepted.  This set is the only
# grammar the control plane recognises.  Expanding it requires a code change
# and a deliberate review, not a free-text field.
ALLOWED_COMMAND_TYPES: frozenset[str] = frozenset(
    {
        "isolate_network",
        "collect_forensic_artifact",
        "terminate_process",
        "quarantine_file",
        "flush_dns_cache",
        "run_vulnerability_scan",
    }
)

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------
# proposed ──(1st approval)──► partially_approved ──(2nd approval)──► approved
# proposed ──(cancel)──► cancelled
# partially_approved ──(cancel)──► cancelled
# proposed / partially_approved / approved ──(expiry check)──► expired
#
# Delivery would be: approved ──(dispatch)──► dispatched   [NOT YET IMPLEMENTED]
#
# States that are awaiting further approvals:
APPROVAL_PENDING_STATES: frozenset[str] = frozenset({"proposed", "partially_approved"})

# States from which a cancel transition is allowed:
CANCELLABLE_STATES: frozenset[str] = frozenset({"proposed", "partially_approved", "approved"})

# Terminal states (no further transitions):
TERMINAL_STATES: frozenset[str] = frozenset({"approved", "cancelled", "expired", "rejected"})


class EndpointCommandRequest(Base, TimestampMixin):
    """A gated, audited request to send a command to an endpoint agent.

    This row represents intent only.  No network call, no shell execution,
    and no agent delivery occur here.  The ``result`` and ``receipt`` columns
    are placeholders for a future signed-delivery layer.

    Approval gate
    -------------
    ``required_approvals`` is fixed at 2 and both approvals must come from
    principals that are *different* from the requester and from each other.

    **Current limitation:** because callers authenticate with API keys,
    ``requester`` and ``approver`` are resolved to ``api_key:<id>`` strings.
    API-key identity is not equivalent to human/role separation of duties.
    A future enforcement layer will require OIDC/SSO subjects and RBAC roles
    to satisfy true two-person-integrity.

    Expiry
    ------
    Requests that have not reached ``approved`` state before ``expires_at``
    are treated as expired at read time.  No background sweeper is needed for
    correctness; the API layer performs the check on every state read.

    Immutable audit
    ---------------
    ``audit_timeline`` is an append-only JSON array.  Each entry is a dict
    with at minimum ``{"event": str, "actor": str, "at": ISO8601}``.
    """

    __tablename__ = "endpoint_command_requests"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_ecr_tenant_idempotency",
        ),
    )

    # --- identity ---
    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)

    # --- target ---
    target_asset_id: Mapped[str | None] = mapped_column(UuidType, index=True)
    target_agent_id: Mapped[str | None] = mapped_column(UuidType, index=True)

    # --- command specification (allowlisted, never raw shell) ---
    command_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parameters: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

    # --- authorship ---
    requester: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # --- lifecycle ---
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(
        String(32), default="proposed", nullable=False, index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- approval gate (two distinct approvers required) ---
    required_approvals: Mapped[int] = mapped_column(default=2, nullable=False)
    approvals: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    rejected_reason: Mapped[str | None] = mapped_column(Text)

    # --- immutable audit timeline ---
    audit_timeline: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)

    # --- result/receipt placeholders (not-dispatched) ---
    # These fields are reserved for a future signed-delivery layer.
    # They are always null in this control-plane slice.
    result: Mapped[dict | None] = mapped_column(JsonType)
    receipt: Mapped[dict | None] = mapped_column(JsonType)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
