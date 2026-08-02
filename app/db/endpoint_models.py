"""Endpoint command intent control-plane models.

Stage 4: request lifecycle only — no delivery, no mTLS transport, no shell
execution, no connector outbox action.  All delivery/receipt fields are
modelled as nullable placeholders; they remain NULL in this release.

Approved intents are not automatically executed. AI output cannot trigger
delivery. Production separation of duties requires OIDC/RBAC subjects;
the current API-key identity limitation is documented honestly here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType

# Strict intent-type allowlist.  Each entry maps to a narrow, typed operation
# on the endpoint agent.  Arbitrary command/script text is explicitly excluded.
ENDPOINT_INTENT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "isolate",
        "unisolate",
        "scan",
        "collect_forensics",
        "kill_process",
        "quarantine_file",
        "restore_file",
        "collect_logs",
    }
)

# Two distinct approvers are required (requester excluded).
REQUIRED_APPROVALS: int = 2


class EndpointCommandIntent(Base, TimestampMixin):
    """Lifecycle record for a tenant-scoped endpoint command request.

    State machine (explicit transitions only):
      proposed  ──approval(1)──►  partially_approved
                 ──approval(2)──►  approved
                 ──reject       ──►  rejected     (terminal)
                 ──cancel       ──►  cancelled    (terminal)
                 ──expiry       ──►  expired      (terminal)
    partially_approved:
                 ──approval(2)──►  approved
                 ──reject       ──►  rejected
                 ──cancel       ──►  cancelled
                 ──expiry       ──►  expired
    approved:
                 ──cancel       ──►  cancelled    (admin cancel only)
                 (no automatic delivery in this release)

    API-key identity limitation: the current implementation cannot enforce
    OIDC/RBAC-level subject separation for the two-person rule.  The system
    records the api_key_id as the identity; production environments MUST
    use OIDC/RBAC subjects to guarantee real requester/approver isolation.
    """

    __tablename__ = "endpoint_command_intents"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_endpoint_command_intents_tenant_key",
        ),
    )

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)

    # Target validation: at least one of asset/agent must be supplied;
    # if both are supplied their linkage is validated at creation time.
    target_asset_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    target_agent_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("agents.id", ondelete="RESTRICT"), index=True
    )

    requester: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Must be from ENDPOINT_INTENT_ALLOWLIST.
    intent_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Typed parameters; the schema depends on intent_type. No free-form
    # command or script text is accepted.
    parameters: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

    state: Mapped[str] = mapped_column(
        String(32), default="proposed", nullable=False, index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    required_approvals: Mapped[int] = mapped_column(
        Integer, default=REQUIRED_APPROVALS, nullable=False
    )

    # Append-only approval history: [{actor, approved_at, note}]
    approvals: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)

    # Append-only audit timeline: [{event, actor, at, detail}]
    audit_timeline: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)

    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )

    # Cancellation uses a dedicated note field to avoid misusing rejected_reason.
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_note: Mapped[str | None] = mapped_column(Text)
    cancelled_by: Mapped[str | None] = mapped_column(String(255))

    # Rejection
    rejected_reason: Mapped[str | None] = mapped_column(Text)
    rejected_by: Mapped[str | None] = mapped_column(String(255))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Delivery placeholders — always NULL in this release (control-plane only).
    # These fields exist so the schema can evolve without a breaking migration.
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_receipt: Mapped[dict | None] = mapped_column(JsonType)
