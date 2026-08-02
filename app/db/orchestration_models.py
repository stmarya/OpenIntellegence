"""Approval-first automation orchestration control-plane models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType


class AutomationOutboxReplayHistory(Base, TimestampMixin):
    """Append-only audit record for every dead-letter replay attempt.

    A new row is written transactionally with the outbox state reset so the
    replay chain is never lost even when a replayed record later dead-letters
    again.
    """

    __tablename__ = "automation_outbox_replay_history"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    outbox_id: Mapped[str] = mapped_column(
        UuidType,
        ForeignKey("automation_outbox.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    replayed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    original_idempotency_key: Mapped[str] = mapped_column(String(320), nullable=False)
    new_idempotency_key: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    replayed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AutomationPlaybook(Base, TimestampMixin):
    __tablename__ = "automation_playbooks"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    steps: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)


class AutomationRun(Base, TimestampMixin):
    __tablename__ = "automation_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_automation_runs_tenant_key"),
    )

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    playbook_id: Mapped[str] = mapped_column(
        UuidType,
        ForeignKey("automation_playbooks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="proposed", nullable=False, index=True)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    approvals: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    context: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    rejected_reason: Mapped[str | None] = mapped_column(Text)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AutomationOutbox(Base, TimestampMixin):
    __tablename__ = "automation_outbox"
    __table_args__ = (
        UniqueConstraint("run_id", "step_index", name="uq_automation_outbox_run_step"),
    )

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("automation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    delivery_result: Mapped[dict | None] = mapped_column(JsonType)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    lease_token: Mapped[str | None] = mapped_column(String(64), index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
