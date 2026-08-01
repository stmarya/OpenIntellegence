"""Investigation and case-management persistence models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin

UuidType = String(36).with_variant(UUID(as_uuid=False), "postgresql")
JsonType = __import__("sqlalchemy").JSON().with_variant(JSONB(), "postgresql")


class Investigation(Base, TimestampMixin):
    """Analytical workspace built around a question or hypothesis."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    hypothesis: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium", nullable=False, index=True)
    confidence: Mapped[int | None] = mapped_column()
    owner: Mapped[str | None] = mapped_column(String(255), index=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InvestigationEntity(Base, TimestampMixin):
    """Evidence-bearing entity relation; not a copied snapshot."""

    __tablename__ = "investigation_entities"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    investigation_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship: Mapped[str] = mapped_column(String(64), default="related_to", nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text)
    source_refs: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)


class Case(Base, TimestampMixin):
    """Operational response workflow with an owner and SLA."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    investigation_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("investigations.id", ondelete="SET NULL"), index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    case_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium", nullable=False, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), index=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closure_reason: Mapped[str | None] = mapped_column(Text)


class CaseTask(Base, TimestampMixin):
    __tablename__ = "case_tasks"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    case_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(255), index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CaseEvent(Base, TimestampMixin):
    """Append-only human or system event in a case chronology."""

    __tablename__ = "case_events"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    case_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
