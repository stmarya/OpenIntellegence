"""Investigation and case-management persistence models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType


class Investigation(Base, TimestampMixin):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    hypothesis: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium", nullable=False, index=True)
    confidence: Mapped[int | None] = mapped_column(Integer)
    owner: Mapped[str | None] = mapped_column(String(255), index=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InvestigationEntity(Base, TimestampMixin):
    __tablename__ = "investigation_entities"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship: Mapped[str] = mapped_column(String(64), default="related_to", nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text)
    source_refs: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)


class Case(Base, TimestampMixin):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
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

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    case_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(255), index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CaseEvent(Base, TimestampMixin):
    __tablename__ = "case_events"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    case_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
