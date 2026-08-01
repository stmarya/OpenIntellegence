"""Explainable correlation records, AI analyst briefs, and cross-entity timeline."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType


class Correlation(Base, TimestampMixin):
    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    primary_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    primary_entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    factor_breakdown: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    automation_candidates: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    factor_provenance: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class CorrelationAiBrief(Base, TimestampMixin):
    __tablename__ = "correlation_ai_briefs"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("correlations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    citations: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    model_label: Mapped[str] = mapped_column(String(128), default="rag-grounded", nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TimelineEvent(Base):
    """Append-only cross-entity audit timeline.

    Links alerts, correlations, investigations, and cases in a single
    chronological stream. Rows are never updated or deleted — new transitions
    are always appended. ``object_type`` identifies the entity kind and
    ``object_id`` is its primary key. ``data`` carries the before/after
    snapshot or transition context serialised to JSON.

    Note: deliberately has no ``updated_at`` because updating a timeline event
    would defeat its purpose as an immutable audit trail.
    """

    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    # One of: alert, correlation, investigation, case
    object_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str | None] = mapped_column(String(255))
    data: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
