"""Explainable correlation records and AI analyst briefs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin

UuidType = String(36).with_variant(UUID(as_uuid=False), "postgresql")
JsonType = __import__("sqlalchemy").JSON().with_variant(JSONB(), "postgresql")


class Correlation(Base, TimestampMixin):
    """Immutable evidence bundle and reproducible deterministic assessment."""

    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    primary_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    primary_entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    factor_breakdown: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    automation_candidates: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class CorrelationAiBrief(Base, TimestampMixin):
    """Grounded AI explanation linked to a reproducible correlation."""

    __tablename__ = "correlation_ai_briefs"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, server_default=func.uuid_generate_v4())
    correlation_id: Mapped[str] = mapped_column(UuidType, ForeignKey("correlations.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    citations: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    model_label: Mapped[str] = mapped_column(String(128), default="rag-grounded", nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
