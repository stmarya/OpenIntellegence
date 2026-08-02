"""Explainable correlation records and AI analyst briefs."""

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
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    # Resolution status tracks how evidence was obtained.
    # "unavailable" is the server_default so pre-migration rows get a safe value.
    resolution_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unavailable", server_default="unavailable"
    )
    # Preserved separately when a privileged caller supplies manual evidence.
    # Never merged into the resolved evidence path.
    manual_evidence: Mapped[dict | None] = mapped_column(JsonType, nullable=True)


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
