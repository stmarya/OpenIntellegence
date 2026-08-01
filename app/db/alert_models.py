"""Rule-driven alerting and IOC-sighting persistence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType


class AlertRule(Base, TimestampMixin):
    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    condition: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    auto_create_case: Mapped[bool] = mapped_column(default=False, nullable=False)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "fingerprint", name="uq_alerts_tenant_fingerprint"),
    )

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    rule_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("alert_rules.id", ondelete="SET NULL"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(255), index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    payload: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    first_triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(255))


class Sighting(Base, TimestampMixin):
    __tablename__ = "sightings"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    confidence: Mapped[int | None] = mapped_column(Integer)
    context: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
