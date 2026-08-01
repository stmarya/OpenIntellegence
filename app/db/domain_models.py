"""Additional first-class CTI knowledge-domain models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, StrArray, UuidType


class Campaign(Base, TimestampMixin):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    actor_names: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    targeted_sectors: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    targeted_countries: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    attack_techniques: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)


class Malware(Base, TimestampMixin):
    __tablename__ = "malware"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    malware_type: Mapped[str | None] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    platforms: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    capabilities: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    actor_names: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    attack_techniques: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
