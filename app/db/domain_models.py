"""Additional first-class CTI knowledge-domain models.

Campaign and malware are intentionally modelled separately from threat actors.
Attribution is often incomplete, time-bounded, or disputed; forcing one actor
foreign key into either entity would turn an analytical assessment into an
unqualified database fact.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin

JsonType = JSONB().with_variant(__import__("sqlalchemy").JSON(), "sqlite")
StrArray = ARRAY(String).with_variant(__import__("sqlalchemy").JSON(), "sqlite")
UuidType = UUID(as_uuid=False).with_variant(String(36), "sqlite")


class Campaign(Base, TimestampMixin):
    """A time-bounded adversary operation with explicit evidence fields."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(
        UuidType, primary_key=True, server_default=func.cast(func.uuid_generate_v4(), UuidType)
    )
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
    """A malware family, tool, or payload with reusable CTI context."""

    __tablename__ = "malware"

    id: Mapped[str] = mapped_column(
        UuidType, primary_key=True, server_default=func.cast(func.uuid_generate_v4(), UuidType)
    )
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
