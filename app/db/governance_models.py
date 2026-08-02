"""Governance surfaces: detection content, collections, requirements, replay audit."""
from __future__ import annotations
from datetime import datetime
from uuid import uuid4
from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType


def _uuid() -> str:
    return str(uuid4())


class DetectionContent(Base, TimestampMixin):
    """A detection rule tracked as intelligence product, not as a code artefact."""

    __tablename__ = "detection_content"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_format: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(32))
    # Lifecycle stays explicit. Content that has never been validated is not
    # allowed to look production-ready just because it exists.
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False, index=True)
    attack_techniques: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    data_sources: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    version: Mapped[str | None] = mapped_column(String(32))
    author: Mapped[str | None] = mapped_column(String(255))
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntelCollection(Base, TimestampMixin):
    """A curated grouping of entities an analyst maintains deliberately."""

    __tablename__ = "intel_collections"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(String(255))
    owner: Mapped[str | None] = mapped_column(String(255))
    member_refs: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    is_shared: Mapped[bool] = mapped_column(default=False, nullable=False)
    last_curated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntelligenceRequirement(Base, TimestampMixin):
    """A standing priority intelligence requirement and its coverage state."""

    __tablename__ = "intelligence_requirements"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    owner: Mapped[str | None] = mapped_column(String(255))
    # Coverage is recorded, never inferred. A requirement nobody has mapped a
    # source to is uncovered, which is different from unmet.
    covering_sources: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    coverage_note: Mapped[str | None] = mapped_column(Text)
    review_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AutomationReplayAudit(Base, TimestampMixin):
    """Append-only record of every dead-letter replay that was requested."""

    __tablename__ = "automation_replay_audit"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    source_outbox_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    replay_outbox_id: Mapped[str] = mapped_column(UuidType, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
