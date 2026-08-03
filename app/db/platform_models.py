"""Cross-cutting models for identity, graph, search, agent delivery, AI evaluation, and detection."""
from __future__ import annotations
from datetime import datetime
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, StrArray, UuidType

def new_id() -> str:
    return str(uuid4())

class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    oidc_subject: Mapped[str | None] = mapped_column(String(512), index=True)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False, index=True)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

class Role(Base, TimestampMixin):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),)

class RoleAssignment(Base, TimestampMixin):
    __tablename__ = "role_assignments"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UuidType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id: Mapped[str] = mapped_column(UuidType, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_by: Mapped[str] = mapped_column(String(255), nullable=False)
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_role_assignment_user_role"),)

class UserSession(Base, TimestampMixin):
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UuidType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))

class EntityRelationship(Base, TimestampMixin):
    __tablename__ = "entity_relationships"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    evidence: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "source_type", "source_id", "relationship_type", "target_type", "target_id", name="uq_typed_relationship"),)

class EntityRevision(Base, TimestampMixin):
    __tablename__ = "entity_revisions"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict] = mapped_column(JsonType, nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("tenant_id", "entity_type", "entity_id", "revision", name="uq_entity_revision"),)

class SavedSearch(Base, TimestampMixin):
    __tablename__ = "saved_searches"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    user_id: Mapped[str | None] = mapped_column(UuidType, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    query: Mapped[str] = mapped_column(String(2000), nullable=False)
    filters: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class ConnectorCheckpoint(Base, TimestampMixin):
    __tablename__ = "connector_checkpoints"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    cursor: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="idle", nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("tenant_id", "source", name="uq_connector_checkpoint"),)

class AgentCommand(Base, TimestampMixin):
    __tablename__ = "agent_commands"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(UuidType, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    intent_id: Mapped[str] = mapped_column(UuidType, ForeignKey("endpoint_intents.id", ondelete="CASCADE"), unique=True, nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    envelope: Mapped[dict] = mapped_column(JsonType, nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="available", nullable=False, index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JsonType)

class AiEvaluation(Base, TimestampMixin):
    __tablename__ = "ai_evaluations"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    expected_refs: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    actual_refs: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    grounded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    model: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(UuidType, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_format: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="draft", nullable=False, index=True)
    attack_techniques: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    validation: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("tenant_id", "name", "version", name="uq_detection_rule_version"),)
