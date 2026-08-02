"""Persistent control-plane endpoint intent and append-only audit records."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin
from app.db.models import JsonType, UuidType
class EndpointIntent(Base,TimestampMixin):
 __tablename__="endpoint_intents"
 id:Mapped[str]=mapped_column(UuidType,primary_key=True)
 tenant_id:Mapped[str]=mapped_column(UuidType,nullable=False,index=True)
 agent_id:Mapped[str]=mapped_column(UuidType,ForeignKey("agents.id",ondelete="RESTRICT"),nullable=False,index=True)
 intent_type:Mapped[str]=mapped_column(String(64),nullable=False)
 state:Mapped[str]=mapped_column(String(32),nullable=False,default="pending",index=True)
 requested_by:Mapped[str]=mapped_column(String(255),nullable=False)
 expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,index=True)
 delivery_state:Mapped[str]=mapped_column(String(32),nullable=False,default="not_dispatched")
 delivery_result:Mapped[dict|None]=mapped_column(JsonType)
class EndpointIntentAudit(Base,TimestampMixin):
 __tablename__="endpoint_intent_audit"
 id:Mapped[str]=mapped_column(UuidType,primary_key=True)
 intent_id:Mapped[str]=mapped_column(UuidType,ForeignKey("endpoint_intents.id",ondelete="CASCADE"),nullable=False,index=True)
 actor:Mapped[str]=mapped_column(String(255),nullable=False)
 event_type:Mapped[str]=mapped_column(String(64),nullable=False)
 detail:Mapped[dict]=mapped_column(JsonType,default=dict,nullable=False)
 event_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False)
