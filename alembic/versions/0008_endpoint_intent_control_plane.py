"""Add control-plane endpoint intent records.
Revision ID: 0008
Revises: 0007
"""
from __future__ import annotations
import sqlalchemy as sa
from alembic import op
revision="0008"; down_revision="0007"; branch_labels=None; depends_on=None
def upgrade()->None:
 op.create_table("endpoint_intents",sa.Column("id",sa.String(36),primary_key=True),sa.Column("tenant_id",sa.String(36),nullable=False),sa.Column("agent_id",sa.String(36),nullable=False),sa.Column("intent_type",sa.String(64),nullable=False),sa.Column("state",sa.String(32),nullable=False),sa.Column("requested_by",sa.String(255),nullable=False),sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),sa.Column("delivery_state",sa.String(32),nullable=False),sa.Column("delivery_result",sa.JSON()),sa.ForeignKeyConstraint(["agent_id"],["agents.id"],ondelete="RESTRICT"))
 op.create_index("ix_endpoint_intents_tenant_state","endpoint_intents",["tenant_id","state"])
 op.create_table("endpoint_intent_audit",sa.Column("id",sa.String(36),primary_key=True),sa.Column("intent_id",sa.String(36),nullable=False),sa.Column("actor",sa.String(255),nullable=False),sa.Column("event_type",sa.String(64),nullable=False),sa.Column("detail",sa.JSON(),nullable=False),sa.Column("event_at",sa.DateTime(timezone=True),nullable=False),sa.ForeignKeyConstraint(["intent_id"],["endpoint_intents.id"],ondelete="CASCADE"))
def downgrade()->None:
 op.drop_table("endpoint_intent_audit"); op.drop_index("ix_endpoint_intents_tenant_state",table_name="endpoint_intents"); op.drop_table("endpoint_intents")
