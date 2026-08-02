"""Add endpoint command intents and outbox replay history tables.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "automation_outbox_replay_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "outbox_id",
            sa.String(36),
            sa.ForeignKey("automation_outbox.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("replayed_by", sa.String(255), nullable=False),
        sa.Column("original_idempotency_key", sa.String(320), nullable=False),
        sa.Column("new_idempotency_key", sa.String(320), nullable=False, unique=True),
        sa.Column(
            "replayed_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_table(
        "endpoint_command_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column(
            "target_asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="RESTRICT"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "target_agent_id",
            sa.String(36),
            sa.ForeignKey("agents.id", ondelete="RESTRICT"),
            nullable=True,
            index=True,
        ),
        sa.Column("requester", sa.String(255), nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("intent_type", sa.String(64), nullable=False, index=True),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("state", sa.String(32), nullable=False, index=True, server_default="proposed"),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("approvals", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("audit_timeline", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancellation_note", sa.Text(), nullable=True),
        sa.Column("cancelled_by", sa.String(255), nullable=True),
        sa.Column("rejected_reason", sa.Text(), nullable=True),
        sa.Column("rejected_by", sa.String(255), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_receipt", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_endpoint_command_intents_tenant_key",
        ),
    )


def downgrade() -> None:
    op.drop_table("endpoint_command_intents")
    op.drop_table("automation_outbox_replay_history")
