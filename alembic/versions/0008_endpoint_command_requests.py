"""Add endpoint_command_requests table.

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
        "endpoint_command_requests",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("target_asset_id", sa.String(36)),
        sa.Column("target_agent_id", sa.String(36)),
        sa.Column("command_type", sa.String(64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("requester", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="proposed"),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("approvals", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("rejected_reason", sa.Text()),
        sa.Column("audit_timeline", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("result", sa.JSON()),
        sa.Column("receipt", sa.JSON()),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_ecr_tenant_idempotency"),
    )
    op.create_index("ix_ecr_tenant_id", "endpoint_command_requests", ["tenant_id"])
    op.create_index("ix_ecr_target_asset_id", "endpoint_command_requests", ["target_asset_id"])
    op.create_index("ix_ecr_target_agent_id", "endpoint_command_requests", ["target_agent_id"])
    op.create_index("ix_ecr_command_type", "endpoint_command_requests", ["command_type"])
    op.create_index("ix_ecr_state", "endpoint_command_requests", ["state"])
    op.create_index("ix_ecr_requester", "endpoint_command_requests", ["requester"])


def downgrade() -> None:
    for idx in (
        "ix_ecr_requester",
        "ix_ecr_state",
        "ix_ecr_command_type",
        "ix_ecr_target_agent_id",
        "ix_ecr_target_asset_id",
        "ix_ecr_tenant_id",
    ):
        op.drop_index(idx, table_name="endpoint_command_requests")
    op.drop_table("endpoint_command_requests")
