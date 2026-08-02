"""Add replay tracking columns for dead-letter replay audit.

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
    op.add_column(
        "automation_outbox",
        sa.Column("replay_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "automation_outbox",
        sa.Column(
            "replay_history",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("automation_outbox", "replay_history")
    op.drop_column("automation_outbox", "replay_count")
