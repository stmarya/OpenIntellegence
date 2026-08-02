"""Add resolution_status and manual_evidence to correlations.

Forward-safe additive migration: both columns carry server defaults so
pre-existing rows remain valid after upgrade.

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
        "correlations",
        sa.Column(
            "resolution_status",
            sa.String(16),
            nullable=False,
            server_default="unavailable",
        ),
    )
    op.add_column(
        "correlations",
        sa.Column(
            "manual_evidence",
            sa.dialects.postgresql.JSONB(),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_correlations_resolution_status",
        "correlations",
        ["resolution_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_correlations_resolution_status", table_name="correlations")
    op.drop_column("correlations", "manual_evidence")
    op.drop_column("correlations", "resolution_status")
