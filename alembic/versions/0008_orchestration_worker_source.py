"""Add source_outbox_id to cases and reports for worker idempotency.

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
        "cases",
        sa.Column("source_outbox_id", sa.String(320), nullable=True),
    )
    op.create_index("ix_cases_source_outbox_id", "cases", ["source_outbox_id"], unique=True)

    op.add_column(
        "reports",
        sa.Column("source_outbox_id", sa.String(320), nullable=True),
    )
    op.create_index("ix_reports_source_outbox_id", "reports", ["source_outbox_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_reports_source_outbox_id", table_name="reports")
    op.drop_column("reports", "source_outbox_id")
    op.drop_index("ix_cases_source_outbox_id", table_name="cases")
    op.drop_column("cases", "source_outbox_id")
