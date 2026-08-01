"""Add connector-worker retry and lease metadata.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("automation_outbox", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("automation_outbox", sa.Column("last_error", sa.Text()))
    op.add_column("automation_outbox", sa.Column("available_at", sa.DateTime(timezone=True)))
    op.add_column("automation_outbox", sa.Column("lease_token", sa.String(64)))
    op.add_column("automation_outbox", sa.Column("lease_until", sa.DateTime(timezone=True)))
    op.create_index("ix_automation_outbox_available", "automation_outbox", ["state", "available_at"])
    op.create_index("ix_automation_outbox_lease", "automation_outbox", ["lease_token", "lease_until"])


def downgrade() -> None:
    op.drop_index("ix_automation_outbox_lease", table_name="automation_outbox")
    op.drop_index("ix_automation_outbox_available", table_name="automation_outbox")
    for column in ("lease_until", "lease_token", "available_at", "last_error", "attempts"):
        op.drop_column("automation_outbox", column)
