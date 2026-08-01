"""Alert evaluation worker columns and cross-entity timeline.

Adds:
* ``alerts.evidence``              – server-resolved evidence JSONB
* ``correlations.factor_provenance`` – factor provenance JSONB list
* ``timeline_events``              – append-only cross-entity audit timeline

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
    uuid = sa.dialects.postgresql.UUID()
    jsonb = sa.dialects.postgresql.JSONB()

    # -- alerts.evidence -------------------------------------------------------
    op.add_column(
        "alerts",
        sa.Column("evidence", jsonb, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )

    # -- correlations.factor_provenance ----------------------------------------
    op.add_column(
        "correlations",
        sa.Column(
            "factor_provenance", jsonb, nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )

    # -- timeline_events -------------------------------------------------------
    op.create_table(
        "timeline_events",
        sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", uuid, nullable=False),
        sa.Column("object_type", sa.String(32), nullable=False),
        sa.Column("object_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255)),
        sa.Column("data", jsonb, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_timeline_events"),
    )
    op.create_index("ix_timeline_events_tenant_id", "timeline_events", ["tenant_id"])
    op.create_index("ix_timeline_events_object_type", "timeline_events", ["object_type"])
    op.create_index("ix_timeline_events_object_id", "timeline_events", ["object_id"])
    op.create_index("ix_timeline_events_event_type", "timeline_events", ["event_type"])
    op.create_index("ix_timeline_events_event_at", "timeline_events", ["event_at"])
    op.create_index("ix_timeline_events_created_at", "timeline_events", ["created_at"])
    # Composite index for the most common query: all events for one object.
    op.create_index(
        "ix_timeline_events_tenant_object",
        "timeline_events",
        ["tenant_id", "object_type", "object_id", "event_at"],
    )


def downgrade() -> None:
    op.drop_table("timeline_events")
    op.drop_column("correlations", "factor_provenance")
    op.drop_column("alerts", "evidence")
