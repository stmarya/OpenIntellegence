"""Add approval-first automation orchestration.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = sa.dialects.postgresql.UUID()
    op.create_table(
        "automation_playbooks",
        sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", uuid, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("trigger_type", sa.String(64), nullable=False),
        sa.Column(
            "steps",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id", name="pk_automation_playbooks"),
    )
    op.create_index(
        "ix_automation_playbooks_tenant_enabled", "automation_playbooks", ["tenant_id", "enabled"]
    )
    op.create_table(
        "automation_runs",
        sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", uuid, nullable=False),
        sa.Column("playbook_id", uuid, nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(255), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="proposed"),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "approvals",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "context",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("rejected_reason", sa.Text()),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id", name="pk_automation_runs"),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["automation_playbooks.id"],
            ondelete="RESTRICT",
            name="fk_automation_runs_playbook",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_automation_runs_tenant_key"),
    )
    op.create_index("ix_automation_runs_tenant_state", "automation_runs", ["tenant_id", "state"])
    op.create_table(
        "automation_outbox",
        sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", uuid, nullable=False),
        sa.Column("run_id", uuid, nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column(
            "payload",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("idempotency_key", sa.String(320), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("delivery_result", sa.dialects.postgresql.JSONB()),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id", name="pk_automation_outbox"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["automation_runs.id"], ondelete="CASCADE", name="fk_automation_outbox_run"
        ),
        sa.UniqueConstraint("run_id", "step_index", name="uq_automation_outbox_run_step"),
        sa.UniqueConstraint("idempotency_key", name="uq_automation_outbox_idempotency"),
    )
    op.create_index(
        "ix_automation_outbox_tenant_state", "automation_outbox", ["tenant_id", "state"]
    )


def downgrade() -> None:
    op.drop_table("automation_outbox")
    op.drop_table("automation_runs")
    op.drop_table("automation_playbooks")
