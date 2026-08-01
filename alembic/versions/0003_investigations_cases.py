"""Add investigation and case-management workflow tables.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = sa.dialects.postgresql.UUID()
    op.create_table("investigations", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("title", sa.String(512), nullable=False), sa.Column("hypothesis", sa.Text()), sa.Column("status", sa.String(32), server_default="open", nullable=False), sa.Column("priority", sa.String(16), server_default="medium", nullable=False), sa.Column("confidence", sa.Integer()), sa.Column("owner", sa.String(255)), sa.Column("opened_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("closed_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_investigations"))
    op.create_index("ix_investigations_tenant_status", "investigations", ["tenant_id", "status"])
    op.create_index("ix_investigations_priority", "investigations", ["priority"])

    op.create_table("investigation_entities", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("investigation_id", uuid, nullable=False), sa.Column("entity_type", sa.String(64), nullable=False), sa.Column("entity_id", sa.String(255), nullable=False), sa.Column("relationship", sa.String(64), server_default="related_to", nullable=False), sa.Column("evidence", sa.Text()), sa.Column("source_refs", sa.dialects.postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_investigation_entities"), sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE", name="fk_investigation_entities_investigation"))
    op.create_index("ix_investigation_entities_investigation", "investigation_entities", ["investigation_id"])

    op.create_table("cases", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("investigation_id", uuid), sa.Column("title", sa.String(512), nullable=False), sa.Column("case_type", sa.String(64), nullable=False), sa.Column("status", sa.String(32), server_default="new", nullable=False), sa.Column("priority", sa.String(16), server_default="medium", nullable=False), sa.Column("owner", sa.String(255)), sa.Column("sla_due_at", sa.DateTime(timezone=True)), sa.Column("closed_at", sa.DateTime(timezone=True)), sa.Column("closure_reason", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_cases"), sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="SET NULL", name="fk_cases_investigation"))
    op.create_index("ix_cases_tenant_status", "cases", ["tenant_id", "status"])
    op.create_index("ix_cases_sla", "cases", ["sla_due_at"])

    op.create_table("case_tasks", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("case_id", uuid, nullable=False), sa.Column("title", sa.String(512), nullable=False), sa.Column("status", sa.String(32), server_default="open", nullable=False), sa.Column("assignee", sa.String(255)), sa.Column("due_at", sa.DateTime(timezone=True)), sa.Column("completed_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_case_tasks"), sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE", name="fk_case_tasks_case"))
    op.create_index("ix_case_tasks_case_status", "case_tasks", ["case_id", "status"])

    op.create_table("case_events", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("case_id", uuid, nullable=False), sa.Column("event_type", sa.String(64), nullable=False), sa.Column("body", sa.Text(), nullable=False), sa.Column("actor", sa.String(255)), sa.Column("event_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_case_events"), sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE", name="fk_case_events_case"))
    op.create_index("ix_case_events_case_time", "case_events", ["case_id", "event_at"])


def downgrade() -> None:
    for table in ("case_events", "case_tasks", "cases", "investigation_entities", "investigations"):
        op.drop_table(table)
