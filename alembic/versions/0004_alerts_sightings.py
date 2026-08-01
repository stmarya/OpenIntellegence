"""Add rule-driven alerts and sightings.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = sa.dialects.postgresql.UUID()
    op.create_table("alert_rules", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("name", sa.String(255), nullable=False), sa.Column("description", sa.Text()), sa.Column("trigger_type", sa.String(64), nullable=False), sa.Column("condition", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")), sa.Column("severity", sa.String(16), nullable=False, server_default="medium"), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="60"), sa.Column("auto_create_case", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_alert_rules"))
    op.create_index("ix_alert_rules_tenant_enabled", "alert_rules", ["tenant_id", "enabled"])
    op.create_index("ix_alert_rules_trigger_type", "alert_rules", ["trigger_type"])

    op.create_table("alerts", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("rule_id", uuid), sa.Column("fingerprint", sa.String(64), nullable=False), sa.Column("title", sa.String(512), nullable=False), sa.Column("summary", sa.Text()), sa.Column("severity", sa.String(16), nullable=False), sa.Column("status", sa.String(32), nullable=False, server_default="open"), sa.Column("entity_type", sa.String(64)), sa.Column("entity_id", sa.String(255)), sa.Column("risk_score", sa.Integer()), sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")), sa.Column("first_triggered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"), sa.Column("acknowledged_at", sa.DateTime(timezone=True)), sa.Column("acknowledged_by", sa.String(255)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_alerts"), sa.ForeignKeyConstraint(["rule_id"], ["alert_rules.id"], ondelete="SET NULL", name="fk_alerts_rule"), sa.UniqueConstraint("tenant_id", "fingerprint", name="uq_alerts_tenant_fingerprint"))
    op.create_index("ix_alerts_tenant_status", "alerts", ["tenant_id", "status"])
    op.create_index("ix_alerts_tenant_severity", "alerts", ["tenant_id", "severity"])
    op.create_index("ix_alerts_last_triggered", "alerts", ["last_triggered_at"])

    op.create_table("sightings", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("entity_type", sa.String(64), nullable=False), sa.Column("entity_id", sa.String(255), nullable=False), sa.Column("asset_id", sa.String(255)), sa.Column("source", sa.String(64), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("confidence", sa.Integer()), sa.Column("context", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.PrimaryKeyConstraint("id", name="pk_sightings"))
    op.create_index("ix_sightings_tenant_observed", "sightings", ["tenant_id", "observed_at"])
    op.create_index("ix_sightings_entity", "sightings", ["entity_type", "entity_id"])


def downgrade() -> None:
    for table in ("sightings", "alerts", "alert_rules"):
        op.drop_table(table)
