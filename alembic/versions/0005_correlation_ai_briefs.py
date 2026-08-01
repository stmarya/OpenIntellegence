"""Add explainable correlations and grounded AI briefs.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = sa.dialects.postgresql.UUID()
    op.create_table("correlations", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("tenant_id", uuid, nullable=False), sa.Column("title", sa.String(512), nullable=False), sa.Column("primary_entity_type", sa.String(64), nullable=False), sa.Column("primary_entity_id", sa.String(255), nullable=False), sa.Column("evidence", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")), sa.Column("factor_breakdown", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")), sa.Column("risk_score", sa.Integer(), nullable=False), sa.Column("risk_tier", sa.String(16), nullable=False), sa.Column("automation_candidates", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")), sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.PrimaryKeyConstraint("id", name="pk_correlations"))
    op.create_index("ix_correlations_tenant_tier", "correlations", ["tenant_id", "risk_tier"])
    op.create_index("ix_correlations_entity", "correlations", ["primary_entity_type", "primary_entity_id"])
    op.create_index("ix_correlations_evaluated", "correlations", ["evaluated_at"])
    op.create_table("correlation_ai_briefs", sa.Column("id", uuid, server_default=sa.text("uuid_generate_v4()"), nullable=False), sa.Column("correlation_id", uuid, nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("content", sa.Text(), nullable=False), sa.Column("citations", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")), sa.Column("model_label", sa.String(128), nullable=False, server_default="rag-grounded"), sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.PrimaryKeyConstraint("id", name="pk_correlation_ai_briefs"), sa.ForeignKeyConstraint(["correlation_id"], ["correlations.id"], ondelete="CASCADE", name="fk_correlation_ai_briefs_correlation"))
    op.create_index("ix_correlation_ai_briefs_correlation", "correlation_ai_briefs", ["correlation_id"])


def downgrade() -> None:
    op.drop_table("correlation_ai_briefs")
    op.drop_table("correlations")
