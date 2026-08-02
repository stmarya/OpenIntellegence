"""Add governance surfaces and automation replay audit.
Revision ID: 0009
Revises: 0008
"""
from __future__ import annotations
import sqlalchemy as sa
from alembic import op
revision="0009"; down_revision="0008"; branch_labels=None; depends_on=None
def upgrade()->None:
 op.create_table("detection_content",
  sa.Column("id",sa.String(36),primary_key=True),
  sa.Column("tenant_id",sa.String(36),nullable=False),
  sa.Column("name",sa.String(255),nullable=False),
  sa.Column("content_format",sa.String(32),nullable=False),
  sa.Column("external_id",sa.String(128)),
  sa.Column("description",sa.Text()),
  sa.Column("severity",sa.String(32)),
  sa.Column("status",sa.String(32),nullable=False),
  sa.Column("attack_techniques",sa.JSON(),nullable=False),
  sa.Column("data_sources",sa.JSON(),nullable=False),
  sa.Column("version",sa.String(32)),
  sa.Column("author",sa.String(255)),
  sa.Column("last_validated_at",sa.DateTime(timezone=True)),
  sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
  sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 op.create_index("ix_detection_content_tenant_status","detection_content",["tenant_id","status"])
 op.create_table("intel_collections",
  sa.Column("id",sa.String(36),primary_key=True),
  sa.Column("tenant_id",sa.String(36),nullable=False),
  sa.Column("name",sa.String(255),nullable=False),
  sa.Column("description",sa.Text()),
  sa.Column("purpose",sa.String(255)),
  sa.Column("owner",sa.String(255)),
  sa.Column("member_refs",sa.JSON(),nullable=False),
  sa.Column("is_shared",sa.Boolean(),nullable=False),
  sa.Column("last_curated_at",sa.DateTime(timezone=True)),
  sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
  sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 op.create_index("ix_intel_collections_tenant","intel_collections",["tenant_id"])
 op.create_table("intelligence_requirements",
  sa.Column("id",sa.String(36),primary_key=True),
  sa.Column("tenant_id",sa.String(36),nullable=False),
  sa.Column("code",sa.String(32),nullable=False),
  sa.Column("title",sa.String(255),nullable=False),
  sa.Column("description",sa.Text()),
  sa.Column("priority",sa.String(32),nullable=False),
  sa.Column("status",sa.String(32),nullable=False),
  sa.Column("owner",sa.String(255)),
  sa.Column("covering_sources",sa.JSON(),nullable=False),
  sa.Column("coverage_note",sa.Text()),
  sa.Column("review_due_at",sa.DateTime(timezone=True)),
  sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
  sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 op.create_index("ix_intelligence_requirements_tenant_status","intelligence_requirements",["tenant_id","status"])
 op.create_table("automation_replay_audit",
  sa.Column("id",sa.String(36),primary_key=True),
  sa.Column("tenant_id",sa.String(36),nullable=False),
  sa.Column("source_outbox_id",sa.String(36),nullable=False),
  sa.Column("replay_outbox_id",sa.String(36),nullable=False),
  sa.Column("action",sa.String(64),nullable=False),
  sa.Column("actor",sa.String(255),nullable=False),
  sa.Column("detail",sa.JSON(),nullable=False),
  sa.Column("requested_at",sa.DateTime(timezone=True),nullable=False),
  sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
  sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 op.create_index("ix_automation_replay_audit_tenant","automation_replay_audit",["tenant_id"])
def downgrade()->None:
 op.drop_index("ix_automation_replay_audit_tenant",table_name="automation_replay_audit"); op.drop_table("automation_replay_audit")
 op.drop_index("ix_intelligence_requirements_tenant_status",table_name="intelligence_requirements"); op.drop_table("intelligence_requirements")
 op.drop_index("ix_intel_collections_tenant",table_name="intel_collections"); op.drop_table("intel_collections")
 op.drop_index("ix_detection_content_tenant_status",table_name="detection_content"); op.drop_table("detection_content")
