"""Initial schema.

Creates the core tables plus three things SQLAlchemy models cannot express:
the ``vector`` and ``timescaledb`` extensions, a pgvector HNSW index for RAG
retrieval, and TimescaleDB hypertables for the two append-heavy tables.

Revision ID: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pgvector powers semantic retrieval; TimescaleDB partitions the
    # time-series tables. Both must exist before any table that uses them.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # ------------------------------------------------------------------
    # Reference data
    # ------------------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )

    # ------------------------------------------------------------------
    # Ingestion bookkeeping
    # ------------------------------------------------------------------
    op.create_table(
        "source_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_fetched", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_ingested", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_quarantined", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_source_runs"),
    )
    op.create_index("ix_source_runs_source_started", "source_runs", ["source", "started_at"])

    op.create_table(
        "quarantined_records",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("source_run_id", sa.UUID(), nullable=True),
        sa.Column("reason", sa.String(255), nullable=False),
        # The raw payload is kept so a parser fix can replay the record.
        sa.Column("raw_payload", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_quarantined_records"),
    )
    op.create_index(
        "ix_quarantined_records_source_reason", "quarantined_records", ["source", "reason"]
    )

    # ------------------------------------------------------------------
    # Intelligence
    # ------------------------------------------------------------------
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        # Nullable on purpose: an unscored CVE is not a 0.0 CVE.
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("is_kev", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("kev_added_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("cpe_uris", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("exploit_maturity", sa.String(16), server_default="unknown", nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        # Provenance. The legacy collectors had no equivalent, so a merged
        # record could not be traced back to the feed that produced it.
        sa.Column("sources", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_vulnerabilities"),
        sa.UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"),
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_is_kev", "vulnerabilities", ["is_kev"])
    op.create_index("ix_vulnerabilities_cvss", "vulnerabilities", ["cvss_score"])
    op.create_index(
        "ix_vulnerabilities_cpe",
        "vulnerabilities",
        ["cpe_uris"],
        postgresql_using="gin",
    )

    op.create_table(
        "exploits",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("vulnerability_id", sa.UUID(), nullable=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("platform", sa.String(64), nullable=True),
        sa.Column("stars", sa.Integer(), nullable=True),
        # GitHub PoC search is noisy; confidence gates it out of the UI.
        sa.Column("confidence", sa.Float(), server_default="0.5", nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_run_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_exploits"),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name="fk_exploits_vulnerability_id_vulnerabilities",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("source", "external_id", name="uq_exploits_source_external_id"),
    )

    op.create_table(
        "threat_actors",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("canonical_name", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("aliases", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("actor_type", sa.String(64), nullable=True),
        sa.Column("origin_country", sa.String(64), nullable=True),
        sa.Column("primary_sector", sa.String(128), nullable=True),
        sa.Column("victim_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "attack_techniques", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sources", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_threat_actors"),
        sa.UniqueConstraint("canonical_name", name="uq_threat_actors_canonical_name"),
    )

    op.create_table(
        "ransomware_victims",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        # Canonical key drives de-duplication across the three leak feeds.
        sa.Column("canonical_key", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(512), nullable=False),
        # Every upstream spelling is preserved so a merge can be audited.
        sa.Column("raw_names", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("group_name", sa.String(128), nullable=False),
        sa.Column("country", sa.String(64), nullable=True),
        sa.Column("sector", sa.String(128), nullable=True),
        sa.Column("website", sa.String(512), nullable=True),
        sa.Column("screenshot_url", sa.String(1024), nullable=True),
        sa.Column("disclosure_status", sa.String(32), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("needs_review", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("sources", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("source_run_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_ransomware_victims"),
        sa.UniqueConstraint(
            "canonical_key",
            "group_name",
            "discovered_at",
            name="uq_ransomware_victims_canonical_key_group_name_discovered_at",
        ),
    )
    op.create_index("ix_ransomware_victims_group", "ransomware_victims", ["group_name"])
    op.create_index("ix_ransomware_victims_discovered", "ransomware_victims", ["discovered_at"])

    op.create_table(
        "indicators",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        # NULL verdict means "not yet enriched" — a real, displayable state.
        sa.Column("verdict", sa.String(16), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("tags", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("sources", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_indicators"),
        sa.UniqueConstraint("indicator_type", "value", name="uq_indicators_type_value"),
    )
    op.create_index("ix_indicators_verdict", "indicators", ["verdict"])

    # ------------------------------------------------------------------
    # Assets and agents
    # ------------------------------------------------------------------
    op.create_table(
        "assets",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("asset_type", sa.String(32), server_default="endpoint", nullable=False),
        sa.Column("criticality", sa.String(16), server_default="medium", nullable=False),
        sa.Column("os_family", sa.String(32), nullable=True),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("os_eol", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("ip_address", sa.dialects.postgresql.INET(), nullable=True),
        sa.Column("mac_address", sa.String(32), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("tags", sa.dialects.postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_assets_tenant_id_tenants", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("tenant_id", "hostname", name="uq_assets_tenant_id_hostname"),
    )

    op.create_table(
        "installed_software",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("cpe_uri", sa.String(512), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        # Soft delete: knowing a package *was* installed matters in an incident.
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_installed_software"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_installed_software_asset_id_assets",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_installed_software_cpe", "installed_software", ["cpe_uri"])

    op.create_table(
        "asset_exposures",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("vulnerability_id", sa.UUID(), nullable=False),
        # Which rule produced this match, so a false positive is traceable.
        sa.Column("matched_via", sa.String(32), nullable=False),
        sa.Column("match_evidence", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_asset_exposures"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_asset_exposures_asset_id_assets",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name="fk_asset_exposures_vulnerability_id_vulnerabilities",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_asset_exposures_asset", "asset_exposures", ["asset_id"])
    op.create_index("ix_asset_exposures_vuln", "asset_exposures", ["vulnerability_id"])
    op.create_index("ix_asset_exposures_sla", "asset_exposures", ["sla_due_at"])

    op.create_table(
        "agents",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("os_family", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), server_default="pending", nullable=False),
        sa.Column("cert_serial", sa.String(64), nullable=True),
        sa.Column("cert_fingerprint", sa.String(128), nullable=True),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_agents"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_agents_tenant_id_tenants", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_agents_asset_id_assets", ondelete="SET NULL"
        ),
        sa.UniqueConstraint("cert_serial", name="uq_agents_cert_serial"),
    )
    op.create_index("ix_agents_status", "agents", ["status"])
    op.create_index("ix_agents_heartbeat", "agents", ["last_heartbeat_at"])

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        # Indexed public half. Verification is one PK lookup plus one Argon2
        # call, instead of Argon2 against every stored key.
        sa.Column("key_id", sa.String(32), nullable=False),
        sa.Column("secret_hash", sa.String(255), nullable=False),
        sa.Column("masked_key", sa.String(64), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("scopes", sa.dialects.postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("rate_limit_per_hour", sa.Integer(), server_default="1000", nullable=False),
        sa.Column("status", sa.String(16), server_default="active", nullable=False),
        sa.Column("single_use", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(500), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_api_keys_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("key_id", name="uq_api_keys_key_id"),
    )
    op.create_index("ix_api_keys_status", "api_keys", ["status"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("details", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action", "created_at"])

    # ------------------------------------------------------------------
    # AI
    # ------------------------------------------------------------------
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("template", sa.String(64), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("status", sa.String(16), server_default="queued", nullable=False),
        sa.Column("progress", sa.Integer(), server_default="0", nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_markdown", sa.Text(), nullable=True),
        # Without citations an AI report is an unfalsifiable claim.
        sa.Column("citations", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("generation_seconds", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_reports_tenant_id_tenants",
            ondelete="CASCADE",
        ),
    )

    op.create_table(
        "document_chunks",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_document_chunks"),
    )
    # Dimensionality is tied to the embedding model. Changing the model
    # requires a re-index, not just a settings change.
    op.execute("ALTER TABLE document_chunks ADD COLUMN embedding vector(1536)")
    op.execute(
        "CREATE INDEX ix_document_chunks_embedding ON document_chunks "
        "USING hnsw (embedding vector_cosine_ops)"
    )
    op.create_index(
        "ix_document_chunks_entity", "document_chunks", ["entity_type", "entity_id"]
    )

    # ------------------------------------------------------------------
    # TimescaleDB hypertables
    # ------------------------------------------------------------------
    # These two tables grow monotonically and are almost always queried by
    # time range, which is exactly the case hypertables are built for.
    op.execute(
        "SELECT create_hypertable('source_runs', 'started_at', "
        "migrate_data => true, if_not_exists => true)"
    )
    op.execute(
        "SELECT create_hypertable('ransomware_victims', 'discovered_at', "
        "migrate_data => true, if_not_exists => true)"
    )


def downgrade() -> None:
    for table in (
        "document_chunks",
        "reports",
        "audit_logs",
        "api_keys",
        "agents",
        "asset_exposures",
        "installed_software",
        "assets",
        "indicators",
        "ransomware_victims",
        "threat_actors",
        "exploits",
        "vulnerabilities",
        "quarantined_records",
        "source_runs",
        "tenants",
    ):
        op.drop_table(table)
