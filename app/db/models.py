"""ORM models for the OpenIntelligence platform.

Modelling decisions worth knowing
---------------------------------
* Every ingested entity carries ``source`` and ``source_run_id``. The legacy
  dump kept provenance only in the filename, so merging destroyed it. Here
  provenance is a first-class column and is never optional.
* ``Vulnerability.cvss_score`` is nullable. A missing NVD score is *unknown*,
  not zero, and the API must surface that distinction.
* Ransomware victims are keyed on a canonical join key rather than the raw
  display name, because the three ransomware feeds spell the same victim
  three different ways.
* API keys store only the Argon2id hash of the secret half.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

# JSONB on PostgreSQL, plain JSON elsewhere (keeps the SQLite test suite fast).
JsonType = JSON().with_variant(JSONB(), "postgresql")
StrArray = JSON().with_variant(ARRAY(String), "postgresql")
UuidType = String(36).with_variant(UUID(as_uuid=False), "postgresql")


# ==========================================================================
# Enumerations
# ==========================================================================


class Severity(enum.StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitMaturity(enum.StrEnum):
    """How weaponised a vulnerability is, in ascending order of urgency."""

    UNKNOWN = "unknown"
    NONE = "none"
    POC = "poc"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class AgentStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    STALE = "stale"
    SERVICE_STOPPED = "service_stopped"
    CERT_EXPIRED = "cert_expired"
    UNREACHABLE = "unreachable"
    REVOKED = "revoked"


class ApiKeyStatus(enum.StrEnum):
    ACTIVE = "active"
    EXPIRING = "expiring"
    REVOKED = "revoked"


class RunStatus(enum.StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class ReportStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ==========================================================================
# Tenancy
# ==========================================================================


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ==========================================================================
# Ingest provenance
# ==========================================================================


class SourceRun(Base, TimestampMixin):
    """One execution of one connector.

    Every ingested row points back here, which is what makes the UI able to
    say "AlienVault OTX has been failing since 04:12, these numbers exclude
    it" instead of silently under-reporting.
    """

    __tablename__ = "source_runs"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[RunStatus] = mapped_column(String(16), nullable=False)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    records_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_quarantined: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[str | None] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

    __table_args__ = (Index("ix_source_runs_source_started", "source", "started_at"),)


class QuarantinedRecord(Base, TimestampMixin):
    """A record that failed normalisation.

    Dropping unparseable rows silently is how feeds quietly lose 10% of their
    volume. They are parked here with the raw payload and the reason, so the
    connector can be fixed and the backlog replayed.
    """

    __tablename__ = "quarantined_records"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_run_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("source_runs.id", ondelete="CASCADE"), nullable=False
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JsonType, nullable=False)
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ==========================================================================
# Vulnerabilities
# ==========================================================================


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)

    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)

    # Nullable on purpose: NVD genuinely has not scored some CVEs yet.
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[Severity | None] = mapped_column(String(16), index=True)
    epss_score: Mapped[float | None] = mapped_column(Float)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # CISA KEV is the only feed carrying reliable vendor/product, which makes
    # it the anchor for asset matching.
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vendor: Mapped[str | None] = mapped_column(String(255), index=True)
    product: Mapped[str | None] = mapped_column(String(255), index=True)
    cpe_uris: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)

    exploit_maturity: Mapped[ExploitMaturity] = mapped_column(
        String(16), default=ExploitMaturity.UNKNOWN, nullable=False, index=True
    )

    # Which feeds contributed to this row, e.g. ["nvd", "cisa_kev", "exploitdb"].
    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    exploits: Mapped[list[Exploit]] = relationship(back_populates="vulnerability")

    __table_args__ = (
        Index("ix_vulnerabilities_triage", "is_kev", "exploit_maturity", "cvss_score"),
    )


class Exploit(Base, TimestampMixin):
    """Public exploit or proof-of-concept for a vulnerability."""

    __tablename__ = "exploits"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    vulnerability_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    url: Mapped[str | None] = mapped_column(String(1024))
    author: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(64))

    # GitHub PoC search is extremely noisy — a LaTeX CV and a video-editing
    # plugin both matched "CVE". This score gates what reaches the UI.
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    stars: Mapped[int | None] = mapped_column(Integer)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    source_run_id: Mapped[str | None] = mapped_column(UuidType, ForeignKey("source_runs.id"))

    vulnerability: Mapped[Vulnerability | None] = relationship(back_populates="exploits")

    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_exploits_source_id"),)


# ==========================================================================
# Ransomware
# ==========================================================================


class ThreatActor(Base, TimestampMixin):
    __tablename__ = "threat_actors"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    canonical_name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)

    actor_type: Mapped[str | None] = mapped_column(String(32))
    primary_sector: Mapped[str | None] = mapped_column(String(128))
    origin_country: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)

    attack_techniques: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    victim_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RansomwareVictim(Base, TimestampMixin):
    """A victim posted to a ransomware leak site.

    ``canonical_key`` is what makes cross-feed de-duplication work. The raw
    name is preserved in ``display_name`` and ``raw_names`` so an analyst can
    always see what the feed actually said.
    """

    __tablename__ = "ransomware_victims"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)

    canonical_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_names: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)

    actor_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("threat_actors.id", ondelete="SET NULL"), index=True
    )
    group_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    country: Mapped[str | None] = mapped_column(String(64), index=True)
    sector: Mapped[str | None] = mapped_column(String(128), index=True)
    website: Mapped[str | None] = mapped_column(String(512))
    screenshot_url: Mapped[str | None] = mapped_column(String(1024))
    disclosure_status: Mapped[str | None] = mapped_column(String(32))

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # True when the display name still looks like a URL or carries a status
    # marker. The UI flags these rather than pretending they are clean.
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    source_run_id: Mapped[str | None] = mapped_column(UuidType, ForeignKey("source_runs.id"))

    __table_args__ = (
        UniqueConstraint(
            "canonical_key",
            "group_name",
            "discovered_at",
            name="uq_ransomware_victims_canonical_key_group_name_discovered_at",
        ),
        Index("ix_victims_group_discovered", "group_name", "discovered_at"),
    )


# ==========================================================================
# Indicators of compromise
# ==========================================================================


class Indicator(Base, TimestampMixin):
    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)

    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)

    # "malicious" | "suspicious" | "clean" | None (= not yet enriched).
    # None is a real, displayable state, not an error.
    verdict: Mapped[str | None] = mapped_column(String(16), index=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    stix_pattern: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)

    sources: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (UniqueConstraint("indicator_type", "value", name="uq_indicators_type_value"),)


# ==========================================================================
# Assets and endpoint agents
# ==========================================================================


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(32), default="endpoint", nullable=False)
    criticality: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)

    os_family: Mapped[str | None] = mapped_column(String(32), index=True)
    os_version: Mapped[str | None] = mapped_column(String(128))
    os_eol: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    ip_address: Mapped[str | None] = mapped_column(String(45).with_variant(INET(), "postgresql"))
    mac_address: Mapped[str | None] = mapped_column(String(32))

    exposed_cve_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)

    tags: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    meta: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("tenant_id", "hostname", name="uq_assets_tenant_id_hostname"),
    )


class InstalledSoftware(Base, TimestampMixin):
    """Software inventory reported by the endpoint agent.

    This is the join surface between asset inventory and CVE intelligence:
    CPE here matches ``Vulnerability.cpe_uris``.
    """

    __tablename__ = "installed_software"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(128))
    vendor: Mapped[str | None] = mapped_column(String(255))
    cpe_uri: Mapped[str | None] = mapped_column(String(512), index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("asset_id", "name", "version", name="uq_software_asset_name_version"),
    )


class AssetExposure(Base, TimestampMixin):
    """Materialised link between an asset and a CVE it is exposed to."""

    __tablename__ = "asset_exposures"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[str] = mapped_column(
        UuidType,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    matched_via: Mapped[str] = mapped_column(String(32), nullable=False)
    match_evidence: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        UniqueConstraint("asset_id", "vulnerability_id", name="uq_exposure_asset_vuln"),
    )


class Agent(Base, TimestampMixin):
    """An installed endpoint agent."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        UuidType, ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )

    version: Mapped[str] = mapped_column(String(32), nullable=False)
    os_family: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(
        String(24), default=AgentStatus.PENDING, nullable=False, index=True
    )

    # mTLS identity
    cert_serial: Mapped[str | None] = mapped_column(String(64), unique=True)
    cert_fingerprint: Mapped[str | None] = mapped_column(String(95), index=True)
    cert_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_inventory_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(255))


# ==========================================================================
# API keys
# ==========================================================================


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Public half — indexed so verification is one lookup, not a table scan.
    key_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    # Argon2id hash of the secret half. The raw key is never stored.
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    masked_key: Mapped[str] = mapped_column(String(64), nullable=False)

    scopes: Mapped[list[str]] = mapped_column(StrArray, default=list, nullable=False)
    rate_limit_per_hour: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)

    status: Mapped[ApiKeyStatus] = mapped_column(
        String(16), default=ApiKeyStatus.ACTIVE, nullable=False, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(500))
    single_use: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_by: Mapped[str | None] = mapped_column(String(255))


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)

    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(128))

    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)


# ==========================================================================
# AI reports
# ==========================================================================


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        UuidType, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    template: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        String(16), default=ReportStatus.QUEUED, nullable=False, index=True
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    content_markdown: Mapped[str | None] = mapped_column(Text)
    artifact_url: Mapped[str | None] = mapped_column(String(1024))

    # Which records the model was actually given. Without this an AI report is
    # an unfalsifiable claim.
    citations: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    model: Mapped[str | None] = mapped_column(String(64))
    generation_seconds: Mapped[float | None] = mapped_column(Float)
    error_message: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str | None] = mapped_column(String(128))


class DocumentChunk(Base, TimestampMixin):
    """Retrievable text chunk backing the RAG chat.

    The embedding is a pgvector ``vector(1536)`` column, which is what makes
    ``embedding.cosine_distance(...)`` available in the retrieval query. The
    Alembic migration also creates an HNSW index over it; without that index
    semantic search degrades to a sequential scan as the corpus grows.
    """

    __tablename__ = "document_chunks"

    id: Mapped[str] = mapped_column(UuidType, primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(UuidType, index=True)

    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)

    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: Dimensionality must match Settings.embedding_dimensions; changing the
    #: embedding model requires a re-index, not just a config edit.
    embedding: Mapped[list | None] = mapped_column(Vector(1536), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

    __table_args__ = (Index("ix_chunks_entity", "entity_type", "entity_id"),)
