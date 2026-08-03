"""Pydantic request/response models.

Two conventions run through this file:

* Optional numeric intelligence (a CVSS score, an IOC verdict) is ``None``
  when unknown, never a zero or an empty string. Clients must be able to
  distinguish "no exposure" from "not assessed".
* Every list response carries a :class:`Provenance` block naming which feeds
  contributed and which were unhealthy, so a dashboard can state that its
  numbers exclude a failing source instead of silently under-reporting.

A third rule applies to identifiers. When a detail endpoint looks a record up
by primary key, the corresponding list schema must expose that key. Omitting it
does not hide the record; it just leaves the client with no way to reach the
detail view, which is how a list and its detail page drift apart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------


class FeedStatus(BaseModel):
    source: str
    label: str
    status: Literal["success", "partial", "failed", "running", "disabled", "never_run"]
    last_run_at: datetime | None = None
    records_ingested: int = 0
    records_quarantined: int = 0
    error_message: str | None = None


class Provenance(BaseModel):
    """Which feeds stand behind a response."""

    generated_at: datetime
    sources_included: list[str] = Field(default_factory=list)
    sources_degraded: list[str] = Field(default_factory=list)
    is_partial: bool = False
    note: str | None = None


class Page(BaseModel):
    limit: int
    offset: int
    total: int
    has_more: bool


class ListResponse[T](BaseModel):
    data: list[T]
    page: Page
    provenance: Provenance


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------


class ExploitOut(ORMModel):
    source: str
    external_id: str
    title: str | None = None
    url: str | None = None
    author: str | None = None
    stars: int | None = None
    confidence: float
    published_at: datetime | None = None


class VulnerabilityOut(ORMModel):
    #: ``cve_id`` is the addressable key for this record; the detail route is
    #: /vulnerabilities/{cve_id}, so no surrogate id is published.
    cve_id: str
    title: str | None = None
    description: str | None = None

    #: ``None`` means NVD has not published a score. Render as an em dash,
    #: never as 0.0.
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    epss_score: float | None = None

    is_kev: bool = False
    kev_added_at: datetime | None = None
    kev_due_at: datetime | None = None
    vendor: str | None = None
    product: str | None = None

    exploit_maturity: str
    published_at: datetime | None = None
    last_modified_at: datetime | None = None

    sources: list[str] = Field(default_factory=list)
    affected_asset_count: int = 0


class VulnerabilityDetail(VulnerabilityOut):
    cpe_uris: list[str] = Field(default_factory=list)
    exploits: list[ExploitOut] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Ransomware and actors
# --------------------------------------------------------------------------


class RansomwareVictimOut(ORMModel):
    id: str
    display_name: str
    canonical_key: str
    domain: str | None = None
    group_name: str
    country: str | None = None
    sector: str | None = None
    discovered_at: datetime
    disclosure_status: str | None = None

    #: True when the upstream name was a URL or carried a status prefix. The
    #: UI surfaces this rather than pretending the row is clean.
    needs_review: bool = False
    raw_names: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class ThreatActorOut(ORMModel):
    #: Required by the console: /actors/{actor_id} resolves on this value.
    id: str
    canonical_name: str
    display_name: str
    aliases: list[str] = Field(default_factory=list)
    actor_type: str | None = None
    origin_country: str | None = None
    primary_sector: str | None = None
    victim_count: int = 0
    attack_techniques: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------


class IndicatorOut(ORMModel):
    #: Required by the console: /iocs/{indicator_id} resolves on this value.
    id: str
    indicator_type: str
    value: str
    #: ``None`` = not yet enriched. This is a real, displayable state.
    verdict: str | None = None
    confidence: float | None = None
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


# --------------------------------------------------------------------------
# Assets and agents
# --------------------------------------------------------------------------


class AssetOut(ORMModel):
    id: str
    hostname: str
    asset_type: str
    criticality: str
    os_family: str | None = None
    os_version: str | None = None
    os_eol: bool = False
    ip_address: str | None = None
    exposed_cve_count: int = 0
    risk_score: int | None = None
    tags: list[str] = Field(default_factory=list)


class ExposureItem(BaseModel):
    cve_id: str
    cvss_score: float | None = None
    severity: str | None = None
    is_kev: bool
    exploit_maturity: str
    matched_via: str
    detected_at: datetime
    sla_due_at: datetime | None = None
    sla_breached: bool = False


class AssetExposureResponse(BaseModel):
    asset: AssetOut
    exposures: list[ExposureItem]
    provenance: Provenance


class AgentOut(ORMModel):
    id: str
    version: str
    os_family: str
    status: str
    asset_id: str | None = None
    cert_expires_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    enrolled_at: datetime | None = None


# --- Agent gateway payloads ---


class EnrollmentRequest(BaseModel):
    """Sent once by a freshly installed agent.

    Only a CSR is accepted. The private key is generated on the endpoint and
    must never be transmitted.
    """

    hostname: str = Field(min_length=1, max_length=255)
    os_family: Literal["windows", "linux", "macos"]
    os_version: str | None = None
    agent_version: str = Field(min_length=1, max_length=32)
    csr_pem: str = Field(min_length=1)
    mac_address: str | None = None


class EnrollmentResponse(BaseModel):
    agent_id: str
    asset_id: str
    certificate_pem: str
    ca_chain_pem: str
    certificate_expires_at: datetime
    heartbeat_interval_seconds: int


class SoftwareItem(BaseModel):
    name: str = Field(max_length=255)
    version: str | None = Field(default=None, max_length=128)
    vendor: str | None = Field(default=None, max_length=255)
    cpe_uri: str | None = Field(default=None, max_length=512)


class HeartbeatRequest(BaseModel):
    """Periodic agent check-in.

    Deliberately absent: file contents, keystrokes, clipboard, browser
    history, credentials, screenshots and network payloads. The agent is an
    inventory collector, not surveillance, and the schema enforces that
    boundary.
    """

    agent_version: str
    os_version: str | None = None
    ip_address: str | None = None
    uptime_seconds: int | None = None
    software: list[SoftwareItem] | None = None


class HeartbeatResponse(BaseModel):
    acknowledged_at: datetime
    next_heartbeat_seconds: int
    certificate_expires_at: datetime | None = None
    certificate_renewal_due: bool = False


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------


class ApiKeyOut(ORMModel):
    id: str
    name: str
    #: Display form only, e.g. ``ngs_live_7f3a…c21b``.
    masked_key: str
    scopes: list[str] = Field(default_factory=list)
    rate_limit_per_hour: int
    status: str
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime

    #: A revoked key stays listed. Withholding the reason would leave the
    #: record of what once had access without the record of why it was taken
    #: away, so both are published.
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(min_length=1)
    rate_limit_per_hour: int = Field(default=1000, ge=1, le=100_000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    agent_key: bool = False


class ApiKeyCreated(ApiKeyOut):
    #: Returned exactly once, at creation. Never retrievable again.
    raw_key: str
    warning: str = "Store this key now. It is hashed with Argon2id and cannot be shown again."


# --------------------------------------------------------------------------
# AI
# --------------------------------------------------------------------------


class Citation(BaseModel):
    entity_type: str
    entity_id: str
    title: str
    source: str | None = None
    url: str | None = None


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    top_k: int = Field(default=12, ge=1, le=50)


class ChatResponse(BaseModel):
    answer: str
    #: Every claim must be traceable. An empty list means the model had no
    #: grounding and the answer should be treated as unsupported.
    citations: list[Citation] = Field(default_factory=list)
    provenance: Provenance


class ReportRequest(BaseModel):
    template: Literal[
        "executive_brief",
        "threat_advisory",
        "ransomware_landscape",
        "asset_exposure",
        "compliance_pack",
        "ioc_hunting_pack",
    ]
    title: str | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    focus_cve_id: str | None = None


class ReportOut(ORMModel):
    id: str
    template: str
    title: str
    status: str
    progress: int
    period_start: datetime | None = None
    period_end: datetime | None = None
    content_markdown: str | None = None
    citations: list = Field(default_factory=list)
    generation_seconds: float | None = None
    error_message: str | None = None
    created_at: datetime
