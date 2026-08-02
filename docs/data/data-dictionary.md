# Data Dictionary

> **Truthfulness note:** This dictionary is based on the current ORM (`app/db/models.py`) and initial migration (`alembic/versions/0001_initial_schema.py`). Fields from feature branches (PRs #3–#13) that are not yet merged into the main codebase are labelled **[planned]**. Do not treat planned fields as available until their migration is merged and integrated.

---

## Conventions

| Convention | Meaning |
|---|---|
| `nullable` | Field may be `NULL`; absence carries domain meaning (e.g., unknown CVSS) |
| `non-null` | Field is required by schema constraint |
| `[planned]` | Field exists in a feature branch but is not yet in the merged schema |
| UUID PK | `uuid_generate_v4()` server default; globally unique, non-sequential |
| BigInt PK | Auto-increment integer; used for high-volume append-heavy tables |

---

## Infrastructure entities

### `tenants`

The top-level isolation boundary. Every tenant-owned record carries a `tenant_id` foreign key.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | Tenant identity; referenced by all tenant-owned tables |
| `slug` | VARCHAR(64) | non-null, unique | URL-safe short name; used in API responses |
| `name` | VARCHAR(255) | non-null | Human-readable display name |
| `is_active` | BOOLEAN | non-null | Inactive tenants cannot authenticate |
| `created_at` | TIMESTAMPTZ | non-null | Auto-set on insert |
| `updated_at` | TIMESTAMPTZ | non-null | Auto-set on update |

**Lifecycle:** tenants are never deleted; they are deactivated.

---

### `api_keys`

Authentication credentials for human users and service accounts. Endpoint agents use mTLS instead.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | |
| `tenant_id` | UUID FK → tenants | non-null | Key is scoped to this tenant |
| `name` | VARCHAR(255) | non-null | Human-readable label |
| `key_id` | VARCHAR(32) | non-null, unique | Public identifier prefix (not secret) |
| `prefix` | VARCHAR(16) | non-null | `ngs_live_` (platform) or `ngs_agnt_` (agent) |
| `secret_hash` | VARCHAR(255) | non-null | Argon2id hash; plaintext shown only at creation |
| `scopes` | TEXT[] | non-null | Granted capability scopes |
| `rate_limit_per_hour` | INTEGER | non-null | Per-key sliding-window quota |
| `status` | VARCHAR(16) | non-null | `active`, `revoked`, `expired` |
| `expires_at` | TIMESTAMPTZ | nullable | `NULL` means no expiry |
| `last_used_at` | TIMESTAMPTZ | nullable | Updated on successful authentication |
| `revoked_at` | TIMESTAMPTZ | nullable | Set when status = `revoked` |
| `single_use` | BOOLEAN | — | `true` for single-use agent enrollment keys |
| `created_by` | VARCHAR(255) | nullable | API key ID of the creator |
| `created_at` | TIMESTAMPTZ | non-null | |
| `updated_at` | TIMESTAMPTZ | non-null | |

**Scopes:** `read`, `write`, `ioc`, `enroll`, `apikey:read`, `apikey:write`, `report:write`, `admin`

**Data-quality rule:** Revoked keys must be retained; do not delete them. Deletion erases the audit trail of what once had access.

---

### `audit_logs`

Append-only record of material mutations. Implemented as a TimescaleDB hypertable.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | Auto-increment |
| `tenant_id` | UUID | nullable | `NULL` for system-level events |
| `actor` | VARCHAR | non-null | e.g., `api_key:<id>` or `system` |
| `action` | VARCHAR(64) | non-null | e.g., `api_key.create`, `api_key.revoke` |
| `entity_type` | VARCHAR(64) | nullable | Resource type acted upon |
| `entity_id` | VARCHAR(255) | nullable | Resource identifier |
| `ip_address` | VARCHAR(45) | nullable | Requester IP (IPv4 or IPv6) |
| `user_agent` | VARCHAR(512) | nullable | HTTP client User-Agent |
| `details` | JSONB | non-null | Action-specific detail; must not contain secrets |
| `created_at` | TIMESTAMPTZ | non-null | |

**Required audit events:** API key creation/revocation, approval decisions, automation dispatch, AI-generated record creation, case state changes.

---

## Intelligence entities

### `vulnerabilities`

CVE-based vulnerability records, primarily from NVD. One row per CVE.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `cve_id` | VARCHAR(32) | non-null, unique | e.g., `CVE-2024-12345` |
| `title` | VARCHAR(512) | nullable | Short NVD title |
| `description` | TEXT | nullable | Full description |
| `cvss_score` | FLOAT | **nullable** | `NULL` = unknown, never coerce to 0.0 |
| `cvss_vector` | VARCHAR(128) | nullable | CVSS vector string |
| `severity` | VARCHAR(16) | nullable | `critical`, `high`, `medium`, `low`, `none` |
| `epss_score` | FLOAT | nullable | EPSS exploitation probability |
| `is_kev` | BOOLEAN | non-null | In CISA Known Exploited Vulnerabilities catalog |
| `kev_added_at` | TIMESTAMPTZ | nullable | KEV catalog add date |
| `kev_due_at` | TIMESTAMPTZ | nullable | KEV remediation due date |
| `vendor` | VARCHAR(255) | nullable | Affected vendor |
| `product` | VARCHAR(255) | nullable | Affected product |
| `cpe_uris` | TEXT[] | non-null | CPE identifiers for asset matching |
| `exploit_maturity` | VARCHAR(16) | non-null | `unknown`, `poc`, `weaponized` |
| `published_at` | TIMESTAMPTZ | nullable | NVD publication date |
| `last_modified_at` | TIMESTAMPTZ | nullable | Last NVD update |
| `sources` | TEXT[] | non-null | Source feeds that contributed this record |
| `first_seen` | TIMESTAMPTZ | nullable | First time ingested by this platform |
| `last_seen` | TIMESTAMPTZ | nullable | Most recent ingestion |
| `created_at` | TIMESTAMPTZ | non-null | |
| `updated_at` | TIMESTAMPTZ | non-null | |

**Relationships:** one-to-many with `exploits`; many-to-many with `assets` via `asset_exposures`.

---

### `exploits`

Exploit evidence records linked to vulnerabilities. Sources include GitHub PoC search.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `vulnerability_id` | BIGINT FK → vulnerabilities | nullable | May be unlinked |
| `source` | VARCHAR(64) | non-null | e.g., `github_poc` |
| `external_id` | VARCHAR(128) | non-null | Source-specific identifier |
| `title` | VARCHAR(512) | nullable | |
| `url` | VARCHAR(1024) | nullable | Link to exploit/PoC |
| `confidence` | FLOAT | non-null | 0.0–1.0; GitHub PoC search is noisy, default 0.5 |
| `stars` | INTEGER | nullable | GitHub stars if applicable |
| `published_at` | TIMESTAMPTZ | nullable | |
| `source_run_id` | UUID FK → source_runs | nullable | Provenance of this record |

**Data-quality rule:** `confidence` must not be treated as truth. Low-confidence exploits should be displayed with appropriate caveats.

---

### `threat_actors`

Named threat groups and individuals. One row per canonical name.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `canonical_name` | VARCHAR(128) | non-null, unique | Stable identity key |
| `display_name` | VARCHAR(255) | non-null | Human-readable name |
| `aliases` | TEXT[] | non-null | Alternative names used by different vendors |
| `actor_type` | VARCHAR(32) | nullable | e.g., `apt`, `ransomware`, `criminal` |
| `primary_sector` | VARCHAR(128) | nullable | Primary targeting sector |
| `origin_country` | VARCHAR(64) | nullable | Attribution; may be disputed |
| `description` | TEXT | nullable | |
| `attack_techniques` | TEXT[] | non-null | MITRE ATT&CK technique IDs |
| `victim_count` | INTEGER | non-null | Aggregated claim count |
| `sources` | TEXT[] | non-null | Contributing feeds |
| `first_seen` | TIMESTAMPTZ | nullable | |
| `last_seen` | TIMESTAMPTZ | nullable | |

**Data-quality rule:** `origin_country` is attribution and may be disputed or multi-party. Do not treat it as confirmed fact.

---

### `ransomware_victims`

Victim claims from ransomware group leak sites (primarily Ransomware.live Pro).

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `canonical_key` | VARCHAR(255) | non-null | Stable deduplication key |
| `display_name` | VARCHAR(512) | non-null | |
| `raw_names` | TEXT[] | non-null | Original source name variants |
| `domain` | VARCHAR(255) | nullable | Victim domain if available |
| `actor_id` | BIGINT FK → threat_actors | nullable | Claiming group |
| `group_name` | VARCHAR(128) | non-null | |
| `country` | VARCHAR(64) | nullable | |
| `sector` | VARCHAR(128) | nullable | |
| `website` | VARCHAR(512) | nullable | |
| `disclosure_status` | VARCHAR(32) | nullable | e.g., `claimed`, `confirmed` |
| `discovered_at` | TIMESTAMPTZ | non-null | |
| `needs_review` | BOOLEAN | non-null | Flagged for analyst review |
| `sources` | TEXT[] | non-null | |
| `source_run_id` | UUID FK → source_runs | nullable | |

---

### `indicators`

Indicators of Compromise (IOCs). Source: OTX and future feeds.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `indicator_type` | VARCHAR(32) | non-null | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email` |
| `value` | VARCHAR(1024) | non-null | Indicator value |
| `verdict` | VARCHAR(16) | nullable | `malicious`, `suspicious`, `clean`; `NULL` = unenriched |
| `confidence` | FLOAT | nullable | 0.0–1.0 |
| `enriched_at` | TIMESTAMPTZ | nullable | Last enrichment timestamp |
| `stix_pattern` | TEXT | nullable | STIX-format detection pattern |
| `tags` | TEXT[] | non-null | |
| `sources` | TEXT[] | non-null | |
| `first_seen` | TIMESTAMPTZ | nullable | |
| `last_seen` | TIMESTAMPTZ | nullable | |

**Data-quality rule:** An unenriched IOC (`verdict = NULL`) is not clean. Never coerce to `clean`.

---

## Asset and agent entities

### `assets`

Endpoint and infrastructure inventory. Tenant-owned.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | |
| `tenant_id` | UUID FK → tenants | non-null | Tenant isolation |
| `hostname` | VARCHAR(255) | non-null | |
| `asset_type` | VARCHAR(32) | non-null | `endpoint`, `server`, `network_device` |
| `criticality` | VARCHAR(16) | non-null | `critical`, `high`, `medium`, `low` |
| `os_family` | VARCHAR(32) | nullable | `windows`, `linux`, `macos` |
| `os_version` | VARCHAR(128) | nullable | |
| `os_eol` | BOOLEAN | non-null | Whether OS has reached end-of-life |
| `ip_address` | INET | nullable | |
| `mac_address` | VARCHAR(32) | nullable | |
| `exposed_cve_count` | INTEGER | non-null | Cached count; updated by exposure job |
| `risk_score` | INTEGER | nullable | Computed exposure score |
| `tags` | TEXT[] | non-null | |
| `meta` | JSONB | non-null | Extensible attributes |

---

### `installed_software`

Software inventory per asset. Used for CPE-based vulnerability matching.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `asset_id` | UUID FK → assets | non-null | |
| `name` | VARCHAR(255) | non-null | |
| `version` | VARCHAR(128) | nullable | |
| `vendor` | VARCHAR(255) | nullable | |
| `cpe_uri` | VARCHAR(512) | nullable | Used to link to vulnerabilities |

---

### `asset_exposures`

Links assets to vulnerabilities they are exposed to.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `asset_id` | UUID FK → assets | non-null | |
| `vulnerability_id` | BIGINT FK → vulnerabilities | non-null | |
| `matched_via` | VARCHAR(32) | non-null | `cpe`, `hostname`, `manual` |
| `detected_at` | TIMESTAMPTZ | non-null | When exposure was first detected |
| `resolved_at` | TIMESTAMPTZ | nullable | When patched/resolved; `NULL` = active |
| `sla_due_at` | TIMESTAMPTZ | nullable | Remediation SLA deadline |

---

### `agents`

Enrolled endpoint agents. Use mTLS certificates for authentication.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | |
| `tenant_id` | UUID FK → tenants | non-null | |
| `asset_id` | UUID FK → assets | nullable | Associated asset if linked |
| `version` | VARCHAR(32) | non-null | Agent software version |
| `os_family` | VARCHAR(32) | non-null | |
| `status` | VARCHAR(16) | non-null | `enrolled`, `active`, `stale`, `revoked` |
| `cert_serial` | VARCHAR(64) | nullable, unique | TLS certificate serial |
| `cert_fingerprint` | VARCHAR(95) | nullable | |
| `cert_issued_at` | TIMESTAMPTZ | nullable | |
| `cert_expires_at` | TIMESTAMPTZ | nullable | |
| `enrolled_at` | TIMESTAMPTZ | nullable | |
| `last_heartbeat_at` | TIMESTAMPTZ | nullable | `NULL` or stale = visible as stale |
| `last_inventory_at` | TIMESTAMPTZ | nullable | Last software inventory sync |
| `revoked_at` | TIMESTAMPTZ | nullable | |
| `revocation_reason` | VARCHAR(255) | nullable | |

**Lifecycle:** `enrolled` → `active` (heartbeat received) → `stale` (missed heartbeats) → `revoked` (manual or expiry).

**Data-quality rule:** A stale agent is never treated as healthy. Missing heartbeat threshold = `AGENT_STALE_AFTER_MISSED` × `AGENT_HEARTBEAT_INTERVAL_SECONDS`.

---

## Ingestion bookkeeping

### `source_runs`

One record per ingestion run per connector.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | |
| `source` | VARCHAR(64) | non-null | Connector name (e.g., `nvd`, `otx`, `ransomware_live`) |
| `status` | VARCHAR(16) | non-null | `running`, `success`, `partial`, `failed` |
| `started_at` | TIMESTAMPTZ | non-null | |
| `finished_at` | TIMESTAMPTZ | nullable | `NULL` if still running or crashed |
| `records_fetched` | INTEGER | non-null | Total records from source |
| `records_ingested` | INTEGER | non-null | Successfully normalized and stored |
| `records_quarantined` | INTEGER | non-null | Rejected records |
| `error_message` | TEXT | nullable | Error detail if `status = failed` |
| `meta` | JSONB | non-null | Additional run metadata |

---

### `quarantined_records`

Malformed or invalid source records retained for replay.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `source` | VARCHAR(64) | non-null | |
| `source_run_id` | UUID FK → source_runs | nullable | |
| `reason` | TEXT | non-null | Rejection reason |
| `raw_payload` | JSONB | non-null | Original source record |
| `replayed_at` | TIMESTAMPTZ | nullable | Set when successfully replayed |

---

## AI and reporting entities

### `reports`

AI-generated intelligence reports. Tenant-owned.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | UUID PK | non-null | |
| `tenant_id` | UUID FK → tenants | non-null | |
| `template` | VARCHAR(64) | non-null | Template key from `TEMPLATES` registry |
| `title` | VARCHAR(512) | non-null | |
| `status` | VARCHAR(16) | non-null | `queued`, `generating`, `complete`, `failed` |
| `progress` | INTEGER | non-null | 0–100 |
| `period_start` | TIMESTAMPTZ | nullable | Reporting period start |
| `period_end` | TIMESTAMPTZ | nullable | Reporting period end |
| `content_markdown` | TEXT | nullable | Generated report body |
| `artifact_url` | VARCHAR(1024) | nullable | Object storage URL if exported |
| `citations` | JSONB | non-null | Array of supporting evidence records |
| `model` | VARCHAR(64) | nullable | LLM model used |
| `generation_seconds` | FLOAT | nullable | Generation latency |
| `error_message` | TEXT | nullable | Error if `status = failed` |
| `requested_by` | VARCHAR(255) | nullable | API key ID of requester |

---

### `document_chunks`

Vector embeddings for RAG retrieval. Tenant-scoped.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | BIGINT PK | non-null | |
| `tenant_id` | UUID | nullable | `NULL` for global/shared intelligence |
| `entity_type` | VARCHAR(32) | non-null | Source entity type (e.g., `vulnerability`, `indicator`) |
| `entity_id` | VARCHAR(64) | non-null | Source entity ID |
| `content` | TEXT | non-null | Text content of the chunk |
| `embedding` | VECTOR(1536) | nullable | pgvector embedding; `NULL` until computed |
| `meta` | JSONB | non-null | Chunk-level metadata |

**Index:** HNSW pgvector index on `embedding` for approximate nearest-neighbour retrieval.

---

## Planned entities (feature branches — not yet in merged schema)

The following entity groups exist in open PRs (#3–#9) but are not yet available in any deployed environment. They are documented here for reference only.

| Domain | Entities | Integration PR |
|---|---|---|
| Campaigns | `campaigns`, `malware`, `campaign_actors`, `campaign_malware` | PR #5 |
| Investigations | `investigations`, `investigation_entities` | PR #6 |
| Cases | `cases`, `case_tasks`, `case_events` | PR #6 |
| Alerts & rules | `detection_rules`, `alerts`, `alert_events` | PR #7 |
| Sightings | `sightings` | PR #7 |
| Correlation briefs | `correlation_briefs`, `brief_citations` | PR #8 |
| Orchestration | `playbooks`, `playbook_runs`, `outbox_messages` | PR #9 |

**State vocabulary for investigation/case (planned):**

| Entity | States |
|---|---|
| `Investigation` | `open`, `closed`, `archived` |
| `Case` | `open`, `in_progress`, `resolved`, `closed` |
| `CaseTask` | `open`, `in_progress`, `done`, `cancelled` |
| `Alert` | `open`, `acknowledged`, `resolved`, `suppressed` |
| `PlaybookRun` | `proposed`, `approved`, `dispatching`, `complete`, `failed`, `rejected` |
| `OutboxMessage` | `pending`, `leased`, `delivered`, `failed`, `dead_letter` |
