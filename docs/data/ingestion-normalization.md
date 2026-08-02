# Ingestion and Normalization

This document describes the end-to-end lifecycle of an intelligence record from source arrival to enrichment-ready storage, including error handling, source health, and acceptance criteria.

---

## Lifecycle overview

```
External source (NVD, OTX, Ransomware.live Pro, GitHub PoC)
        │
        ▼ 1. Input / fetch
[Connector.fetch()] ─── HTTP request, pagination, credential check
        │
        ▼ 2. Validation
[parse / schema check] ─── reject malformed records → quarantine
        │
        ▼ 3. Normalize
[normalize.py] ─── field mapping, timestamp parsing, identifier canonicalization
        │
        ▼ 4. Deduplicate
[upsert by stable key] ─── merge evidence, preserve provenance, do not overwrite
        │
        ▼ 5. Provenance
[set source, source_run_id, ingested_at] ─── immutable after write
        │
        ▼ 6. Quarantine (error path)
[QuarantinedRecord] ─── raw_payload retained for replay
        │
        ▼ 7. Enrichment (async / future)
[embedding, CPE match, KEV check] ─── updates existing records
        │
        ▼
Queryable, provenance-bearing records in PostgreSQL
```

---

## Stage 1 — Input / fetch

**Owned by:** `app/ingest/connectors.py` + `app/ingest/base.py`

Each connector is registered in the `ConnectorRegistry` singleton. A connector implements `BaseConnector.fetch()` and returns an iterable of raw source records.

| Connector | Source | Credential key | Behavior if credential absent |
|---|---|---|---|
| `nvd` | NIST NVD CVE API | `NVD_API_KEY` | Runs at the unauthenticated rate limit |
| `otx` | AlienVault OTX | `OTX_API_KEY` | Skipped; logged as `unconfigured` |
| `ransomware_live` | Ransomware.live Pro | `RANSOMWARE_LIVE_API_KEY` | Skipped; logged as `unconfigured` |
| `github_poc` | GitHub search API | `GITHUB_TOKEN` | Runs at anonymous rate limit; lower quota |

**Behavior on HTTP failure:**
- Transient (5xx, timeout): logged as error; `SourceRun.status` set to `partial` or `failed`
- Authentication failure (401/403): connector marked `auth_error`; run aborted for that source
- Rate limit (429): retry after `Retry-After` header if present; otherwise abort and mark `rate_limited`

**Source health signal:** Every run creates a `SourceRun` record. The `GET /feeds` endpoint shows the health of all registered connectors, including ones that have never run (`never_run`).

---

## Stage 2 — Validation

**Owned by:** `app/ingest/normalize.py` (field-level checks) + `app/ingest/pipeline.py` (quarantine routing)

Validation checks applied before normalization:

| Check | Rejection reason |
|---|---|
| Required identifier present (`cve_id`, `canonical_name`, `value`) | `missing_identifier` |
| Timestamp parseable | `invalid_timestamp` |
| Numeric field in valid range (e.g., CVSS 0.0–10.0) | `invalid_numeric` |
| Record body not empty | `empty_payload` |
| Source-specific schema requirements | `schema_violation` |

**On validation failure:** the raw record (with the original source payload) is written to `quarantined_records` with the `reason` field set. The `SourceRun.records_quarantined` counter is incremented. Processing continues with the next record; a single bad record does not abort the run.

---

## Stage 3 — Normalize

**Owned by:** `app/ingest/normalize.py`

Normalization maps source-specific fields to the canonical ORM schema:

| Operation | Rule |
|---|---|
| Identifier canonicalization | CVE IDs uppercased; IOC values lowercased for IP/domain/hash types |
| Timestamp normalization | All timestamps converted to timezone-aware UTC |
| Severity mapping | Source-specific labels mapped to `critical/high/medium/low/none` |
| Null preservation | Unknown/absent values preserved as `NULL`; never coerced to 0, `false`, or `clean` |
| Unknown CVSS | `cvss_score = NULL` if source does not provide a score |
| Unenriched IOC | `verdict = NULL`, not `clean` |
| Attribution uncertainty | Multi-party or disputed origin recorded; not collapsed to single value |

**Normalization version:** the version of the normalization logic is intended to be recorded per record so that replay (after a parser fix) can be targeted at old normalization-version records. This field is marked **[planned]** until the schema change is merged.

---

## Stage 4 — Deduplicate

**Owned by:** `app/ingest/pipeline.py`

Deduplication uses stable natural keys that identify an entity uniquely across runs:

| Entity | Deduplication key |
|---|---|
| `Vulnerability` | `cve_id` |
| `ThreatActor` | `canonical_name` |
| `RansomwareVictim` | `(group_name, canonical_key)` |
| `Indicator` | `(indicator_type, value)` |
| `Exploit` | `(source, external_id)` |

**Merge behavior:**
- An existing record matched by the natural key is updated, not replaced.
- Source provenance arrays (`sources`) are appended to, never overwritten.
- `first_seen` is preserved from the original ingest; `last_seen` is updated.
- Raw source fields that have changed are updated; fields not present in the new payload are left unchanged.

**Data-quality rule:** deduplication merges operationally identical events without erasing source evidence. It is not a delete-and-replace operation.

---

## Stage 5 — Provenance

**Owned by:** pipeline write path and `app/services/provenance.py` (query side)

Every stored record carries:

| Field | Value |
|---|---|
| `sources` | Array of contributing connector names |
| `source_run_id` | UUID of the `SourceRun` that last updated this record |
| `created_at` / `updated_at` | Auto-managed by `TimestampMixin` |
| `first_seen` / `last_seen` | Entity-level observation timestamps from source |

List API responses include a `provenance` block (built by `build_provenance()`) that identifies:
- Which feeds contributed to the result set
- Which feeds were degraded or unavailable
- A `note` field when the response is incomplete due to source failures

---

## Stage 6 — Quarantine

**Owned by:** `app/ingest/pipeline.py` + `app/db/models.py` (`QuarantinedRecord`)

Records are quarantined rather than discarded for the following reasons:
- Failed validation (see Stage 2)
- Normalization exception (unexpected source field structure)
- Database constraint violation that cannot be resolved by merge

**Quarantine record contents:**
- `source` and `source_run_id` for traceability
- `reason` code (short string)
- `raw_payload` (full original source record as JSONB)
- `replayed_at` (set when the record is successfully replayed)

**Replay protocol:**
1. Identify quarantine records by source and reason: `GET /quarantine?source=nvd`
2. Fix the normalization logic if the reason is a parser bug
3. Re-trigger ingest for the affected source: `POST /ingest/{source}/run`
4. Successfully replayed records have `replayed_at` set

**Data-quality rule:** quarantined records must never be silently dropped. If a source consistently quarantines records, this is a feed health signal.

---

## Stage 7 — Enrichment

**Status:** partially implemented; some enrichment is performed inline during normalization.

| Enrichment type | Trigger | Status |
|---|---|---|
| CPE → asset matching | Post-ingest job matching `cpe_uris` to `installed_software.cpe_uri` | Foundation available |
| KEV flag update | NVD connector checks CISA KEV catalog | Foundation available |
| EPSS score update | NVD connector fetches EPSS data | Foundation available |
| Vector embedding for RAG | Document chunking and embedding | Foundation available (`document_chunks`) |
| IOC verdict enrichment | External enrichment feed | **[planned]** |
| Threat actor alias resolution | Cross-source alias merging | **[planned]** |

---

## Source health

Source health is queryable at `GET /feeds`. A connector has one of the following health states:

| State | Meaning |
|---|---|
| `never_run` | Connector registered but no runs recorded |
| `ok` | Last run completed successfully |
| `partial` | Last run completed with some quarantined records |
| `failed` | Last run failed entirely |
| `auth_error` | Last run rejected by source authentication |
| `rate_limited` | Last run aborted due to rate limiting |
| `unconfigured` | Required credential is absent |

Feed health degradation must be observable and eligible for alerting (see `docs/operations/observability-and-incidents.md`).

---

## Error handling matrix

| Error class | Handling | Observable signal |
|---|---|---|
| Transient HTTP failure | Retry within run, then abort | `SourceRun.status = partial/failed`, `error_message` set |
| Authentication failure | Abort immediately | `status = auth_error` |
| Validation failure | Quarantine record, continue | `records_quarantined` counter, `quarantined_records` row |
| Normalization exception | Quarantine record, log, continue | Same as validation failure |
| Database constraint error | Quarantine record, log | Same as above |
| Worker crash mid-run | `SourceRun.finished_at = NULL` | Orphaned run visible in `/runs`; requires cleanup |

---

## Acceptance criteria

A connector is considered production-safe when:

- [ ] Records from the source are normalized without data loss or coercion
- [ ] Provenance fields (`sources`, `source_run_id`) are set on every stored record
- [ ] Malformed records are quarantined with original payload preserved
- [ ] Unknown fields (CVSS, verdict, attribution) remain `NULL`, not coerced
- [ ] Deduplication merges without erasing source evidence
- [ ] Source health is visible in `GET /feeds`
- [ ] A run that fails partially still reports accurate `records_fetched` and `records_quarantined`
- [ ] Missing credential disables the connector without crashing the pipeline
- [ ] Replay of quarantined records works after a parser fix
