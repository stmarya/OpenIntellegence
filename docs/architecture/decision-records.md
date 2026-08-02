# Architecture Decision Records

Each ADR records a significant architectural or design decision made for OpenIntelligence. Records are append-only; superseded decisions link forward to their replacement.

---

## ADR-001 — Multi-tenancy via `tenant_id` column filtering

**Status:** Accepted  
**Date:** Initial architecture

### Context
OpenIntelligence is designed to serve multiple organizations (tenants) from a single deployment. Tenant isolation must be enforced at the data layer, not assumed from application-level routing.

### Decision
Every tenant-owned entity carries a non-nullable `tenant_id` (UUID) column. All reads and writes for tenant-owned data filter on `tenant_id` using the authenticated principal's tenant. There is no shared-data shortcut that bypasses this filter.

### Consequences
- A 404 for a resource that exists under a different tenant is indistinguishable from a genuine 404; this prevents cross-tenant existence oracles.
- New domain models must include `tenant_id` before any feature using them can be considered tenant-safe.
- Tests must verify that a principal from Tenant A cannot read or mutate a record owned by Tenant B.

### Alternatives considered
- Row-level security (RLS) at the PostgreSQL layer: provides a deeper guarantee but adds operational complexity and requires a connection-per-tenant or `SET LOCAL` pattern. Deferred to a future hardening phase.
- Separate schemas or databases per tenant: too operationally expensive at this stage.

---

## ADR-002 — Provenance as a first-class field

**Status:** Accepted  
**Date:** Initial architecture

### Context
Legacy collector scripts embedded credentials in source code and had no provenance tracking, making it impossible to trace a claim back to the feed that produced it. A merged record could have come from anywhere.

### Decision
Every normalized intelligence record retains:
- `source` (provider name) and `source_run_id` (the ingestion run that produced it)
- Collected, observed, and published timestamps when the source provides them
- Ingestion timestamp and normalization version
- Confidence and enrichment state
- Reference to the original/raw payload where retention permits

### Consequences
- Analysts can trace any claim to a specific feed and ingestion run.
- Malformed source data is quarantined with its raw payload preserved, enabling replay after parser fixes.
- Provenance metadata appears in list responses; degraded feeds are visible rather than silently missing.

---

## ADR-003 — UUID identity for new domain entities

**Status:** Accepted  
**Date:** Initial architecture

### Context
The initial migration uses PostgreSQL's `uuid_generate_v4()` for primary keys. Several feature branches independently introduced domain models; some used integer sequences instead.

### Decision
New CTI and workflow domain entities use UUID primary keys (`uuid-ossp` extension, `uuid_generate_v4()` server default). Integer sequences are not used for new entities. The integration PR (PR #14) enforces this as part of schema parity.

### Consequences
- IDs are globally unique without coordination; safe to expose in API responses.
- Avoids sequential ID enumeration attacks.
- Slightly larger index footprint than integers; acceptable for this workload.

---

## ADR-004 — PostgreSQL as primary store with outbox pattern

**Status:** Accepted  
**Date:** Initial architecture

### Context
OpenIntelligence requires transactional consistency for workflow state (investigations, cases, approvals, alerts) and auditability for automation actions.

### Decision
PostgreSQL (TimescaleDB HA image) is the primary transactional store. Connector delivery uses a database-backed outbox table with lease semantics, idempotency keys, and dead-letter progression rather than an external message broker.

Outbox delivery:
1. A connector action is written to the outbox table within the same transaction as the triggering business event.
2. A worker claims available outbox records using `FOR UPDATE SKIP LOCKED`.
3. Delivery attempts are retried with bounded backoff (configurable via `CONNECTOR_MAX_ATTEMPTS`).
4. Terminal failures move the record to `dead_letter` state rather than silently dropping it.
5. An expired lease may be safely reclaimed by another worker instance.

### Consequences
- No external message broker dependency; reduces operational surface area.
- Transactional outbox guarantees at-least-once delivery semantics within a single PostgreSQL deployment.
- Worker crash safety requires correct lease recovery (PR #11).

---

## ADR-005 — Approval-first automation

**Status:** Accepted  
**Date:** Initial architecture

### Context
The platform connects threat intelligence to connector delivery and, in future, endpoint command execution. Fully automated dispatch based on AI output or alert signals carries significant blast radius risk.

### Decision
All high-impact automation (connector delivery, playbook dispatch, endpoint commands) begins in `proposed` state and transitions to dispatchable only after an explicit authorized approval. AI output alone is insufficient authorization for any destructive or externally-visible action.

### Consequences
- Analysts retain control over automation decisions even when AI provides recommendations.
- Approval is an audited event; the approver, timestamp, and decision are persisted.
- Automation throughput is lower by design; this is acceptable given the risk profile.
- AI brief write authorization requires `write` scope minimum (PR #12).

---

## ADR-006 — RAG grounding with mandatory citation

**Status:** Accepted  
**Date:** Initial architecture

### Context
LLM-generated content without grounding will invent CVE details, threat actor attributions, and exposure assessments that are not in the platform's data. This is especially dangerous in a security context.

### Decision
The RAG service always retrieves relevant platform records before generating any factual analyst claim. Citations (source records that supported the response) are stored alongside generated output. When retrieval returns no supporting evidence, the response is explicitly labelled `unverified` or withheld rather than relying on the model's general knowledge.

### Consequences
- Every AI claim has a traceable evidence chain within the platform's own records.
- Absent evidence produces an explicit `unverified` signal, not silence or fabrication.
- The `rag_top_k` setting controls retrieval breadth (default: 12); increasing it improves coverage at higher latency.
- OpenAI-compatible base URL is configurable (`LLM_BASE_URL`) to support self-hosted gateways that keep intelligence data off third-party providers.

---

## ADR-007 — Unknown-state semantics

**Status:** Accepted  
**Date:** Initial architecture

### Context
Legacy collectors coerced missing values to safe-looking defaults (e.g., CVSS 0.0, "no attribution", "clean IOC") that were indistinguishable from actual low-risk assessments. This masked risk.

### Decision
Unknown, unenriched, stale, and disputed states are explicit domain values, never coerced:

| Field | Unknown representation |
|---|---|
| `cvss_score` | `null` (not `0.0`) |
| IOC enrichment state | `unenriched` (not `clean`) |
| Threat actor attribution | `partial`, `disputed`, or multi-party fields |
| Endpoint agent status | `stale` (not removed or shown as healthy) |
| AI-generated output without evidence | `unverified` label, not withheld silently |

### Consequences
- Analysts see risk uncertainty rather than false confidence.
- API consumers must handle `null` and explicit state values; a field being absent is different from being confirmed safe.
- UI layers must not convert these states to "safe" defaults without analyst action.

---

## ADR-008 — Forward-only migrations

**Status:** Accepted  
**Date:** Initial architecture

### Context
Rewriting migration history in a deployed environment destroys the lineage record and can leave databases in an inconsistent state that is difficult to detect and harder to repair.

### Decision
Alembic migration revisions are forward-only append-only in deployed environments:
- `alembic heads` must return exactly one revision at all times.
- Destructive changes (column drops, type changes) are only permitted in a forward migration that includes a safe data migration step.
- Rollback to a prior state uses a forward "undo" migration during development, or a tested backup restore in production.
- The `alembic_version` table must not be manually edited to skip or reorder migrations.

### Consequences
- Migration history is a reliable audit trail of schema evolution.
- CI must verify that `alembic upgrade head` succeeds from a clean state before merge.
- Feature branches that introduce competing migrations must be linearized by the integration PR (PR #14) before any deployment.
