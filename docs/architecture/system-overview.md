# System Architecture

## Core services

```text
Collectors / feeds / endpoint agents
        ↓
Ingestion + normalization + provenance
        ↓
PostgreSQL/TimescaleDB ── OpenSearch ── object storage
        ↓                     ↓
Intelligence API / Investigation / Alerting / Correlation
        ↓
Approval-first orchestration → Outbox → Slack / Jira / SIEM / internal workers
        ↓
Grounded RAG + cited reports and analyst chat
```

## Responsibilities

- **API service:** authentication, tenant isolation, REST contracts, deterministic domain operations.
- **Database:** canonical transactional records, relationships, auditability, and outbox persistence.
- **Workers:** asynchronous rule evaluation and connector delivery; never embedded in API request handling.
- **AI layer:** retrieves workspace evidence, returns citations, labels unsupported responses as unverified, and cannot autonomously execute risky actions.
- **Endpoint gateway:** mTLS enrollment/heartbeat and future signed command delivery.

## Non-negotiable boundaries

1. Every tenant-owned query filters by `tenant_id`.
2. External source data retains provenance, ingest time, and source-health context.
3. Automation starts as `proposed`; it only dispatches after required approval.
4. Connector secrets live in environment configuration, never database payloads or repository files.
5. Unknown intelligence fields are preserved as unknown—not converted to safe/zero values.
