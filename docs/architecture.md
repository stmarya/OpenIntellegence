# Architecture

## Logical components

```text
External feeds / TAXII / APIs ─┐
Endpoint agents ───────────────┼─> Ingestion & normalization ─> PostgreSQL
Tenant API clients ────────────┘                │                    │
                                                  ├─> Search / graph / vector retrieval
                                                  ├─> Correlation & alert evaluation
                                                  ├─> Cases, reports, and automation
                                                  └─> Provenance and audit records

Analyst UI / API ─> FastAPI /api/v1 ─> scoped tenant dependencies ─> domain services
                                                       │
                                                       └─> approval-first outbox ─> Slack / Jira / SIEM / internal workers
```

## Core services

- **FastAPI API:** versioned REST interface; validates input, resolves tenant context, and enforces scopes.
- **PostgreSQL/TimescaleDB:** source of truth for tenant data, events, cases, assets, and automation state.
- **Alembic:** forward migration history for schema changes; must have one linear head.
- **Redis:** rate limiting and future transient workload coordination.
- **Object storage:** original artifacts and report assets; not a replacement for normalized records.
- **Vector retrieval:** document chunks for grounded RAG. Responses must retain citations.
- **Workers:** ingestion, alert evaluation, report generation, connector delivery, and eventually endpoint command delivery.

## Trust boundaries

1. Tenant identity is established by API key authentication and scope checks.
2. Every tenant-owned query must filter by `tenant_id`; IDs alone are never authorization.
3. External data is untrusted until normalized, scored, and retained with source provenance.
4. AI may summarize retrieved facts, but may not invent facts or execute risky actions.
5. Automation begins as `proposed`; dispatch is permitted only after approval requirements are satisfied.

## Data principles

- Provenance is mandatory for CTI claims.
- Unknown CVSS is `null`, never `0.0`.
- An unenriched IOC is an explicit state, never a clean verdict.
- Attribution supports partial/disputed evidence rather than binary certainty.
- Stale endpoint agents remain visible; silence is not health.
