# Project Plan

## Product statement

**OpenIntelligence is a cyber threat intelligence platform that connects external threat intelligence with internal assets, endpoint telemetry, investigations, and AI-assisted intelligence production.**

## Objectives

1. Ingest and normalize CTI from heterogeneous external sources while retaining provenance.
2. Resolve external intelligence against tenant assets, exposure, telemetry, and sightings.
3. Give analysts evidence-first research, investigation, case, and reporting workflows.
4. Provide grounded AI that cites retrieved records and never silently turns uncertainty into fact.
5. Enable automation only through explicit approval, auditable execution, and constrained connectors.

## Delivery milestones

### M0 — Foundation
API framework, tenant-scoped API keys, rate limits, CTI ingestion/normalization, assets, endpoint enrollment/heartbeat, RAG, reporting, Docker, and baseline migrations.

### M1 — Analyst workspace vertical slices
Intelligence search, actor/IOC detail, campaigns/malware, investigations/cases, alerts/sightings, correlations, and approval-first orchestration.

### M2 — Integration backbone **(current priority)**
- Reconcile ORM, migrations, and API assumptions into one canonical contract.
- Consolidate all `/api/v1` routers.
- Create a single linear Alembic history and one migration head.
- Add schema, route, tenant, scoring, approval, and outbox guard tests.

### M3 — Detection and automation reliability
- Alert evaluation worker and rule cooldown execution.
- Database-resolved correlation evidence.
- Connector capability registry, health, metrics, and dead-letter replay.
- Internal case/report workers; later, signed endpoint command worker.

### M4 — Development validation
Run migrations and service stack in a dedicated development environment; validate API, workers, connectors, RAG behavior, tenant isolation, and failure modes.

### M5 — Production readiness
Observability, backups, retention, incident procedures, secrets management, security review, capacity testing, release process, and controlled rollout.

## Current definition of ready for development validation

The backend is ready only when all of the following are true:

- exactly one Alembic head exists;
- a fresh database upgrades to head successfully;
- ORM metadata, migration schema, and runtime code agree on critical entities;
- all intended API routers are mounted exactly once;
- API key scopes and tenant isolation are tested;
- alert deduplication, correlation scoring, approval state transitions, and outbox lease/retry behavior have deterministic tests;
- no endpoint represents an unknown intelligence value as a clean/zero-risk value.
