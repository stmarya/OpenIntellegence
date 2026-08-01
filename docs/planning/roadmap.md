# Delivery Roadmap & Readiness Gates

## Product objective

OpenIntelligence turns external CTI, internal assets, endpoint telemetry, investigation workflows, and grounded AI into analyst-controlled security decisions.

## Current phase — Backend integration hardening

**Exit gate:** one schema contract, one Alembic head, one v1 router registry, and guard tests for schema/routes/tenant safety.

| Priority | Workstream | Outcome |
|---|---|---|
| P0 | Schema parity | ORM, Alembic, and runtime agree on types, fields, constraints, and defaults |
| P0 | Router consolidation | All supported `/api/v1` domains registered once |
| P0 | Migration lineage | Fresh and existing databases upgrade through one linear chain |
| P1 | Alert evaluator | Rules run automatically with cooldown/deduplication |
| P1 | Correlation evidence | Score inputs resolved from platform facts, not solely caller payload |
| P1 | Orchestration hardening | Capabilities, health, replay, internal action workers |

## Development validation gate

Only after P0 is merged:

```bash
pip install -e ".[dev]"
ruff check .
pytest
alembic upgrade head
docker compose up --build
```

Validate health/readiness, scope and tenant isolation, ingestion, endpoint mTLS, RAG citations, cases, alerting, correlation, approval state machine, and outbox retry/dead-letter behavior.

## Deferred product work

- Endpoint agent for Windows, Linux, and macOS
- Detection content and ATT&CK coverage
- Intelligence requirements, collections, import workbench, and data-quality queues
- TAXII/inbound SIEM-SOAR connectors
- API-connected Next.js enterprise UI
