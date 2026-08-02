# Component Boundaries

This document defines the concrete modules of the OpenIntelligence backend, their responsibilities, ownership boundaries, and the dependency rules that must not be violated.

---

## Module map

```
app/
├── main.py                    ← FastAPI application factory and lifespan
├── core/
│   ├── config.py              ← Pydantic-Settings; all env-sourced config
│   ├── deps.py                ← FastAPI dependency injectors (DB, principal, scopes)
│   ├── security.py            ← Key generation, Argon2id hashing, scope enforcement
│   └── ratelimit.py           ← Sliding-window rate limiter (Redis or in-memory)
├── db/
│   ├── base.py                ← SQLAlchemy async engine / session factory
│   └── models.py              ← Canonical ORM models for all domain entities
├── api/
│   ├── schemas.py             ← Pydantic I/O schemas (request/response contracts)
│   └── v1/
│       ├── router.py          ← Single aggregated APIRouter; registered once in main.py
│       ├── intel.py           ← Threat intelligence routes (vulns, actors, IOCs, etc.)
│       ├── assets.py          ← Asset inventory, exposure, agent enrollment, heartbeat
│       ├── admin.py           ← API key lifecycle, feed health, quarantine, ingest trigger
│       └── ai.py              ← RAG chat, report generation and retrieval
├── ingest/
│   ├── base.py                ← Connector registry and base class
│   ├── connectors.py          ← Concrete feed connectors (NVD, OTX, Ransomware.live, GitHub)
│   ├── normalize.py           ← Source-specific normalization and field mapping
│   └── pipeline.py            ← Ingestion orchestration: fetch → normalize → store → quarantine
├── services/
│   ├── provenance.py          ← Feed status queries and provenance block construction
│   └── agents.py              ← Endpoint agent business logic
├── ai/
│   ├── rag.py                 ← Vector retrieval, embedding, LLM call, citation assembly
│   └── reports.py             ← Report template definitions and generation orchestration
└── agent_gateway/
    ├── bootstrap_ca.py        ← Development CA generation utility
    └── mtls.py                ← mTLS certificate issuance and verification logic
```

---

## Module responsibilities

### `app/main.py` — Application factory

| Responsibility | Notes |
|---|---|
| Create and configure the FastAPI application | CORS, middleware, exception handlers |
| Lifespan management | Redis ping, rate-limiter setup, connector registry population |
| Mount the v1 router | Calls `app.include_router(api_router, prefix="/api/v1")` exactly once |
| Liveness and readiness probes | `/health` (always 200) and `/health/ready` (checks DB + Redis) |

**Must not:** contain domain logic, database queries, or business rules.

---

### `app/core/` — Cross-cutting infrastructure

| Module | Responsibility |
|---|---|
| `config.py` | Single `Settings` object loaded from environment; `lru_cache` singleton |
| `deps.py` | FastAPI `Depends` factories: `DbSession`, `Principal`, `require_scope` |
| `security.py` | API key prefix generation, Argon2id hashing/verification, scope enum |
| `ratelimit.py` | `RateLimiter` (Redis-backed) and `InMemoryRateLimiter` fallback |

**Dependency rule:** `core` must not import from `api`, `ingest`, `services`, or `ai`. It is the lowest-level internal package and is imported by everything else.

---

### `app/db/` — Persistence layer

| Module | Responsibility |
|---|---|
| `base.py` | `create_async_engine`, session factory, `get_engine()` |
| `models.py` | All SQLAlchemy ORM models; single source of schema truth |

**Owns:** table definitions, relationships, constraints, enum types. Does not contain query logic beyond relationship loading options.

**Dependency rule:** `db` imports only `core.config`. No imports from `api`, `ingest`, `services`, `ai`, or `agent_gateway`.

---

### `app/api/v1/` — REST API layer

| Module | Responsibility |
|---|---|
| `router.py` | Aggregates sub-routers; imported once by `main.py` |
| `intel.py` | Read-heavy CTI routes: vulnerability list/detail, actor list/detail, IOC search, ransomware victims |
| `assets.py` | Asset CRUD, exposure context, agent enrollment (`POST /agents/enroll`), heartbeat (`POST /agents/{id}/heartbeat`) |
| `admin.py` | API key management (create/list/revoke), feed health (`GET /feeds`), quarantine, ingest trigger |
| `ai.py` | `POST /chat/query`, `POST /reports/generate`, `GET /reports`, `GET /reports/{id}` |

**Owns:** request validation, authorization checks (via `require_scope`), HTTP status codes, and response serialization. Does not own business or persistence logic.

**Dependency rule:** `api` imports from `core`, `db`, `services`, `ingest.base`, and `ai`. It must not import directly from `ingest.pipeline` for long-running work (use background tasks or workers).

---

### `app/ingest/` — Data ingestion

| Module | Responsibility |
|---|---|
| `base.py` | `ConnectorRegistry` singleton; `BaseConnector` abstract class |
| `connectors.py` | Registered connectors: NVD, OTX, Ransomware.live Pro, GitHub PoC search |
| `normalize.py` | Per-source field normalization, timestamp parsing, identifier canonicalization |
| `pipeline.py` | `IngestPipeline.run()`: fetch → normalize → upsert → quarantine malformed records → update `SourceRun` |

**Owns:** feed-specific HTTP calls, normalization decisions, quarantine logic, and `SourceRun`/`QuarantinedRecord` writes.

**Dependency rule:** `ingest` imports from `core` and `db`. It must not import from `api` or `ai`. Long-running ingest runs must not block an HTTP request thread — they are triggered by an admin endpoint but run as a synchronous pipeline step (currently) or as a background task.

---

### `app/services/` — Domain services

| Module | Responsibility |
|---|---|
| `provenance.py` | `build_provenance()` — queries `SourceRun` to construct provenance metadata for list responses; `feed_statuses()` for health display |
| `agents.py` | Agent enrollment validation, certificate issuance delegation, heartbeat staleness evaluation |

**Owns:** reusable domain operations that are shared across multiple API routes.

**Dependency rule:** `services` imports from `core` and `db`. Must not import from `api`.

---

### `app/ai/` — AI and RAG layer

| Module | Responsibility |
|---|---|
| `rag.py` | `RagService`: embed query → vector search → retrieve platform records → LLM call → return answer + citations; raises `LlmError` on failure |
| `reports.py` | `ReportGenerator`: template-driven multi-section report using `RagService`; writes `Report` records |

**Owns:** embedding calls, vector retrieval, LLM API calls, citation assembly, grounding enforcement.

**Constraint:** Must retrieve supporting evidence before generating factual claims. If retrieval returns nothing, the response must be explicitly flagged as `unverified`. The AI layer cannot approve, dispatch, or execute automation.

**Dependency rule:** `ai` imports from `core`, `db`, and `services`. Must not import from `api` or `ingest`.

---

### `app/agent_gateway/` — Endpoint agent gateway

| Module | Responsibility |
|---|---|
| `bootstrap_ca.py` | CLI utility to generate a development CA certificate and key |
| `mtls.py` | Certificate signing for enrolled agents; mTLS verification helpers |

**Owns:** PKI operations for agent identity. Command execution is not yet implemented.

**Dependency rule:** `agent_gateway` imports from `core`. Must not import from `api`, `ingest`, or `ai`.

---

### `alembic/` — Schema migrations

| Path | Responsibility |
|---|---|
| `alembic.ini` | Migration configuration (DB URL via env) |
| `alembic/env.py` | Migration environment; imports `app.db.models` for autogenerate |
| `alembic/versions/` | Immutable, forward-only revision chain |

**Constraint:** There must be exactly one Alembic head at all times in integrated environments. Migration files are append-only in deployed environments.

---

## Dependency rules summary

```
core  ←  db
core  ←  ingest
core  ←  services
core  ←  ai
core  ←  agent_gateway
core  ←  api

db    ←  ingest
db    ←  services
db    ←  ai
db    ←  api

services ←  api
ai       ←  api
ingest.base ← api

(arrows mean "is imported by")
```

Cycles are prohibited. `core` and `db` are the foundation; nothing in them may import from the layers above.

---

## Workers (planned)

Workers are asynchronous processes that run outside the HTTP request cycle. They are not yet integrated into the main codebase (see `docs/planning/project-status.md` — PR #9, PR #10).

| Worker | Planned module | Responsibility |
|---|---|---|
| `AlertEvaluationWorker` | `app/workers/alert_evaluation.py` | Evaluate enabled rules against new signals, manage cooldowns, write alert records |
| `ConnectorDeliveryWorker` | `app/workers/connector_delivery.py` | Claim outbox messages with lease, deliver to Slack/Jira/SIEM, retry transient failures, dead-letter terminal failures |

**Worker boundary rules:**
- Workers must not be invoked inside an HTTP request handler.
- Workers must use `FOR UPDATE SKIP LOCKED` when claiming outbox messages.
- Workers must apply idempotency keys to prevent double-delivery.
- Network delivery calls belong only in workers, not in API routes.

---

## Planned integrations (feature-branch work)

The following modules exist in feature branches (PRs #3–#13) and are not yet registered in the main router or merged into the ORM:

| Domain | Planned modules | Integration status |
|---|---|---|
| Intelligence Explorer | Extended `intel.py` routes | In review / integration pending (PR #3, #4, #5) |
| Investigation & Cases | `app/api/v1/investigations.py`, `cases.py` | In review / integration pending (PR #6) |
| Alerts & Sightings | `app/api/v1/alerts.py`, `sightings.py` | In review / integration pending (PR #7) |
| Correlation & AI briefs | `app/api/v1/correlation.py` | In review / integration pending (PR #8) |
| Orchestration / outbox | `app/api/v1/playbooks.py` | In review / integration pending (PR #9) |
| Connector runtime | Worker + connector registry | In review / integration pending (PR #10) |

Until these are merged and registered in `router.py`, they are not available in any running environment.
