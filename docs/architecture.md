# Architecture

## Layers

1. **Ingestion** — pulls external intelligence sources, normalizes them into platform entities, and stamps provenance.
2. **Core API** — FastAPI application exposing `/api/v1`, tenant-scoped and authenticated on every route.
3. **Persistence** — relational store with Alembic migrations; every domain table carries a tenant discriminator.
4. **Detection and correlation** — bounded rule evaluation producing alerts with fingerprint-based idempotency and cooldown.
5. **Automation and orchestration** — playbooks, runs, and an outbox delivered by workers that own only configured connector actions.
6. **Control plane** — endpoint intent requests with approval policy and no execution path.
7. **AI layer** — retrieval-grounded chat and report generation over platform evidence only.
8. **Frontend** — Next.js application consuming the REST API through a typed boundary.

## Request flow

```
client -> Next.js route -> typed API client -> /api/v1 -> tenant guard
       -> service layer -> repository -> database
```

## Background flow

```
scheduler -> alert evaluation worker -> alert + fingerprint
          -> orchestration proposal -> approval -> outbox row
          -> connector delivery worker (configured actions only) -> external system
          -> internal automation worker (case/report actions only)
```

## Boundaries that must not blur

- Connector delivery never handles internal actions or endpoint intents.
- Internal workers never produce LLM-written report bodies.
- Endpoint intents never create ordinary automation outbox rows.
