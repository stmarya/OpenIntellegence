# OpenIntelligence — CTI Platform Backend

Backend for a cyber threat intelligence platform: it ingests public and
commercial feeds, correlates them against your own endpoint inventory, and
exposes the result over a versioned REST API with an AI layer on top.

FastAPI · Python 3.12 · PostgreSQL 16 (TimescaleDB + pgvector) · Redis

---

## Quick start

```bash
cp .env.example .env
python -m app.agent_gateway.bootstrap_ca --out ./certs
docker compose up --build
```

The API is available at `http://localhost:8000`, interactive API documentation
at `/docs`, and the analyst console at `http://localhost:3000`.

Without Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
alembic upgrade head
uvicorn app.main:app --reload
pytest
```

## First tenant

Create the first tenant and one privileged API key. The plaintext key is shown
once and is never persisted recoverably.

```bash
python -m app.cli.bootstrap_tenant \
  --slug acme \
  --name "ACME Security"
```

Configure the returned value as server-only `API_SERVICE_KEY`; never expose it
through a `NEXT_PUBLIC_` variable or browser code.

## Investigation graph

The analyst console includes `/graph`, a tenant-scoped visual canvas over
persisted typed CTI relationships. It supports one-to-three-hop traversal,
confidence and relationship filters, node pivots, evidence inspection, local
view snapshots, report-summary copy, and SVG/JSON export. No model-generated
edge is presented as fact.

For an explicitly labelled test graph after tenant bootstrap and migrations:

```bash
docker compose exec api python -m app.cli.seed_graph_demo \
  --tenant-slug acme \
  --confirm-synthetic
```

Open:

```text
http://localhost:3000/graph?entity_type=campaign&entity_id=synthetic-campaign-night-glass&depth=3
```

Every fixture edge is marked `synthetic_test_only`, the command is idempotent,
and it refuses to run in production. See `docs/investigation-graph.md` for the
API contract, truth boundaries, and verification checklist.

---

## Core safety positions

- Missing CVSS is `None`, never `0`.
- An outage is unavailable, never an empty or clean result.
- Synthetic fixtures are test-only and must never be represented as tenant telemetry.
- API-key plaintext is shown once and never persisted.
- Endpoint agents use mTLS and cannot execute arbitrary shell commands.
- AI prose without valid retrieved citations is withheld.
- Investigation graph edges are persisted evidence, never model-invented facts.

## Authentication

Send an API key as `X-API-Key` or `Authorization: Bearer <key>`. Supported
scopes are `read`, `write`, `ioc`, `enroll`, `apikey.read`, `apikey.write`,
`report.write`, and `admin`.

## Selected endpoints

| Method | Path | Scope |
|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | `read` |
| `GET` | `/api/v1/assets` | `read` |
| `GET` | `/api/v1/agents` | `read` |
| `GET` | `/api/v1/graph/traverse` | `read` |
| `POST` | `/api/v1/relationships` | `write` |
| `POST` | `/api/v1/chat/query` | `read` |
| `POST` | `/api/v1/reports/generate` | `report.write` |

## Layout

```text
app/             API, models, ingestion, workers, agent gateway, and AI
frontend/        Next.js analyst console
alembic/         database migrations
endpoint_agent/  cross-platform mTLS inventory agent
tests/           security and regression contracts
docs/            architecture, operations, and feature documentation
```

## Current runtime boundary

The repository contains source, migrations, containers, workers, frontend, and
CI gates. Runtime readiness still requires executing the documented compile,
lint, migration, test, build, and compose checks in a reachable development
environment. A committed workflow is not evidence that those checks passed.
