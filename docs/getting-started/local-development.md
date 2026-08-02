# Local Development Guide

> **Truthfulness note:** This guide describes the intended setup steps based on the repository layout. Until development validation (Phase D in the project status tracker) is fully executed, any specific output claims (e.g. "all tests pass") are aspirational targets, not confirmed results. Commands are accurate as of the current codebase.

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Python | 3.12 | Enforced in `pyproject.toml` |
| PostgreSQL | 16 (TimescaleDB HA image) | Must have `timescaledb` and `pgvector` extensions |
| Redis | 7 | Rate limiting and future task queuing |
| Docker + Compose | Docker ≥ 24, Compose plugin | Required for the full stack; optional for unit/lint-only |
| OpenSearch | 2.17.1 | Required for full-text search (Docker only) |
| MinIO | latest | Object storage; optional for development |
| Git | Any recent | |

Python dependency manager: `pip` with `setuptools`. No Poetry or PDM setup exists.

---

## Environment file conventions

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Fill in **only** development values. **Never commit `.env` or any real credentials.** The `.gitignore` already excludes `.env`.
3. Key names that require values for local operation (real values must come from your environment; do not add them here):

| Key | Purpose | Required locally |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection | Yes — points to `localhost:5432/openintel` |
| `REDIS_URL` | Redis connection | Yes — `redis://localhost:6379/0` |
| `ENVIRONMENT` | `development` / `production` | Set to `development` |
| `DEBUG` | Enables verbose logging | `true` for local |
| `AGENT_CA_CERT_PATH` | mTLS CA certificate path | Only for agent enrollment testing |
| `AGENT_CA_KEY_PATH` | mTLS CA key path | Only for agent enrollment testing |
| `RANSOMWARE_LIVE_API_KEY` | Feed credential | Optional; disables feed if absent |
| `GITHUB_TOKEN` | GitHub PoC connector | Optional |
| `NVD_API_KEY` | NVD feed credential | Optional |
| `OTX_API_KEY` | AlienVault OTX credential | Optional |
| `LLM_API_KEY` | LLM provider key | Optional; disables AI if absent |
| `LLM_BASE_URL` | OpenAI-compatible endpoint | Override to use a self-hosted gateway |
| `SLACK_WEBHOOK_URL` | Connector delivery | Optional; leave empty in development |
| `JIRA_BASE_URL` | Jira connector | Optional |
| `JIRA_EMAIL` | Jira connector identity | Optional |
| `JIRA_API_TOKEN` | Jira connector secret | Optional |
| `SIEM_WEBHOOK_URL` | SIEM connector | Optional |
| `SIEM_WEBHOOK_TOKEN` | SIEM bearer secret | Optional |

> Connector keys are deliberately optional. A missing key disables the relevant connector cleanly instead of crashing the ingest run.

---

## Install

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. Install runtime and development dependencies
pip install -e ".[dev]"
```

This installs: FastAPI, SQLAlchemy, Alembic, asyncpg, pgvector, Redis, argon2-cffi, structlog, httpx, prometheus-client, ruff, pytest, pytest-asyncio, mypy, and their transitive dependencies.

---

## Lint and test

```bash
# Static analysis / linting
ruff check .

# Type checking (optional but recommended)
mypy app

# Unit tests
pytest

# Unit tests with verbose output
pytest -v

# Run a specific test file
pytest tests/test_normalize.py
```

> **Limitation:** Tests that require a running PostgreSQL or Redis instance are not currently isolated behind fixtures that spin up disposable databases. Before confirming integration test results, ensure the relevant services are reachable or marked as skipped. See the project status tracker — development validation (Phase D) is not yet complete.

---

## Database and migration commands

```bash
# Check current migration state
alembic current

# Check for multiple heads (must be exactly one)
alembic heads

# Apply all pending migrations
alembic upgrade head

# Show migration history
alembic history --verbose

# Downgrade one step (development only; not for deployed environments)
alembic downgrade -1

# Generate a new migration from ORM changes (review before committing)
alembic revision --autogenerate -m "describe_the_change"
```

> **Migration safety rule:** Deployed migration history is forward-only. Do not rewrite released revisions. New migrations must extend the chain from the current head. See `docs/data/migration-playbook.md` for the full migration protocol.

### Generate a development CA for mTLS testing

```bash
python -m app.agent_gateway.bootstrap_ca --out ./certs
```

This creates `certs/agent-ca.crt` and `certs/agent-ca.key`. The CA private key must never be committed.

---

## Docker workflow

The `docker-compose.yml` file starts PostgreSQL (TimescaleDB), Redis, OpenSearch, MinIO, and the API service.

```bash
# Build and start the full stack
docker compose up --build

# Start only infrastructure (run the API locally)
docker compose up postgres redis

# Rebuild after dependency changes
docker compose up --build api

# Tear down (preserves volumes)
docker compose down

# Tear down and remove volumes (fresh-state reset)
docker compose down -v

# View API logs
docker compose logs -f api
```

After `docker compose up --build`:
- API: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`
- Liveness: `GET /health`
- Readiness: `GET /health/ready`
- OpenSearch: `http://localhost:9200`
- MinIO console: `http://localhost:9001`

The Docker Compose `api` service automatically runs `alembic upgrade head` before starting uvicorn. If the migration fails (e.g., multiple heads or constraint error), the container exits immediately.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `ImportError` on startup | Missing dependency or wrong Python version | Confirm `python --version` ≥ 3.12; re-run `pip install -e ".[dev]"` |
| `asyncpg.exceptions.TooManyConnectionsError` | Connection pool exhausted | Reduce pool size or restart Postgres |
| `alembic.util.exc.CommandError: Multiple head revisions` | Two migration branches not yet merged | Run `alembic heads`; follow the migration-playbook to resolve |
| `redis.exceptions.ConnectionError` | Redis not running | Start Redis: `docker compose up redis` |
| `422 Unprocessable Entity` on API calls | Request body or query parameter validation failed | Check the `fields` array in the response body for per-field error detail |
| `503 Service Unavailable` from `/health/ready` | Database or Redis unreachable | Check `checks` object in the response; ensure services are healthy |
| `rate_limiter_degraded` log line | Redis unavailable; using in-memory fallback | Expected in local dev without Redis; will not persist across restarts |
| mTLS enrollment fails | CA certs not generated or paths misconfigured | Run `python -m app.agent_gateway.bootstrap_ca --out ./certs`; confirm `.env` paths |
| `pgvector` extension missing | Docker image does not include pgvector | Use `timescale/timescaledb-ha:pg16` as specified in `docker-compose.yml` |

---

## What cannot be claimed without execution

The following items require a running environment with all dependencies healthy before they can be reported as validated:

- [ ] All Alembic migrations apply cleanly from a fresh database
- [ ] All unit tests pass (`pytest`)
- [ ] Tenant isolation is enforced end-to-end (requires integration fixtures)
- [ ] Agent mTLS enrollment and heartbeat work correctly
- [ ] RAG grounding and citation behavior (requires LLM credentials)
- [ ] Connector delivery through Slack/Jira/SIEM (requires connector credentials)
- [ ] Rate limiting under load

Refer to `docs/planning/project-status.md` (the project status tracker) for the current execution state of each gate.
