# Deployment Guide

> **Truthfulness note:** This guide describes the intended deployment process based on the current codebase and configuration. Development validation (Phase D in the project status tracker) has not yet been completed in a full environment. Do not interpret this guide as a confirmation that all steps have been executed successfully.

---

## Environment separation

| Environment | Purpose | Secrets source | Migration policy |
|---|---|---|---|
| `development` | Local developer iteration | `.env` file (never committed) | Any forward migration; downgrade allowed |
| `staging` | Integration validation before production | Secrets manager / CI secrets | Forward-only; test against clean DB |
| `production` | Live tenant service | Secrets manager / HSM for CA keys | Forward-only; tested backup required before migration |

**Rule:** `ENVIRONMENT=production` causes the application to refuse startup if Redis is unavailable, because unmetered API access is a security risk. Non-production environments fall back to in-memory rate limiting.

---

## Configuration checklist

Use key names only. Never record actual values in this document or any committed file.

### Required for all environments

| Key | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL async DSN (asyncpg driver) |
| `REDIS_URL` | Redis DSN for rate limiting |
| `ENVIRONMENT` | `development`, `staging`, or `production` |
| `CORS_ORIGINS` | JSON array of allowed origins (no wildcard in production) |

### Required for production

| Key | Description |
|---|---|
| `AGENT_CA_CERT_PATH` | Path to agent CA certificate file |
| `AGENT_CA_KEY_PATH` | Path to agent CA private key (HSM or secure file) |
| `AGENT_CA_KEY_PASSWORD` | Password for encrypted CA key (if applicable) |

### Required for AI features

| Key | Description |
|---|---|
| `LLM_API_KEY` | LLM provider API key |
| `LLM_BASE_URL` | Override to self-hosted gateway to keep data off third-party providers |
| `LLM_MODEL` | Model identifier |
| `EMBEDDING_MODEL` | Embedding model identifier |

### Required per enabled connector

| Key | Connector |
|---|---|
| `RANSOMWARE_LIVE_API_KEY` | Ransomware.live Pro |
| `NVD_API_KEY` | NIST NVD (optional; unauthenticated rate limit applies if absent) |
| `OTX_API_KEY` | AlienVault OTX |
| `GITHUB_TOKEN` | GitHub PoC search |
| `SLACK_WEBHOOK_URL` | Slack delivery connector |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` | Jira delivery connector |
| `SIEM_WEBHOOK_URL`, `SIEM_WEBHOOK_TOKEN` | SIEM delivery connector |
| `CONNECTOR_DELIVERY_TIMEOUT_SECONDS` | HTTP timeout for connector delivery |
| `CONNECTOR_MAX_ATTEMPTS` | Retry count before dead-letter |

**Rule:** Leave connector keys empty (not set) to disable a connector. Do not set a connector key to a test value that points at production systems.

---

## Migration rollout

### Pre-deployment checks

```bash
# Confirm single migration head
alembic heads
# Expected: exactly one revision ID

# Check current database state
alembic current

# Preview pending migrations
alembic history --verbose
```

### Apply migrations

```bash
alembic upgrade head
```

**Stop rollout if:**
- `alembic heads` returns multiple revisions
- `alembic upgrade` raises a constraint violation or type error
- The migration completes but `alembic current` does not match `alembic heads`

### Rollback approach

OpenIntelligence uses forward-only migrations in deployed environments. There is no `alembic downgrade` in production.

| Situation | Action |
|---|---|
| Migration fails mid-run | Restore from pre-migration backup; investigate failure; fix migration in a new forward revision |
| Data corruption after migration | Restore from backup; create a corrective forward migration |
| Schema incompatibility discovered post-deploy | Create a forward corrective migration; do not rewrite history |

---

## Worker topology

| Worker | Command | Singleton or multiple | Notes |
|---|---|---|---|
| Connector delivery | `python -m app.workers.connector_delivery` | Can run multiple; lease prevents double-claiming | Status: feature branch (PR #10); not yet merged |

**Worker rules:**
- Workers must not be embedded in the API process
- Workers use `FOR UPDATE SKIP LOCKED` to prevent double-claiming outbox messages
- Crashed workers leave messages in `leased` state; another instance reclaims them after `lease_expires_at`
- Worker count should be scaled based on outbox message volume, not arbitrarily

---

## Release gates

Before promoting to production:

- [ ] `alembic heads` returns exactly one revision
- [ ] `alembic upgrade head` succeeds on a clean database clone
- [ ] `GET /health/ready` returns `{"status": "ready"}` after deployment
- [ ] Authentication and scope enforcement tests pass
- [ ] Tenant isolation verified for all tenant-owned routes
- [ ] No secrets present in the deployed container image or environment config dump
- [ ] Audit log writes confirmed for key lifecycle operations
- [ ] Connector credentials tested against staging targets before production

---

## Docker image

```bash
# Build
docker build -t openintelligence:latest .

# Run with env file (development)
docker run --env-file .env -p 8000:8000 openintelligence:latest

# The image entrypoint runs: alembic upgrade head && uvicorn app.main:app
```

The `Dockerfile` is in the repository root. Dependencies are installed from `pyproject.toml`. The image does not contain secrets; all configuration is injected via environment variables at runtime.

---

## Backup requirements

| Resource | Backup method | Frequency | Notes |
|---|---|---|---|
| PostgreSQL | pg_dump or streaming replication | Daily minimum; before every migration | Must be tested with a restore before each production migration |
| Redis | RDB/AOF persistence (configured in `docker-compose.yml`) | Continuous | Rate limiter windows only; loss is non-critical |
| CA certificate and key | Separate secure backup | On creation and rotation | Loss requires full agent re-enrollment |

---

## Post-deployment validation

```bash
# 1. Liveness
curl https://<host>/health
# Expected: {"status": "ok", "version": "0.1.0"}

# 2. Readiness
curl https://<host>/health/ready
# Expected: {"status": "ready", "checks": {"database": "ok", "redis": "ok"}}

# 3. API authentication (replace KEY with a valid key)
curl -H "X-API-Key: KEY" https://<host>/api/v1/feeds
# Expected: list of connector health records

# 4. Migration state
alembic current
# Expected: matches alembic heads output
```

**Do not claim deployment is successful until all four checks pass with expected responses.**
