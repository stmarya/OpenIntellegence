# OpenIntelligence — CTI Platform Backend

Backend for a cyber threat intelligence platform: it ingests public and
commercial feeds, correlates them against your own endpoint inventory, and
exposes the result over a versioned REST API with an AI layer on top.

FastAPI · Python 3.12 · PostgreSQL 16 (TimescaleDB + pgvector) · Redis

---

## What this replaces

This codebase supersedes a set of standalone collector scripts. Six defects
were measured in those scripts, and the architecture here is shaped around
preventing each one structurally rather than fixing it once.

| # | Defect in the legacy collectors | How this codebase prevents it |
|---|---|---|
| 1 | A Ransomware.live PRO key hardcoded in source | Every credential is a `Settings` field loaded from the environment. No connector accepts an inline key. |
| 2 | `ssl.CERT_NONE` and `check_hostname = False` | `build_http_client()` is the only HTTP client factory, it pins `CERT_REQUIRED` and `check_hostname=True`, and it exposes no switch to disable them. |
| 3 | Malformed f-strings producing literal `{{...}}` URLs | URL construction is covered by connector tests that assert the rendered string. |
| 4 | CXSecurity parser reading `<lastBuildDate>` instead of `<pubDate>` | Unparseable records are quarantined with their raw payload instead of dropped, so a parser bug surfaces as a visible count rather than silence. |
| 5 | Time windows drifting past the requested `end_date` | `normalize_timestamp()` returns timezone-aware UTC for every source, with naive-source zones declared explicitly in `NAIVE_SOURCE_TIMEZONES`. |
| 6 | No `source` field, so provenance was lost on merge | `NormalizedRecord` raises if `source` is missing, and every list response carries a `provenance` block. |

Two further positions follow from the same reasoning:

- **A missing CVSS score is `None`, never `0.0`.** Coercing an unscored CVE
  to zero files it as harmless. The API, the schema and the UI contract all
  carry the null through.
- **An unenriched indicator is its own category**, not "clean". Folding it
  into clean would overstate confidence.

---

## Quick start

```bash
cp .env.example .env
python -m app.agent_gateway.bootstrap_ca --out ./certs   # dev CA for agents
docker compose up --build
```

The API is then on `http://localhost:8000`, with interactive docs at
`/docs` and the schema at `/openapi.json`.

Without Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
alembic upgrade head
uvicorn app.main:app --reload
pytest
```

---

## Layout

```
app/
  core/          config, API-key security, rate limiting, request dependencies
  db/            declarative base, ORM models
  ingest/        normalisation, connector framework, connectors, pipeline
  agent_gateway/ mTLS certificate authority, dev CA bootstrap
  services/      provenance, agent identity, exposure matching
  ai/            RAG retrieval, report generation
  api/           Pydantic schemas and v1 routers
alembic/         migrations, including pgvector and TimescaleDB setup
tests/           regression tests for the defects above
```

---

## Authentication

Send the key as `X-API-Key`, or as `Authorization: Bearer <key>`.

Keys look like `ngs_live_<22-char id><32-char secret>`; agent enrollment keys
use the `ngs_agnt_` prefix. Only the **secret half** is stored, hashed with
Argon2id. The id half is indexed, so verifying a request costs one primary-key
lookup plus one Argon2 call — rather than an Argon2 verification against every
stored key, which would be a denial-of-service vector against ourselves.

A key's plaintext is returned exactly once, at creation. We cannot show it
again, which is the point: a platform that can redisplay your key on demand
is a platform storing it recoverably.

**Scopes:** `read`, `write`, `ioc`, `enroll`, `apikey.read`, `apikey.write`,
`report.write`, `admin`. A 403 names the scope you are missing rather than
failing opaquely, and a caller can never grant a scope it does not itself
hold.

**Rate limits** are a Redis sliding window, applied per key. Every response
carries `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`;
a 429 adds `Retry-After`. A fixed window was rejected because it permits a
double-rate burst across the boundary.

---

## Endpoint agents

Agents authenticate with **mutual TLS**, not API keys.

1. The installer carries a single-use `ngs_agnt_` enrollment key.
2. The agent generates its keypair locally and sends only a CSR. **The
   private key never leaves the endpoint.**
3. The gateway signs the CSR and returns a 90-day client certificate. The
   enrollment key is burned on success.
4. The certificate subject is the agent UUID, not the hostname — hostnames
   get renamed and reused, and binding identity to one would let a re-imaged
   machine impersonate its predecessor.

The CSR's own subject is discarded and replaced with one the gateway
controls, so an agent cannot name itself into another tenant.

The heartbeat schema is deliberately narrow. It carries hostname, OS, IP,
uptime and installed software — and **no** file contents, keystrokes,
clipboard, browser history, credentials, screenshots or network payloads.
This is an inventory collector, not surveillance, and the schema enforces
that boundary rather than relying on policy.

Agents that miss five consecutive heartbeats are marked `stale`, never
removed from the fleet list. An endpoint that stopped reporting is the one
you most need to see.

---

## Exposure matching

Installed software is matched to CVEs by two rules, and every exposure
records which one produced it in `matched_via`:

- `cpe` — the software's CPE URI appears in the CVE's CPE list. Precise.
- `vendor_product` — CISA KEV vendor/product matches the software name.
  Broader, and the only rule available for KEV entries, which carry no CPE
  data.

Without that field a false positive is unarguable. Exposures that stop
matching are resolved rather than deleted, preserving remediation history.

Remediation SLAs are 7/14/30/90 days by severity, and 14 days for anything
in CISA KEV regardless of score. A CVE with no score gets **no** SLA date,
because there is no defensible deadline to invent.

---

## AI layer

**Chat** is retrieval-augmented and refuses to answer from model memory. If
retrieval returns nothing, the endpoint says so instead of producing
confident claims about CVEs this workspace never ingested. Retrieval is
hybrid: exact CVE-identifier lookup runs first and always wins, because
embeddings of near-identical identifiers collide.

**Reports** are generated in two stages. Deterministic SQL computes the
figures; the model is then asked to write prose around numbers it was handed
and explicitly forbidden to compute its own. Every report stores its
citations — without them an AI report is an unfalsifiable claim.

Six templates: executive brief, threat advisory, ransomware landscape, asset
exposure, compliance pack (ISO 27001 A.12.6 / SOC 2 CC7.1), IOC hunting pack.

If no LLM is configured, both features degrade to returning the verified
records and figures rather than failing.

---

## Selected endpoints

| Method | Path | Scope |
|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | `read` |
| `GET` | `/api/v1/vulnerabilities/{cve_id}` | `read` |
| `GET` | `/api/v1/ransomware/victims` | `read` |
| `GET` | `/api/v1/actors` | `read` |
| `GET` | `/api/v1/iocs` | `ioc` |
| `GET` | `/api/v1/assets` | `read` |
| `GET` | `/api/v1/assets/{id}/exposure` | `read` |
| `GET` | `/api/v1/agents` | `read` |
| `POST` | `/api/v1/agents/enroll` | `enroll` |
| `POST` | `/api/v1/agents/heartbeat` | mTLS |
| `GET` | `/api/v1/api-keys` | `apikey.read` |
| `POST` | `/api/v1/api-keys` | `apikey.write` |
| `GET` | `/api/v1/feeds` | `read` |
| `GET` | `/api/v1/quarantine` | `read` |
| `POST` | `/api/v1/ingest/{source}/run` | `admin` |
| `POST` | `/api/v1/chat/query` | `read` |
| `POST` | `/api/v1/reports/generate` | `report.write` |

The vulnerability list is ordered by **affected asset count** by default, not
by CVSS. A 9.8 that touches nothing is less urgent than a 7.8 on a hundred
hosts, and score-first ordering is how remediation queues end up ignored.

---

## Status

This is the foundation slice: schema, normalisation, connector framework,
REST API, agent gateway, API-key service and AI layer.

Not yet done: the Prefect/Kafka orchestration layer, the TAXII 2.1 server,
the OpenSearch and Neo4j integrations, and the outbound webhook emitter. The
Go endpoint agent lives in a separate repository.

Tests cover normalisation and the security primitives. The connectors and
HTTP layer are not yet covered by integration tests against recorded
fixtures.

---

## Frontend (phases 7–9 — dev preview only)

> **Not production-ready.** The frontend ships a mock API adapter so every
> page can be developed and reviewed without a live backend. All pages clearly
> indicate when mock data is active. No security data is fabricated; unknown
> values stay unknown.

### Technology

| Concern | Choice |
|---|---|
| Framework | Next.js 15, App Router, TypeScript |
| Styling | Tailwind CSS 4 + CSS custom properties |
| Design language | Dense dark enterprise UI: teal `#16A9A0`, 13 px base, 4 px radius, 120 ms motion, no decorative shadows |
| API adapter | `src/lib/api/` — real HTTP client + deterministic mock with simulated latency |

### Pages

| Route | Purpose |
|---|---|
| `/dashboard` | KPI summary — critical CVEs, open alerts, exposed assets, critical correlations |
| `/explorer` | Full vulnerability catalogue with KEV and CVSS filters |
| `/assets` | Endpoint inventory with exposure and last-seen data |
| `/alerts` | Alert triage queue with provenance banner when feeds are degraded |
| `/correlations` | Risk-scored evidence correlations with automation candidates |
| `/cases` | Active investigations / case tracking |
| `/automation` | Playbooks and automation-run history |
| `/reports` | Generated intelligence reports |
| `/analyst` | RAG-grounded AI analyst chat; never answers from general knowledge |

### Run the frontend

```bash
cd frontend
npm install
npm run dev       # http://localhost:3000  (mock mode by default)
```

To connect to a live backend:

```bash
NEXT_PUBLIC_API_BASE=http://localhost:8000 \
NEXT_PUBLIC_USE_MOCK=false \
npm run dev
```

### Build & lint

```bash
cd frontend
npm run build     # production build
npm run lint      # ESLint
```

### Run with Docker Compose

```bash
# Start full stack including mock-connector and frontend:
docker compose up

# Backend only:
docker compose up postgres redis api
```

---

## Dev validation boundaries

This section documents what the test suite covers and what it does not,
so CI failures are diagnosed correctly.

### What is tested (no external services required)

| Test file | What it covers |
|---|---|
| `test_alembic_lineage.py` | Single-head migration chain, all 7 revisions present |
| `test_api_contract.py` | All expected endpoint families registered in the OpenAPI schema |
| `test_connector_delivery.py` | Slack ADF format, retry delay bounds, retryable status codes |
| `test_health.py` | `/health` liveness, `/health/ready` degraded-gracefully response, timing header |
| `test_normalize.py` | Timestamp parsing (4 feed formats), CVE extraction, CVSS validation, victim normalisation |
| `test_outbox.py` | DeliveryWorker state machine: delivered → delivered; retryable under max → retry; retryable at max → dead\_letter; non-retryable → dead\_letter; unknown action → dead\_letter |
| `test_rag_citations.py` | No-context refusal string returned; citations match retrieved chunks; CVSS unknown → null (not 0.0); unconfigured LLM → evidence listing, not error |
| `test_schema_contract.py` | ORM column presence, unique constraints |
| `test_security.py` | API key generation, parsing, Argon2 verification, scope model, in-memory rate limiter |
| `test_tenant_safety.py` | Auth required on every data endpoint; 403 for missing scope; tenant\_id injected by all route modules |

### What is NOT tested here

- Real database writes and reads (no test database is started by the test suite).
- Feed HTTP calls to external APIs.
- LLM completions.
- mTLS endpoint agent certificate issuance.
- Frontend browser behaviour.

### Run backend tests

```bash
# Install dev dependencies:
pip install -e ".[dev]"

# Run all tests (no external services needed):
python -m pytest tests/ -v

# Run a specific group:
python -m pytest tests/test_outbox.py tests/test_rag_citations.py -v
```

### Mock connector

`docker compose up mock-connector` starts a MockServer instance on port 1080
pre-configured with Slack webhook, Jira, and SIEM endpoints. Pass
`X-Mock-Status: 503` to simulate retryable failures. Configuration lives in
`dev/mock-connector/mock-connector.json`.

Point connector settings at the mock:

```
SLACK_WEBHOOK_URL=http://localhost:1080/mock/slack/webhook
JIRA_BASE_URL=http://localhost:1080/mock/jira
SIEM_WEBHOOK_URL=http://localhost:1080/mock/siem/events
```
