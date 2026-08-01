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

### Foundation (P0)

Schema, normalisation, connector framework, REST API, agent gateway,
API-key service, rate limiting and AI (RAG-grounded chat / reports) layer.

### Alert Evaluation & Correlation Evidence (Phases 1–3)

**Phase 1 – AlertEvaluationWorker** (`app/workers/alert_evaluation.py`)

A background worker evaluates all enabled tenant alert rules against
server-side DB facts on a 5-minute cadence. Supported trigger types:

| Trigger type | What is evaluated |
|---|---|
| `kev_exposure` | Assets with open KEV exposures in the tenant |
| `ioc_sighting` | New IOC sightings within a configurable look-back window |
| `agent_stale` | Agents whose heartbeat has exceeded the staleness threshold |
| `ransomware_relevance` | Ransomware victims matching configured sectors |
| `feed_degraded` | Ingestion feeds with repeated failures in the window |
| `custom` | Safe metric-threshold conditions (whitelisted metrics only) |

Fingerprint/cooldown deduplication reuses the existing `Alert` table
unique constraint. Each alert carries an `evidence` dict with explicit
`evidence_state` annotations (`"present"` / `"partial"` / `"unknown"`)
so analysts can distinguish known-false from not-yet-known values.

**Safety guarantee**: the worker never executes or schedules remediation
actions. All `automation_candidates` in the response carry
`requires_approval: true` and are gated by the existing `AutomationRun`
approval workflow.

**Phase 2 – Server-side correlation evidence resolver**

`app/services/correlation.resolve_evidence()` reads assets, exposures,
vulnerabilities/KEV, sightings and ransomware victims from the DB and
resolves an evidence dict with factor provenance. The `POST
/correlations/evaluate` endpoint now calls the resolver server-side;
client payload is accepted only as *optional context hints* for fields
the server cannot determine independently. Resolved provenance is
persisted in the new `correlations.factor_provenance` column.

**Phase 3 – Cross-entity timeline events**

A new `timeline_events` table provides an append-only audit stream
linking alerts, correlations, investigations and cases. The worker
appends an `alert.triggered` event for every alert it fires. Rows are
never updated or deleted. Case creation remains subject to the existing
`AutomationRun` proposal/approval gate (`requires_approval: true`).

**Migration**: `alembic/versions/0008_alert_evaluation_timeline.py` adds
`alerts.evidence`, `correlations.factor_provenance`, and the
`timeline_events` table.

**Tests**: `tests/test_alert_evaluation.py` provides 28 deterministic
unit tests (no DB required) covering tenant isolation, rule evaluation for
every trigger type, cooldown dedup, resolved score evidence, and the
alert → correlation → case transition state machine.

### Not yet implemented

The Prefect/Kafka orchestration layer, the TAXII 2.1 server, the
OpenSearch and Neo4j integrations, the outbound webhook emitter, and
Identity/RBAC/login. The Go endpoint agent lives in a separate
repository.

