# Test Strategy

---

## Test pyramid

```
         ┌───────────────────┐
         │    E2E / Manual   │  ← Analyst workflow validation
         ├───────────────────┤
         │   Integration     │  ← Full service with real Postgres/Redis
         ├───────────────────┤
         │   Contract/API    │  ← Route families, status codes, auth semantics
         ├───────────────────┤
         │    Persistence    │  ← Migration correctness, schema constraints
         ├───────────────────┤
         │      Unit         │  ← Domain logic, normalization, retry classification
         ├───────────────────┤
         │      Static       │  ← Lint, type check, import correctness
         └───────────────────┘
```

The majority of automated tests should be unit tests. Integration and E2E tests are valuable but expensive; use them to cover cross-cutting safety properties that unit tests cannot exercise alone.

---

## Test layers

### Layer 1 — Static analysis

| Tool | Command | What it catches |
|---|---|---|
| `ruff` | `ruff check .` | Import order, unused variables, style, up-to-date Python idioms |
| `mypy` | `mypy app` | Type annotation errors, missing type guards |

These must pass before any other layer is considered. A lint failure is a blocking failure.

---

### Layer 2 — Unit tests

**Location:** `tests/`  
**Framework:** `pytest` with `pytest-asyncio`  
**Configuration:** `pyproject.toml` (`asyncio_mode = "auto"`, `testpaths = ["tests"]`)

Unit tests cover deterministic domain behavior without external dependencies:

| Area | What to test |
|---|---|
| Normalization (`app/ingest/normalize.py`) | Field mapping, timestamp parsing, null preservation, severity mapping |
| Security (`app/core/security.py`) | Key generation format, Argon2id hash/verify round-trip, scope validation |
| Retry classification (outbox worker) | Transient vs terminal failure classification, dead-letter threshold |
| Correlation scoring | Deterministic risk factor calculation (CVSS, KEV, exploit, exposure weights) |
| Deduplication logic | Merge behavior for existing records; `sources` array append |
| Unknown state preservation | Null CVSS stays null; unenriched IOC stays unenriched |

**Current test files:**

| File | Coverage area |
|---|---|
| `tests/test_normalize.py` | Normalization logic |
| `tests/test_security.py` | Key generation and security primitives |

---

### Layer 3 — Contract / API tests

Route-contract tests verify that every registered API route:
- Returns the expected HTTP status for a valid request
- Returns 401 for a missing API key
- Returns 403 when the required scope is absent
- Serializes the response body to the declared `response_model` shape
- Returns 404 (not cross-tenant data) for a resource owned by a different tenant

**Required for every route family in `router.py`:**

| Route family | Contract tests required | Current status |
|---|---|---|
| `GET /vulnerabilities` | ✓ | In review (PR #2) |
| `GET /vulnerabilities/{cve_id}` | ✓ | In review (PR #2) |
| `GET /actors` | ✓ | In review (PR #2) |
| `GET /iocs` | ✓ | In review (PR #2) |
| `GET /ransomware/victims` | ✓ | In review (PR #2) |
| `GET /stats/summary` | ✓ | In review (PR #2) |
| `GET /assets` | ✓ | Needs expansion |
| `GET /assets/{id}/exposure` | ✓ | Needs expansion |
| `GET /agents` | ✓ | Needs expansion |
| `POST /agents/enroll` | ✓ | Needs expansion |
| `POST /agents/heartbeat` | ✓ | Needs expansion |
| `GET /api-keys` | ✓ | Needs expansion |
| `POST /api-keys` | ✓ | Needs expansion |
| `DELETE /api-keys/{id}` | ✓ | Needs expansion |
| `GET /feeds` | ✓ | Needs expansion |
| `GET /quarantine` | ✓ | Needs expansion |
| `POST /ingest/{source}/run` | ✓ | Needs expansion |
| `GET /runs` | ✓ | Needs expansion |
| `POST /chat/query` | ✓ | Needs expansion |
| `POST /reports/generate` | ✓ | Needs expansion |
| `GET /reports` | ✓ | Needs expansion |
| `GET /reports/{id}` | ✓ | Needs expansion |

---

### Layer 4 — Persistence / migration tests

| Test | What it verifies |
|---|---|
| `alembic heads` returns exactly one revision | No conflicting migration branches |
| `alembic upgrade head` from empty DB succeeds | Forward migration path is valid |
| Critical constraints exist | `uq_vulnerabilities_cve_id`, `uq_tenants_slug`, `uq_exploits_source_external_id`, etc. |
| Enum values match ORM | `RunStatus`, `AgentStatus`, `ApiKeyStatus`, `ReportStatus` |
| TimestampMixin columns present | `created_at`, `updated_at` on all models |
| `tenant_id` non-nullable on all tenant-owned tables | Schema enforces isolation |

These tests should run against a disposable PostgreSQL instance (e.g., Docker-based test fixture or `testcontainers`).

---

### Layer 5 — Integration tests

Integration tests exercise service behavior with real dependencies (disposable database, mocked external HTTP):

| Test scenario | Coverage |
|---|---|
| Full ingest run with mocked HTTP responses | `fetch → normalize → upsert → quarantine` cycle |
| API key authentication and scope enforcement | Real DB, real Argon2id verification |
| Tenant isolation end-to-end | Principal A cannot access Principal B's records |
| Agent enrollment and heartbeat | mTLS certificate issuance; staleness transition |
| RAG query with mock LLM | Document retrieval, citation assembly, ungrounded response label |
| Rate limiting under Redis | Sliding window enforced; 429 returned; `Retry-After` present |

---

### Layer 6 — E2E / development validation matrix

The full Phase D development validation exercises all integration points together. This is not automated in CI yet.

| Area | Validation command / check |
|---|---|
| Static | `ruff check .` |
| Unit tests | `pytest` |
| Migration from clean DB | `alembic upgrade head` |
| Container startup | `docker compose up --build` |
| Liveness | `GET /health` → `{"status": "ok"}` |
| Readiness | `GET /health/ready` → `{"status": "ready"}` |
| Authentication | Valid key → 200; missing key → 401; wrong scope → 403 |
| Tenant isolation | Cross-tenant resource → 404 |
| Ingestion | `POST /ingest/nvd/run` → records appear in `GET /vulnerabilities` |
| Agent mTLS | Enroll + heartbeat cycle |
| RAG grounding | Chat query returns citations; ungrounded query returns explicit note |
| Case workflow | Create investigation → add evidence → create case → task → timeline |
| Alert triage | Alert received → acknowledged → resolved |
| Approval-first | Playbook run proposed → approved → dispatched |
| Connector delivery | Mock Slack/Jira/SIEM endpoint receives delivery |
| Dead-letter replay | Force delivery failure → dead-letter → replay → delivered |

**Evidence standard:** A feature is not "tested" because code compiles. Record command, environment, result, and known limitations in the PR description and update `docs/planning/project-status.md`.

---

## Mandatory safety test cases

These must exist as automated tests before any feature is considered production-safe:

| Safety case | Test assertion |
|---|---|
| Wrong-tenant read | Principal from Tenant A receives 404 for Tenant B's asset |
| Wrong-tenant write | Principal from Tenant A cannot mutate Tenant B's record |
| Read scope mutation attempt | `read`-scoped key receives 403 on any POST/DELETE |
| AI report with read scope | `read`-scoped key receives 403 on `POST /reports/generate` |
| Concurrent alert intake | Two identical alert events produce one alert record (aggregation, not unique constraint error) |
| Expired outbox lease recovery | Worker B can claim a message whose lease expired while Worker A was processing |
| Active lease not double-claimed | Worker B cannot claim a message with a non-expired lease |
| AI output with no retrieved context | Response includes explicit `unverified` label in provenance note |
| Unknown CVSS not coerced | `cvss_score` field is `null` in response, not `0.0` |
| Unenriched IOC not coerced | `verdict` field is `null` in response, not `"clean"` |
| Agent staleness visible | Missed heartbeats result in `status = "stale"`, not removed from listing |
| Scope escalation rejected | Caller cannot grant scopes they do not hold |
| Self-revocation rejected | A key cannot revoke itself (returns 409) |

---

## Test fixtures and mocks

| What to mock | How |
|---|---|
| External feed HTTP (NVD, OTX, etc.) | `httpx.AsyncMock` or `respx` for HTTPX-based connectors |
| LLM API calls | Mock `httpx.AsyncClient` responses in `RagService` |
| PostgreSQL | `testcontainers` or a test-specific schema; never use production or staging DB |
| Redis | `fakeredis` for unit tests; real Redis for integration tests |
| mTLS CA operations | Use `bootstrap_ca` to generate a test CA; dispose after test run |

**Rule:** Test fixtures must not contain real credentials, production database URLs, or actual secret values. Any fixture containing a value that looks like a credential must use clearly fake placeholder strings.

---

## Contract and schema test requirements

| Requirement | Why |
|---|---|
| Schema migration tests | A schema-only change that passes mypy may still fail at runtime against Postgres |
| API route registry test | Verifies every intended router is registered in `router.py` exactly once |
| Response model shape test | Ensures Pydantic `response_model` serializes without errors on representative data |
| Tenant isolation test per route | Prevents regression when new routes are added without tenant filters |

---

## Release criteria

A release is not eligible for production promotion until:

- [ ] `ruff check .` passes with no errors
- [ ] `pytest` passes with no failures
- [ ] `alembic heads` returns exactly one revision
- [ ] `alembic upgrade head` succeeds on a clean database
- [ ] All mandatory safety test cases have automated coverage
- [ ] All registered route families have contract tests
- [ ] No secrets in test fixtures, migrations, or documentation
- [ ] `docs/planning/project-status.md` is updated with current state
