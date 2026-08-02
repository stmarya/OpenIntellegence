# API Endpoint Inventory

> **Truthfulness note:** This inventory reflects routes registered in `app/api/v1/router.py` as of the merged codebase (PR #1). Routes from feature branches (PRs #3–#13) are listed separately and clearly labelled as **[not yet integrated]**. Do not assume any feature-branch route is available in a deployed environment until its PR is merged and the router registration is confirmed.

---

## Base path

All routes are under `/api/v1`. The router is mounted once in `app/main.py`.

## Authentication

All protected routes require `X-API-Key: <key>` or `Authorization: ****** header.

## Scope legend

| Scope | Meaning |
|---|---|
| `read` | Read any tenant-owned data |
| `write` | Mutate tenant-owned data |
| `ioc` | Access IOC/indicator data |
| `enroll` | Enroll endpoint agents |
| `apikey:read` | List and inspect API keys |
| `apikey:write` | Create and revoke API keys |
| `report:write` | Generate AI reports (mutation) |
| `admin` | Trigger ingestion runs, access system config |

---

## Operations routes (no prefix)

| Method | Path | Summary | Scope | Tenant | Mutable | Status |
|---|---|---|---|---|---|---|
| GET | `/health` | Liveness probe | None | No | No | **Merged** |
| GET | `/health/ready` | Readiness probe (DB + Redis checks) | None | No | No | **Merged** |

---

## Threat Intelligence (`/api/v1`)

Registered in `app/api/v1/intel.py`, tagged `Threat Intelligence`.

| Method | Path | Summary | Scope | Tenant-filtered | Mutable | Status |
|---|---|---|---|---|---|---|
| GET | `/vulnerabilities` | List CVEs with asset context | `read` | No (global CTI) | No | **Merged** |
| GET | `/vulnerabilities/{cve_id}` | CVE detail with exploit evidence | `read` | No | No | **Merged** |
| GET | `/ransomware/victims` | List ransomware victim claims | `read` | No | No | **Merged** |
| GET | `/actors` | List threat actors | `read` | No | No | **Merged** |
| GET | `/iocs` | List indicators of compromise | `read` | No | No | **Merged** |
| GET | `/stats/summary` | Dashboard KPI summary | `read` | Yes (asset counts) | No | **Merged** |

**Query parameters for `/vulnerabilities`:**
- `severity`: filter by severity level
- `is_kev`: boolean filter for KEV-listed CVEs
- `cpe`: CPE URI substring filter
- `limit`, `offset`: pagination

**Query parameters for `/iocs`:**
- `indicator_type`: `ipv4`, `domain`, `url`, etc.
- `verdict`: `malicious`, `suspicious`, `clean`
- `limit`, `offset`: pagination

---

## Assets and Agents (`/api/v1`)

Registered in `app/api/v1/assets.py`, tagged `Assets & Agents`.

| Method | Path | Summary | Scope | Tenant-filtered | Mutable | Status |
|---|---|---|---|---|---|---|
| GET | `/assets` | List assets | `read` | **Yes** | No | **Merged** |
| GET | `/assets/{asset_id}/exposure` | CVE exposure for one asset | `read` | **Yes** | No | **Merged** |
| GET | `/agents` | List endpoint agents | `read` | **Yes** | No | **Merged** |
| POST | `/agents/enroll` | Enroll a new endpoint agent | `enroll` | **Yes** | Yes | **Merged** |
| POST | `/agents/heartbeat` | Agent heartbeat and inventory push | `enroll` | **Yes** | Yes | **Merged** |
| GET | `/agents/{agent_id}/software` | Installed software for an agent | `read` | **Yes** | No | **Merged** |

**Enrollment notes:**
- Requires a single-use agent enrollment key (`single_use = true`)
- Returns a signed certificate for subsequent mTLS authentication
- A key used for enrollment is immediately invalidated

---

## Administration (`/api/v1`)

Registered in `app/api/v1/admin.py`, tagged `Administration`.

| Method | Path | Summary | Scope | Tenant-filtered | Mutable | Status |
|---|---|---|---|---|---|---|
| GET | `/api-keys` | List API keys | `apikey:read` | **Yes** | No | **Merged** |
| POST | `/api-keys` | Create API key (secret shown once) | `apikey:write` | **Yes** | Yes | **Merged** |
| DELETE | `/api-keys/{key_id}` | Revoke an API key | `apikey:write` | **Yes** | Yes | **Merged** |
| GET | `/feeds` | Connector health for all registered feeds | `read` | No | No | **Merged** |
| GET | `/quarantine` | Records rejected during normalisation | `read` | No | No | **Merged** |
| POST | `/ingest/{source}/run` | Trigger an ingestion run | `admin` | No | Yes | **Merged** |
| GET | `/runs` | Recent ingestion runs | `read` | No | No | **Merged** |

**API key creation rules:**
- Plaintext key is returned exactly once; it cannot be retrieved again
- A caller cannot grant scopes they do not themselves hold
- Only scopes in the `GRANTABLE_SCOPES` set are permitted

---

## AI (`/api/v1`)

Registered in `app/api/v1/ai.py`, tagged `AI`.

| Method | Path | Summary | Scope | Tenant-filtered | Mutable | Status |
|---|---|---|---|---|---|---|
| POST | `/chat/query` | Grounded RAG question | `read` | **Yes** | No | **Merged** |
| GET | `/reports/templates` | Available report templates | `read` | No | No | **Merged** |
| POST | `/reports/generate` | Queue a report | `report:write` | **Yes** | Yes | **Merged** |
| GET | `/reports` | List reports | `read` | **Yes** | No | **Merged** |
| GET | `/reports/{report_id}` | Fetch a report by ID | `read` | **Yes** | No | **Merged** |

**Chat behavior:**
- Retrieves from `document_chunks` using vector search before calling the LLM
- If retrieval returns nothing, response includes explicit `unverified` note
- Does not store chat history; each request is stateless

**Report generation behavior:**
- Returns `202 Accepted` immediately with `status = queued`
- Generation runs in a FastAPI background task (40–120 seconds typical)
- Client polls `GET /reports/{report_id}` until `status = complete` or `failed`
- Requires `report:write` scope because report generation is a persisted, potentially billable mutation

---

## Feature-branch routes (not yet integrated)

The following route families exist in open feature branch PRs and are **not registered** in the current `router.py`. They are listed for planning purposes only.

### Intelligence Explorer extensions (PRs #3, #4, #5)

| Method | Intended path | Summary | Integration status |
|---|---|---|---|
| GET | `/vulnerabilities/search` | Full-text CVE search | In review / integration pending |
| GET | `/actors/{actor_id}` | Threat actor detail | In review / integration pending |
| GET | `/iocs/{ioc_id}` | IOC detail | In review / integration pending |
| GET | `/campaigns` | List campaigns | In review / integration pending |
| GET | `/campaigns/{id}` | Campaign detail | In review / integration pending |
| GET | `/malware` | List malware families | In review / integration pending |
| GET | `/malware/{id}` | Malware detail | In review / integration pending |

### Investigation and Cases (PR #6)

| Method | Intended path | Summary | Integration status |
|---|---|---|---|
| POST | `/investigations` | Create investigation | In review / integration pending |
| GET | `/investigations` | List investigations | In review / integration pending |
| GET | `/investigations/{id}` | Investigation detail | In review / integration pending |
| POST | `/investigations/{id}/entities` | Add entity to investigation | In review / integration pending |
| POST | `/cases` | Create case | In review / integration pending |
| GET | `/cases` | List cases | In review / integration pending |
| GET | `/cases/{id}` | Case detail | In review / integration pending |
| POST | `/cases/{id}/tasks` | Add case task | In review / integration pending |
| GET | `/cases/{id}/timeline` | Append-only case timeline | In review / integration pending |

### Alerts and Sightings (PR #7)

| Method | Intended path | Summary | Integration status |
|---|---|---|---|
| GET | `/alerts` | List alerts | In review / integration pending |
| GET | `/alerts/{id}` | Alert detail | In review / integration pending |
| POST | `/alerts/{id}/acknowledge` | Acknowledge alert | In review / integration pending |
| POST | `/sightings` | Record an IOC sighting | In review / integration pending |
| GET | `/sightings` | List sightings | In review / integration pending |

### Correlation and AI Briefs (PR #8)

| Method | Intended path | Summary | Integration status |
|---|---|---|---|
| GET | `/correlations` | List correlation results | In review / integration pending |
| GET | `/correlations/{id}` | Correlation brief with citations | In review / integration pending |

### Orchestration (PR #9)

| Method | Intended path | Summary | Integration status |
|---|---|---|---|
| GET | `/playbooks` | List playbooks | In review / integration pending |
| POST | `/playbooks/{id}/runs` | Propose a playbook run | In review / integration pending |
| GET | `/playbooks/runs/{run_id}` | Run status | In review / integration pending |
| POST | `/playbooks/runs/{run_id}/approve` | Approve proposed run | In review / integration pending |

---

## Intended future routes (planned, not yet specified in any PR)

| Route family | Notes |
|---|---|
| `/v1/users` / `/v1/roles` | User identity and RBAC (Phase C/D) |
| `/v1/agents/{id}/command` | Signed endpoint command delivery; requires approval controls |
| `/v1/connectors` | Connector capability registry and health state |
| `/v1/outbox/dead-letter` | Authorized dead-letter replay |
