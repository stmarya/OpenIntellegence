# REST API

Base path: `/api/v1`

## Authentication

Every caller authenticates with a platform API key, presented either as
`X-API-Key: <key>` or `Authorization: Bearer <key>`. There is no session
mechanism and no user table: **identity in this platform is an API key, not a
person.** The console is a server-side reader that holds a key; it does not log
anyone in.

Keys are hashed with Argon2 at rest, bound to one tenant, and rate limited per
key. The raw key is returned exactly once, at creation. A missing key still
triggers a decoy verification so that timing does not reveal whether a key
exists.

Revoked and expired keys stay listed, and a revoked key publishes
`revoked_reason`. The record of what once had access is incomplete without the
record of why it was withdrawn.

### Scopes

| Scope | Grants |
| --- | --- |
| `read` | All read endpoints |
| `write` | Cases, investigations, alerts, sightings, alert rules |
| `ioc` | Indicator submission |
| `enroll` | Agent enrollment (single-use keys) |
| `apikey.read` / `apikey.write` | Key administration |
| `report.write` | Report generation |
| `admin` | Implies every scope above |

Agent heartbeats are the one exception: they authenticate with the client
certificate issued at enrollment, not with a key, because a body-supplied agent
id would be trivially spoofable.

## Response envelope

List endpoints return:

```json
{
  "data": [],
  "page": { "limit": 50, "offset": 0, "total": 0, "has_more": false },
  "provenance": { "generated_at": "...", "sources_included": [], "sources_degraded": [], "is_partial": false }
}
```

`provenance` is mandatory rather than decorative. A count computed while a feed
was degraded is not the same claim as one computed with every source healthy,
and the envelope is where that difference is recorded.

These endpoints deliberately do **not** use the envelope and return a bare
object: `/agents/{agent_id}/software`, `/quarantine`, `/runs`,
`/ransomware/groups`, `/settings`, `/system-health`, `/stats/summary`. Clients
must read each of these as its own shape.

## Route groups

| Prefix | Module | Purpose |
| --- | --- | --- |
| `/vulnerabilities`, `/iocs`, `/actors`, `/ransomware`, `/stats` | `intel` | Core threat intelligence |
| `/campaigns`, `/malware` | `domains` | Campaign and malware families |
| `/cases`, `/investigations` | `workflows` | Analyst workflow, tasks, events |
| `/alert-rules`, `/alerts`, `/sightings` | `alerting` | Detection triggers and triage |
| `/correlations` | `correlations` | Correlation records and grounded briefs |
| `/endpoint-intents` | `endpoint_intents` | Control-plane requests and approvals |
| `/automation` | `automation_health` | Capability report and delivery mode |
| `/assets`, `/agents` | `assets` | Asset exposure and the agent gateway |
| `/detection-content`, `/collections`, `/intelligence-requirements`, `/audit-log`, `/system-health`, `/settings` | `governance` | Governance surfaces |
| `/me`, `/tenants`, `/access`, `/sharing-groups` | `workspace` | Workspace and access |
| `/api-keys`, `/feeds`, `/quarantine`, `/ingest`, `/runs` | `admin` | Administration and ingestion |
| `/chat`, `/reports` | `ai` | Grounded chat and report generation |

## Error contract

| Status | Meaning |
| --- | --- |
| 400 | Malformed request body |
| 401 | Missing, revoked, or expired credential |
| 403 | Credential valid but lacks the required scope |
| 404 | Not found within the caller tenant scope |
| 409 | Idempotency or state conflict, including revoking your own authenticating key |
| 422 | Semantically invalid request, including unknown scopes and privilege escalation |
| 429 | Rate limit exceeded |

A 403 names what was missing rather than refusing opaquely:

```json
{ "message": "...", "required": [], "missing": [], "granted": [] }
```

Capability responses report availability and delivery mode only. They never echo
credentials, webhook URLs, or tokens, and `configured` is never reported as
`reachable`.

## Runtime requirement

`app/api/schemas.py` uses PEP 695 generic syntax (`class ListResponse[T]`), so
the API requires **Python 3.12 or newer**. On an older interpreter this fails at
import time, not at request time.
