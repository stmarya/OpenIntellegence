# REST API

Base path: `/api/v1`

## Authentication

- Session cookies for the first-party frontend, sent with `credentials: "include"`.
- Platform API keys for programmatic clients and agents. Keys are hashed at rest, scoped to a tenant,
  revocable, and never returned to browser code after creation.
- Rate limiting is applied per key and per tenant.

## Route groups

| Group | Purpose |
| --- | --- |
| `/intel` | Vulnerabilities, indicators, research references |
| `/assets` | Enrolled endpoints and inventory |
| `/alerts` | Alerts, rules, feed health |
| `/correlations` | Correlation records and grounded briefs |
| `/orchestration` | Playbooks, runs, approvals, outbox status |
| `/endpoint-intents` | Control-plane requests and approvals |
| `/automation-health` | Capability report and delivery health |
| `/reports` | Generated report artifacts |

## Error contract

| Status | Meaning |
| --- | --- |
| 400 | Malformed request body |
| 401 | Missing or invalid credential |
| 403 | Credential valid but not authorized for the tenant or resource |
| 404 | Not found within the caller tenant scope |
| 409 | Idempotency or state conflict |
| 422 | Semantically invalid request, including `unsupported_action` and `action_not_configured` |
| 429 | Rate limit exceeded |

Capability responses report availability and delivery mode only. They never echo credentials,
webhook URLs, or tokens.
