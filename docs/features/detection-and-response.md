# Detection and Response

## Status: Implemented in feature branch; pending integration/review/validation — P0 (core delivery) and P1 (reliability controls)

OpenIntelligence ships an approval-first, dual-safeguard automation engine for detection
and response workflows.

---

## Architecture overview

```
Correlation / Alert
      │
      ▼
AutomationRun (proposed)
      │  (1 or 2 approvals required)
      ▼
AutomationRun (approved)
      │
      ▼
dispatch_run → AutomationOutbox items
      │
      ▼
DeliveryWorker (leased, bounded retry)
      │
      ├─ delivered
      ├─ retry (back-off, max 5 attempts)
      └─ dead_letter → replay API (write scope, tenant-owned)
```

---

## Connector capability registry

The platform maintains a **capability registry** that describes every supported action
and its current availability.  The registry is derived from application configuration —
no network probes are issued, and no secrets are exposed.

### Supported actions

| Action | Connector type | Notes |
|---|---|---|
| `slack.notify` | `slack` | Requires `SLACK_WEBHOOK_URL` |
| `jira.issue.create` | `jira` | Requires `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` |
| `siem.push` | `siem_webhook` | Requires `SIEM_WEBHOOK_URL` |
| `case.create` | `internal` | **Planned** — worker not yet implemented |
| `report.generate` | `internal` | **Planned** — worker not yet implemented |
| `endpoint.command.request` | `internal` | **Planned** — dual approval required; no automatic replay |

Internal actions are advertised in the capability registry as `planned` with
`enabled: false`.  They can be included in playbooks, but will remain in `queued`
state in the outbox until their dedicated worker processes them.

---

## Approval-first dispatch flow

1. **Propose** a run (`POST /automation-runs`) — state: `proposed`.
2. **Approve** by required approvers — 1 for most actions; 2 for any playbook
   containing `endpoint.command.request`.
3. **Dispatch** the approved run (`POST /automation-runs/{id}/dispatch`) — this
   validates that every step uses a currently-enabled action.  Delivery-adapter steps
   require a configured connector; internal/planned actions (e.g., `case.create`) are
   also rejected until their worker is integrated and the capability entry is updated
   to `enabled: true`.  Any unavailable action causes the dispatch to be **rejected
   with HTTP 422** listing the specific actions.
4. The **DeliveryWorker** claims and delivers each outbox item with lease/retry
   semantics.  Internal actions are never claimed by this worker.

---

## Dead-letter replay

When a delivery adapter item exhausts its retry budget it enters `dead_letter` state.
Authorised callers may replay it via:

```
POST /automation-outbox/{outbox_id}/replay
```

Rules:
- Requires **write scope**.
- The item must belong to the calling tenant (tenant isolation enforced).
- Only items in `dead_letter` state may be replayed.
- `endpoint.command.request` is **never** replayed automatically; create a new run
  with fresh approvals instead.
- A new idempotency key is generated on each replay to prevent duplicate remote
  side effects.
- Attempt counter is reset to 0 (retry back-off restarts from the beginning).
- Full replay audit (actor, timestamp, reason, previous idempotency key and attempt
  count) is appended to `replay_history` on the outbox item.

---

## Connector health

The `GET /orchestration/health` endpoint returns per-connector health derived from
configuration state, without issuing any network probes.  **Active probing** against
remote endpoints (e.g., Slack, Jira) is **planned** but not yet implemented to avoid
leaking secret endpoint URLs via DNS/network-layer observability.

Health status:
- `healthy` — all required configuration fields are present.
- `degraded` — one or more required fields are missing.

---

## Tenant isolation

Every API endpoint scopes its data to the tenant of the authenticated API key:

- `GET /orchestration/capabilities` — returns platform-wide capability metadata (safe,
  no tenant data).
- `GET /orchestration/health` — outbox counts are scoped to the calling tenant.
- `POST /automation-outbox/{id}/replay` — tenant ownership is enforced; cross-tenant
  replay is rejected with HTTP 404.

---

## Configuration reference

| Environment variable | Required by |
|---|---|
| `SLACK_WEBHOOK_URL` | `slack.notify` |
| `JIRA_BASE_URL` | `jira.issue.create` |
| `JIRA_EMAIL` | `jira.issue.create` |
| `JIRA_API_TOKEN` | `jira.issue.create` |
| `SIEM_WEBHOOK_URL` | `siem.push` |
| `SIEM_WEBHOOK_TOKEN` | `siem.push` (optional bearer token) |
| `CONNECTOR_DELIVERY_TIMEOUT_SECONDS` | All connectors (default: 10) |
| `CONNECTOR_MAX_ATTEMPTS` | All connectors (default: 5) |
