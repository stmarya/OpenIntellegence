# Observability and Incidents

## Status: Implemented in feature branch; pending integration/review/validation — P1 operational health endpoints

---

## Orchestration health summary

### Endpoint

```
GET /orchestration/health
Authorization: ******   (read scope)
```

### Response shape

```json
{
  "capabilities": [
    {
      "action": "slack.notify",
      "connector_type": "slack",
      "enabled": true,
      "config_state": "configured",
      "config_reason": "Webhook URL is set."
    },
    {
      "action": "endpoint.command.request",
      "connector_type": "internal",
      "enabled": false,
      "config_state": "planned",
      "config_reason": "Worker implementation is planned; requires dual approval; no automatic replay permitted."
    }
  ],
  "connectors": [
    {
      "action": "slack.notify",
      "connector_type": "slack",
      "status": "healthy",
      "config_state": "configured",
      "config_reason": "Webhook URL is set.",
      "active_probe": "planned"
    }
  ],
  "outbox": {
    "queued": 0,
    "delivering": 0,
    "retry": 2,
    "dead_letter": 1,
    "delivered": 342,
    "oldest_queued_seconds": 45.2
  }
}
```

### Outbox counts

All counts are scoped to the **calling tenant**.  Cross-tenant counts are never
included.  The `oldest_queued_seconds` field reports the age of the oldest item
in `queued` or `retry` state; `null` when there are none.

---

## Capability registry

```
GET /orchestration/capabilities
Authorization: ******   (read scope)
```

Returns the full capability list including planned/unavailable actions.  Secrets
(webhook URLs, API tokens) are **never** present in the response.  Each entry
describes:

- `action` — the action identifier (e.g., `slack.notify`).
- `connector_type` — `slack`, `jira`, `siem_webhook`, or `internal`.
- `enabled` — whether the connector is currently active.
- `config_state` — `configured`, `not_configured`, or `planned`.
- `config_reason` — human-readable explanation (never contains secrets).

---

## Connector health

Each connector in `GET /orchestration/health` includes a `status` field:

| Status | Meaning |
|---|---|
| `healthy` | All required configuration fields are present. |
| `degraded` | One or more required fields are missing. |

The `active_probe` field is always `"planned"`.  Active network probing is not
yet implemented; deriving health from configuration is intentional to avoid
leaking secret endpoint URLs via DNS/network-layer monitoring systems.

---

## Dead-letter monitoring

Dead-lettered outbox items appear in the `dead_letter` count from
`GET /orchestration/health`.  Operators should monitor this count and replay
legitimate failures via the replay API once the underlying cause is resolved.

### Alert thresholds (recommended)

| Metric | Warning | Critical |
|---|---|---|
| `dead_letter` count | > 0 | > 10 |
| `oldest_queued_seconds` | > 300 (5 min) | > 3600 (1 h) |
| `retry` count | > 5 | > 50 |

---

## Incident response — stale outbox items

1. Check `GET /orchestration/health` for the calling tenant's outbox counts.
2. If `dead_letter > 0`, identify the root cause (connector misconfiguration,
   downstream service unavailability, payload validation error).
3. For `slack.notify`, `jira.issue.create`, or `siem.push` failures, replay
   the item once the connector is healthy:
   ```
   POST /automation-outbox/{outbox_id}/replay
   { "reason": "Slack outage resolved; replaying failed notification." }
   ```
4. `endpoint.command.request` items **must not** be replayed automatically.
   Create a new automation run with fresh dual approvals.
5. Each replay generates a new idempotency key preventing duplicate remote
   side effects from the original attempt.

---

## Log correlation

The delivery worker logs structured events at INFO level for each delivery
attempt, including:

- `outbox_id` — the `AutomationOutbox` UUID.
- `action` — the action being delivered.
- `attempt` — the attempt number (1-based).
- `state` — the resulting state (`delivered`, `retry`, `dead_letter`).
- `error` — error message on failure.

Correlate these with tenant and run IDs in `AutomationRun` for full trace.
