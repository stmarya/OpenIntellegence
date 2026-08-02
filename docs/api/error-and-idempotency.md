# Error Codes, Response Semantics, and Idempotency

---

## Response envelope

All list responses share a common envelope structure:

```json
{
  "data": [...],
  "page": {
    "limit": 50,
    "offset": 0,
    "total": 312,
    "has_more": true
  },
  "provenance": {
    "sources": ["nvd", "otx"],
    "degraded": ["ransomware_live"],
    "note": "ransomware_live feed returned an error during the last run; counts may be incomplete."
  }
}
```

| Field | Meaning |
|---|---|
| `data` | Array of result objects |
| `page.limit` | Page size used |
| `page.offset` | Offset applied |
| `page.total` | Total matching records |
| `page.has_more` | `true` if more pages available |
| `provenance.sources` | Feeds that contributed to this result |
| `provenance.degraded` | Feeds that failed or are unconfigured |
| `provenance.note` | Human-readable degradation message |

---

## HTTP status codes

| Status | When used | Notes |
|---|---|---|
| `200 OK` | Successful read or listing | |
| `201 Created` | Resource successfully created | Body contains the created resource |
| `202 Accepted` | Long-running operation queued | Body contains the resource at initial state; poll for completion |
| `204 No Content` | Successful delete with no body | |
| `400 Bad Request` | Malformed request (not schema-level) | See `error` and `message` fields |
| `401 Unauthorized` | Missing or invalid API key | `X-API-Key` header absent or invalid |
| `403 Forbidden` | Valid key but insufficient scope | Response body names the required scope |
| `404 Not Found` | Resource absent within caller's tenant | Does not reveal cross-tenant existence |
| `409 Conflict` | State conflict (e.g., revoking self) | `message` explains the conflict |
| `422 Unprocessable Entity` | Request body/query parameter validation failure | `fields` array provides per-field detail |
| `429 Too Many Requests` | Rate limit exceeded | `Retry-After` header present |
| `500 Internal Server Error` | Unexpected server error | Logged internally; do not expose stack traces |
| `502 Bad Gateway` | LLM provider failure | Used by AI endpoints when the upstream LLM fails |
| `503 Service Unavailable` | Readiness check failed (DB or Redis down) | `/health/ready` reports `checks` object |

---

## Error response body

Non-2xx responses include a structured body:

```json
{
  "error": "validation_failed",
  "message": "The request body or query parameters are invalid.",
  "fields": [
    {
      "location": "body.scopes",
      "problem": "value is not a valid list item"
    }
  ]
}
```

For 403 responses from scope enforcement:

```json
{
  "message": "Scope 'write' required.",
  "required": "write",
  "held": ["read", "ioc"]
}
```

---

## Rate limiting

Every response carries rate limit headers:

| Header | Value |
|---|---|
| `X-RateLimit-Limit` | Configured limit (requests/hour) |
| `X-RateLimit-Remaining` | Remaining requests in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |

On `429 Too Many Requests`:

| Header | Value |
|---|---|
| `Retry-After` | Seconds until the rate limit resets |

**Rate limit scope:** per API key, sliding window (1 hour default; configurable per key via `rate_limit_per_hour`).

**Degraded state:** if Redis is unavailable, the API falls back to an in-memory rate limiter. In-memory limits do not persist across restarts and are not shared across multiple API instances.

---

## Pagination

All list endpoints use offset-based pagination via `limit` and `offset` query parameters.

| Parameter | Default | Maximum | Notes |
|---|---|---|---|
| `limit` | 50 | 200 (most endpoints) | Some endpoints cap at 500 |
| `offset` | 0 | None | |

**Pagination example:**

```
GET /api/v1/vulnerabilities?limit=50&offset=100
```

Response includes `page.has_more: true` when `offset + limit < total`.

**Safe client behavior for pagination:**
- Do not assume total is stable between requests; concurrent ingestion may change it.
- Use `page.has_more` as the loop condition rather than computing from `total` and `limit`.
- Do not request pages beyond `total`; the response will have `data: []` and `has_more: false`.

---

## Explicit data state fields

The API uses explicit state fields rather than omitting or coercing unknown data:

| Field state | Representation | What clients must not do |
|---|---|---|
| Unknown CVSS | `"cvss_score": null` | Treat `null` as `0.0` or "safe" |
| Unenriched IOC | `"verdict": null` | Treat `null` as `"clean"` |
| Stale agent | `"status": "stale"` | Hide stale agents or treat as healthy |
| Partial/degraded response | `provenance.degraded` populated | Treat counts as complete |
| Unverified AI output | `provenance.note` set to explicit message | Surface AI output without the caveat |

---

## Idempotency — ingestion pipeline

The ingestion pipeline uses natural key upserts for all stored entities. Re-running the same ingestion connector (`POST /ingest/{source}/run`) is safe:

- Entities are matched by their natural key (e.g., `cve_id` for vulnerabilities, `(indicator_type, value)` for IOCs).
- Evidence arrays (`sources`) are merged, not duplicated.
- A re-run that produces the same records will update `last_seen` and `updated_at` but will not create duplicate rows.

---

## Idempotency — outbox delivery (planned, PR #9/PR #10)

Connector delivery records in the outbox use idempotency keys to prevent double-delivery:

- Each outbox message has a unique `idempotency_key` generated at creation time.
- Connector delivery workers check the idempotency key before dispatching.
- A message that has already been delivered to its target will not be dispatched again, even if the lease expired and was reclaimed.
- Idempotency scope is per-connector-target, not global.

---

## Retry policy — connector delivery (planned, PR #11)

| Attempt | Behavior |
|---|---|
| 1 | Deliver immediately |
| 2–N | Retry after exponential backoff (configurable via `CONNECTOR_MAX_ATTEMPTS`) |
| N+1 | Move to `dead_letter` status |

**Lease recovery:** a worker crash leaves the outbox message in `leased` state with an expired `lease_expires_at`. Another worker instance may safely reclaim and retry it. An active (non-expired) lease must not be claimed by a second worker.

**Dead-letter handling:** records in `dead_letter` state are visible to operators via the admin interface. Replay requires authorization. See `docs/operations/observability-and-incidents.md` for triage procedure.

---

## Timing header

Every response carries `X-Request-Duration-Ms` with the server-side request processing time in milliseconds, useful for performance diagnostics.

---

## Safe client behavior summary

| Behavior | Recommendation |
|---|---|
| Authentication | Send key in `X-API-Key` header; rotate keys before expiry |
| Rate limiting | Respect `Retry-After`; back off exponentially on repeated 429s |
| Pagination | Use `has_more` as loop condition; do not assume total is stable |
| Null handling | Never coerce `null` to a safe default; surface the unknown state |
| Provenance | Always display `provenance.degraded` warnings to users |
| 404 responses | Do not attempt to infer cross-tenant existence from 404 |
| Report polling | Poll `GET /reports/{id}` until status is `complete` or `failed`; do not re-trigger |
| Validation errors | Parse the `fields` array for per-field correction guidance |
| Retries on 5xx | Safe to retry idempotent GET requests; do not retry POST/DELETE blindly |
