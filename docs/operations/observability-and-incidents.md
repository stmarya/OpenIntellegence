# Observability and Incident Response

---

## Required logs

All log output uses `structlog` in structured JSON format. Every log event must include at minimum:

| Field | Required | Description |
|---|---|---|
| `timestamp` | Yes | ISO 8601 UTC |
| `level` | Yes | `debug`, `info`, `warning`, `error`, `critical` |
| `event` | Yes | Machine-readable event name |
| `service` | Yes | `openintelligence-api` or `openintelligence-worker` |
| `tenant_id` | When applicable | Must be redacted from error logs if cross-tenant risk |
| `trace_id` / `request_id` | When available | For request correlation |

### Required log events

| Event | Level | Trigger |
|---|---|---|
| `rate_limiter_ready` | info | Redis-backed rate limiter initialized |
| `rate_limiter_degraded` | warning | Redis unavailable; in-memory fallback active |
| `api_key.created` | info | New API key issued (audit log also written) |
| `api_key.revoked` | info | API key revoked (audit log also written) |
| `api_key.auth_failed` | warning | Authentication attempt with invalid key |
| `ingest.run.started` | info | Ingestion run begins |
| `ingest.run.completed` | info | Ingestion run ends (include status, counts) |
| `ingest.run.failed` | error | Ingestion run error |
| `ingest.record.quarantined` | warning | Record rejected to quarantine |
| `outbox.lease.claimed` | debug | Worker claims outbox message |
| `outbox.delivery.success` | info | Message delivered to connector |
| `outbox.delivery.failed` | warning | Delivery attempt failed; will retry |
| `outbox.dead_letter` | error | Message moved to dead_letter after max attempts |
| `agent.enrolled` | info | Endpoint agent enrolled |
| `agent.heartbeat.received` | debug | Heartbeat received; staleness reset |
| `agent.stale` | warning | Agent missed heartbeat threshold |
| `ai.rag.no_context` | warning | RAG query returned no supporting records |
| `ai.llm.error` | error | LLM provider returned an error |
| `ai.report.generated` | info | Report generation complete |

**Rule:** Log entries must never contain: secret values, full API key plaintext, certificate private key material, connector credential values, or raw database passwords.

---

## Required metrics

Use `prometheus-client` (already in dependencies). All metrics must include a `tenant_id` label where applicable, but ensure the label is not used to derive cross-tenant counts.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `http_requests_total` | Counter | `method`, `path`, `status_code` | All HTTP requests |
| `http_request_duration_seconds` | Histogram | `method`, `path` | Request latency |
| `rate_limit_exceeded_total` | Counter | `key_prefix` | 429 responses |
| `ingest_records_ingested_total` | Counter | `source` | Successfully ingested records |
| `ingest_records_quarantined_total` | Counter | `source`, `reason` | Quarantined records |
| `ingest_run_duration_seconds` | Histogram | `source`, `status` | Ingestion run duration |
| `outbox_messages_pending` | Gauge | — | Current pending outbox count |
| `outbox_delivery_attempts_total` | Counter | `connector`, `outcome` | Delivery attempts by outcome |
| `outbox_dead_letter_total` | Counter | `connector` | Messages moved to dead_letter |
| `agent_stale_total` | Gauge | — | Current count of stale agents |
| `ai_rag_context_retrieved` | Histogram | — | Number of chunks retrieved per query |
| `ai_llm_errors_total` | Counter | `error_class` | LLM provider errors |

---

## Required traces

Distributed tracing (e.g., OpenTelemetry) is intended but not yet implemented. Until it is:

- Use `X-Request-Duration-Ms` response header for latency measurement
- Correlate logs by `source_run_id` for ingestion pipeline spans
- Correlate logs by `report_id` for AI report generation spans

---

## Alert conditions

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Multiple Alembic heads | `alembic heads` returns > 1 revision | Critical | Halt deployment; do not start new instances |
| Database connectivity failure | `/health/ready` checks.database ≠ "ok" | Critical | Page on-call; check Postgres health |
| Redis unavailable (production) | `rate_limiter_degraded` log + production env | High | Page on-call; unmetered API access is active |
| High quarantine rate | `ingest_records_quarantined_total` > 10% of fetched per run | Medium | Investigate source feed change or parser bug |
| Dead-letter growth | `outbox_dead_letter_total` increasing | High | See dead-letter triage below |
| Feed authentication failure | `SourceRun.status = auth_error` | Medium | Check connector credential; rotate if needed |
| Agent staleness spike | `agent_stale_total` jumps significantly | Medium | Check network connectivity; investigate mass heartbeat failure |
| LLM error rate | `ai_llm_errors_total` > threshold | Medium | Check LLM provider status; consider fallback |
| Rate limit spike | `rate_limit_exceeded_total` > threshold | Low–High | Investigate API key abuse; consider rate limit adjustment |

---

## Connector dead-letter triage

When `outbox_dead_letter_total` increases:

1. **Identify affected connector:** query dead-letter records by connector type.
2. **Inspect error class:** review `outbox_messages.error_detail` (planned field) for the failure category:
   - `auth_error`: connector credential is invalid or expired — rotate and reconfigure
   - `timeout`: target endpoint is slow or unreachable — check connectivity and target health
   - `rate_limited`: target API quota exceeded — reduce delivery frequency or increase quota
   - `schema_error`: payload rejected by target — check connector payload format against target API
   - `unknown`: inspect full error log for the delivery worker
3. **Resolve root cause** before authorizing replay.
4. **Authorize replay** (requires `admin` scope; planned: approval required).
5. **Monitor** `outbox_delivery_attempts_total` for successful delivery after replay.

**Do not replay dead-letter records** without understanding the root cause; repeated delivery attempts may trigger downstream duplicate processing or rate limits.

---

## Data ingestion degradation response

When a feed is degraded (`SourceRun.status = partial` or `failed`):

1. Check `GET /feeds` for health state and last successful run time.
2. Check `GET /runs?limit=10` for recent run error messages.
3. Determine if degradation is:
   - Transient (network timeout, provider outage): wait for next run; verify recovery
   - Credential failure: rotate key; reconfigure; re-trigger `POST /ingest/{source}/run`
   - Parser bug: identify quarantined records (`GET /quarantine?source=<source>`); fix normalization; replay
   - Source schema change: update connector and normalization logic; re-run
4. After recovery, verify `records_quarantined` returns to baseline.
5. Note in PR/status tracker if a data gap occurred during degradation.

**Analyst communication:** if a feed degradation exceeds 1 hour, notify analysts that intelligence counts may be incomplete and that `provenance.degraded` will appear in API responses.

---

## Security incident response

### Level 1 — Credential exposed or suspected leak

1. **Immediately revoke** the affected credential (API key, connector token, CA key).
2. **Preserve audit log** — do not delete any audit records.
3. **Review audit log** for activity since the credential was issued:
   ```
   GET /api/v1/audit-logs?actor_key_id=<key_id>&since=<iso_timestamp>
   ```
4. **Assess blast radius:** what scopes did the key have? Were mutations made?
5. **Rotate all credentials** in the same secret class if the exposure mechanism is a leaked environment file.
6. **Report** to affected tenants if cross-tenant data was accessed.

### Level 2 — Cross-tenant data access detected

1. **Immediately halt** new requests if possible; put application in maintenance mode.
2. **Preserve evidence:** all relevant audit log rows, request logs, and database state.
3. **Determine scope:** which tenants affected, which records accessed, for how long.
4. **Notify affected tenants** per disclosure obligations.
5. **Root-cause analysis:** was it a missing tenant_id filter, a middleware bypass, or credential sharing?
6. **Do not** clear audit logs or modify database state during investigation.

### Level 3 — Migration failure in production

1. **Stop** all new application instances immediately.
2. **Do not** manually edit the `alembic_version` table.
3. **Restore from backup** taken before the migration.
4. **Diagnose** the migration failure on a clone.
5. **Create a corrective forward migration** and test on staging before re-deploying.

---

## Evidence retention

| Evidence type | Retention minimum | Notes |
|---|---|---|
| Audit logs | 12 months | Never delete; append-only |
| Ingestion run records | 90 days | Reduce after deduplication |
| Quarantined records | 90 days or until replayed | |
| Dead-letter records | Until resolved + 30 days | |
| Application logs | 30 days (development), 90 days (production) | |
| Security incident evidence | 12 months minimum | Legal hold if applicable |

---

## Ownership

| Area | Primary owner | Escalation |
|---|---|---|
| API availability | On-call engineer | Engineering lead |
| Data ingestion | On-call engineer | Feed owner |
| Security incidents | Engineering lead | Legal / compliance if tenant data affected |
| AI content quality | AI feature owner | Engineering lead |
| Connector delivery | On-call engineer | Connector owner |
