# Project Status

Last updated: 2026-08-02

---

## P0 — Backend integration (complete)

| Feature | Status |
|---|---|
| Approval-first automation orchestration | ✅ Complete |
| Dual-approval for `endpoint.command.request` | ✅ Complete |
| Connector outbox with lease/retry semantics | ✅ Complete |
| Slack, Jira, SIEM webhook delivery adapters | ✅ Complete |
| Bounded retry with exponential back-off (max 5 attempts) | ✅ Complete |
| Secret-free configuration (all credentials via `SecretStr`) | ✅ Complete |
| Idempotency key uniqueness enforcement | ✅ Complete |

## P1 — Orchestration reliability controls (complete)

| Feature | Status |
|---|---|
| Connector capability registry (safe metadata, no secrets) | ✅ Complete |
| `GET /orchestration/capabilities` — read-scope API | ✅ Complete |
| `GET /orchestration/health` — tenant-scoped outbox counts | ✅ Complete |
| Dispatch validation — unavailable adapter rejection | ✅ Complete |
| Internal action handling — never silently dead-lettered | ✅ Complete |
| Dead-letter replay (`POST /automation-outbox/{id}/replay`) | ✅ Complete |
| Replay idempotency (new key per replay, attempt reset) | ✅ Complete |
| Replay audit trail (`replay_history` column) | ✅ Complete |
| Tenant isolation for replay and health endpoints | ✅ Complete |
| Config-based connector health (no network probes) | ✅ Complete |
| Worker claim filter — internal actions excluded | ✅ Complete |
| Deterministic reliability tests (no external calls) | ✅ Complete |

## Planned

| Feature | Status |
|---|---|
| `case.create` internal worker | 🔲 Planned |
| `report.generate` internal worker | 🔲 Planned |
| `endpoint.command.request` internal worker | 🔲 Planned |
| Active connector health probes (network ping) | 🔲 Planned — deferred to avoid URL leakage via monitoring |
| Prometheus metrics for outbox state counts | 🔲 Planned |
| Webhook event delivery for dead-letter alerts | 🔲 Planned |

---

## Data migrations

| Revision | Description | Status |
|---|---|---|
| 0001 | Initial schema | ✅ Applied |
| 0002 | Campaign and malware domain tables | ✅ Applied |
| 0003 | Investigations and cases | ✅ Applied |
| 0004 | Alerts and sightings | ✅ Applied |
| 0005 | Correlation AI briefs | ✅ Applied |
| 0006 | Approval-first orchestration | ✅ Applied |
| 0007 | Connector delivery runtime (lease/retry) | ✅ Applied |
| 0008 | Replay tracking columns (`replay_count`, `replay_history`) | ✅ Applied |

---

## Security posture

- All secrets loaded via `pydantic-settings` `SecretStr`; never serialised to JSON.
- API responses from capability and health endpoints are verified to contain no secret values.
- Tenant isolation enforced on all orchestration read and write endpoints.
- Dead-letter replay requires write scope and tenant ownership; `endpoint.command.request`
  replay is hard-blocked.
- No active network probes that could leak configured endpoint URLs.
