# Project Status

Last updated: 2026-08-02

> **Note:** All items below reflect the state of unmerged feature branches.
> Nothing here has been applied to a production or integration environment.
> Status values indicate implementation progress within the feature branch only.
> Final validation occurs after integration into the main branch.

---

## P0 — Backend integration (implemented in feature branch; pending integration/review/validation)

| Feature | Status |
|---|---|
| Approval-first automation orchestration | ✅ Implemented in feature branch |
| Dual-approval for `endpoint.command.request` | ✅ Implemented in feature branch |
| Connector outbox with lease/retry semantics | ✅ Implemented in feature branch |
| Slack, Jira, SIEM webhook delivery adapters | ✅ Implemented in feature branch |
| Bounded retry with exponential back-off (max 5 attempts) | ✅ Implemented in feature branch |
| Secret-free configuration (all credentials via `SecretStr`) | ✅ Implemented in feature branch |
| Idempotency key uniqueness enforcement | ✅ Implemented in feature branch |

## P1 — Orchestration reliability controls (implemented in feature branch; pending integration/review/validation)

| Feature | Status |
|---|---|
| Connector capability registry (safe metadata, no secrets) | ✅ Implemented in feature branch |
| `GET /orchestration/capabilities` — read-scope API | ✅ Implemented in feature branch |
| `GET /orchestration/health` — tenant-scoped outbox counts | ✅ Implemented in feature branch |
| Dispatch validation — all unavailable action rejection | ✅ Implemented in feature branch |
| Internal action blocking — dispatch rejects unimplemented workers | ✅ Implemented in feature branch |
| Dead-letter replay (`POST /automation-outbox/{id}/replay`) | ✅ Implemented in feature branch |
| Replay idempotency (new key per replay, attempt reset) | ✅ Implemented in feature branch |
| Replay audit trail (`replay_history` column) | ✅ Implemented in feature branch |
| Tenant isolation for replay and health endpoints | ✅ Implemented in feature branch |
| Config-based connector health (no network probes) | ✅ Implemented in feature branch |
| Worker claim filter — internal actions excluded | ✅ Implemented in feature branch |
| Deterministic reliability tests (no external calls) | ✅ Implemented in feature branch |

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

> Migration status reflects the feature branch only.  None of these have been
> applied to a shared or production database; final numbering and ordering will
> be confirmed during integration.

| Revision | Description | Status |
|---|---|---|
| 0001 | Initial schema | ⏳ Pending application — implemented in feature branch |
| 0002 | Campaign and malware domain tables | ⏳ Pending application — implemented in feature branch |
| 0003 | Investigations and cases | ⏳ Pending application — implemented in feature branch |
| 0004 | Alerts and sightings | ⏳ Pending application — implemented in feature branch |
| 0005 | Correlation AI briefs | ⏳ Pending application — implemented in feature branch |
| 0006 | Approval-first orchestration | ⏳ Pending application — implemented in feature branch |
| 0007 | Connector delivery runtime (lease/retry) | ⏳ Pending application — implemented in feature branch |
| 0008 | Replay tracking columns (`replay_count`, `replay_history`) | ⏳ Pending application — implemented in feature branch; revision number subject to change on integration |

---

## Security posture

- All secrets loaded via `pydantic-settings` `SecretStr`; never serialised to JSON.
- API responses from capability and health endpoints are verified to contain no secret values.
- Tenant isolation enforced on all orchestration read and write endpoints.
- Dead-letter replay requires write scope and tenant ownership; `endpoint.command.request`
  replay is hard-blocked.
- No active network probes that could leak configured endpoint URLs.
