# Governance surfaces

This document covers the read surfaces that back the last five console pages,
plus two reliability behaviours that were previously derived at read time.

## Endpoints

| Endpoint | Purpose | Scope |
|---|---|---|
| `GET /detection-content` | Detection rules tracked as intelligence product | `read` |
| `GET /collections` | Analyst-curated groupings of entities | `read` |
| `GET /intelligence-requirements` | Standing requirements and their recorded coverage | `read` |
| `GET /audit-log` | Recorded audit events for the tenant | `read` |
| `GET /settings` | Policy constants the platform enforces | `read` |

All list endpoints are tenant-scoped, paginated (`limit` 1–200, `offset`), and
return the standard `ListResponse` envelope with provenance.

## Audit coverage is deliberately narrow

`GET /audit-log` reads `endpoint_intent_audit` joined to `endpoint_intents` so
the tenant filter is enforced through the parent record. Every row carries an
explicit `source` field, and the response provenance note states that coverage
spans endpoint intent control-plane events only.

This matters: other subsystems do not yet persist audit rows. An empty audit log
means *nothing has been recorded*, not *nothing has happened*. The note prevents
the page from being read as a complete account of platform activity, which would
be a false assurance during an incident review.

Extending coverage means persisting audit rows in the originating subsystem and
adding it as a further `source` here — not widening the query over tables that
happen to have timestamps.

## Settings exposes decisions, not secrets

`GET /settings` returns policy constants only: grantable API key scopes, the
allowlisted endpoint intents, the two-distinct-approver rule, the actions that
can never be replayed, and the configured automation capabilities.

No credential, connection string, token, or provider key is read by this
endpoint. Capability state is derived from configuration, not from probing an
external system, so a `configured` capability means "configuration is present",
never "the integration was reached". `endpoint_command_delivery` is reported as
`not_implemented`, matching the fact that endpoint intents remain control-plane
records with no delivery path.

## Deterministic intent expiry

`app/workers/intent_expiry.py` provides `sweep_expired_intents(session, now=None)`.
It selects `pending` intents whose `expires_at` has elapsed, sets `state` to
`expired`, and appends an `EndpointIntentAudit` row with actor
`system:intent_expiry`.

Read paths still derive `effective_state` so an intent never *looks* actionable
between sweeps, but the sweep is what makes the transition durable. Without it,
two operators reading the ledger at different times would reconstruct different
histories. Only `pending` rows are selected, so the sweep is idempotent and
re-running it produces no additional audit rows.

Naive timestamps returned by SQLite are treated as UTC rather than allowing the
comparison to raise.

## Replay audit persistence

`replay_dead_letter` now writes an `automation_replay_audit` row alongside the
queued replay message. The replayed message already carries its origin in its
payload, but a payload can be rewritten by a later step; the audit row is the
durable record of who requested the retry, for which action, and when.

The non-replayable action set is unchanged: `endpoint.command.request`,
`case.create`, and `report.generate` are still refused before any row is written.

## Schema

Migration `0009_governance_surfaces` adds `detection_content`,
`intel_collections`, `intelligence_requirements`, and
`automation_replay_audit`. Models live in `app/db/governance_models.py` and are
registered in `app/db/registry.py`.

List-valued columns use `JsonType` rather than `StrArray` so the migration maps
cleanly to `sa.JSON()` on both SQLite and PostgreSQL.
