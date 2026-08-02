# Data model

## Tenancy

Every domain table carries a tenant identifier. Every query, insert, worker claim, and replay filters on it.
There is no cross-tenant read path, including for administrative tooling.

## Entity groups

- **Intelligence** — vulnerabilities, indicators, research references, threat actors.
- **Assets** — enrolled endpoints, inventory attributes, heartbeat and staleness state.
- **Detection** — rules, alerts, alert fingerprints, cooldown windows.
- **Correlation** — correlation records, evidence links, generated briefs.
- **Orchestration** — playbooks, runs, outbox rows, dead letters.
- **Control plane** — endpoint intent requests, approvals, expiry state.

## Provenance columns

Intelligence records store the source file, snapshot label, upstream repository, commit, and observation timestamp.
A record without provenance is invalid and must not be persisted.

## Null semantics

- `cvss_score` is nullable and stays `NULL` when the upstream source omits it.
- Absence from the KEV corpus means unknown exploitation, not absence of exploitation.
- Never coerce unknown to `0`, `false`, or an empty string.

## Migrations

Alembic is the single source of truth for schema change. Lineage is asserted by a dedicated test so the
revision graph cannot fork silently.
