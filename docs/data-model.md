# Data Model and Schema Contract

## Canonical rule

For every persisted entity, these must agree:

1. SQLAlchemy ORM metadata;
2. Alembic migration schema;
3. API and service assumptions;
4. database constraints, indexes, defaults, and foreign keys.

A model field that is missing from migrations is a runtime defect, not documentation debt.

## Core entity groups

| Group | Representative entities |
|---|---|
| Tenant/security | tenant, API key, audit log, rate-limit identity |
| Intelligence | indicator, threat actor, campaign, malware, vulnerability, ransomware victim |
| Asset context | asset, installed software, exposure, agent state |
| Research corpus | source document, chunk, embedding, citation |
| Workflow | investigation, investigation entity, case, task, case event |
| Detection | alert rule, alert, sighting |
| Correlation | correlation, factor breakdown, AI brief, citations |
| Automation | playbook, run, approval, outbox, delivery receipt |

## Identity and tenancy

- Use one consistent identifier strategy per entity family; do not mix UUID and integer assumptions between model and migration.
- Tenant-owned tables require `tenant_id` and tenant-oriented query paths.
- Cross-tenant joins must be impossible through API behavior; query filters are mandatory even when an ID appears globally unique.

## Data integrity requirements

- Alert deduplication uses a unique `(tenant_id, fingerprint)` constraint.
- Outbox records preserve idempotency keys, lease state, attempt count, delivery result, and terminal failure state.
- Event/timeline records are append-only unless an explicit retention process says otherwise.
- Original source artifacts may be retained separately, but normalized intelligence must retain source references and timestamps.

## Migration policy

- Migrations are forward-only once used outside a disposable local environment.
- Do not rewrite a released baseline to hide schema mismatch; add corrective migrations.
- The repository must expose one Alembic head and a deterministic chain.
