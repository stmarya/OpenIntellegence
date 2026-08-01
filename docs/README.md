# OpenIntelligence Documentation

This directory is the versioned engineering handbook for OpenIntelligence: a multi-tenant cyber threat intelligence platform connecting external intelligence, internal assets, endpoint telemetry, investigations, and grounded AI.

## Navigation

| Area | Purpose |
|---|---|
| [Planning](planning/roadmap.md) | Current delivery sequence and readiness gates |
| [Architecture](architecture/system-overview.md) | System boundaries and service responsibilities |
| [Data contracts](data/schema-and-provenance.md) | Source of truth, schema, tenant, and provenance rules |
| [API](api/api-conventions.md) | REST conventions, authorization, and compatibility |
| [Security](security/security-model.md) | Secrets, API keys, mTLS, approval boundaries |
| [Operations](operations/runbooks.md) | Migration, worker, release, and incident runbooks |
| [Features](features/README.md) | Domain-by-domain feature specifications |

## Documentation rules

- Change the relevant document in the same pull request as a material product or contract change.
- Database schema changes must update `data/schema-and-provenance.md` and include a migration note.
- API additions/changes must update `api/api-conventions.md` and route-contract tests.
- Never document a value as safe when it is unknown, unenriched, stale, or disputed.
- AI output must remain grounded in retrieved platform records and cite supporting sources.
