# OpenIntelligence Documentation

This directory is the versioned engineering handbook for OpenIntelligence: a multi-tenant cyber threat intelligence platform connecting external intelligence, internal assets, endpoint telemetry, investigations, and grounded AI.

> **Project execution state:** see [Planning → Project Status](planning/project-status.md) for the current source of truth on what is merged, in review, or not yet started.

## Navigation

### Getting started

| Document | Purpose |
|---|---|
| [Local development guide](getting-started/local-development.md) | Prerequisites, environment setup, install, lint/test, Docker workflow, troubleshooting |

### Planning

| Document | Purpose |
|---|---|
| [Project status tracker](planning/project-status.md) | Delivery tracker — merged, in review, blocked, next steps |
| [Roadmap](planning/roadmap.md) | Delivery sequence and readiness gates |

### Architecture

| Document | Purpose |
|---|---|
| [System overview](architecture/system-overview.md) | High-level service boundaries and data flow |
| [Component boundaries](architecture/component-boundaries.md) | Concrete modules, responsibilities, ownership, and dependency rules |
| [Decision records](architecture/decision-records.md) | ADRs: multi-tenancy, provenance, UUID, Postgres/outbox, approval-first, RAG, unknown states, migrations |

### Data

| Document | Purpose |
|---|---|
| [Schema and provenance](data/schema-and-provenance.md) | Layered schema contract and provenance rules |
| [Data dictionary](data/data-dictionary.md) | Domain entity glossary, field reference, lifecycle states |
| [Ingestion and normalization](data/ingestion-normalization.md) | Input → validation → normalize → deduplicate → provenance → quarantine → enrichment lifecycle |
| [Migration playbook](data/migration-playbook.md) | Forward-only migration protocol |

### API

| Document | Purpose |
|---|---|
| [API conventions](api/api-conventions.md) | REST conventions, authorization, and compatibility |
| [Endpoint inventory](api/endpoint-inventory.md) | Route families, scopes, tenant rules, status (merged vs planned) |
| [Error codes and idempotency](api/error-and-idempotency.md) | Response semantics, pagination, retry policy, safe client behavior |

### Security

| Document | Purpose |
|---|---|
| [Security model](security/security-model.md) | Credentials, mTLS, AI safety, audit requirements |
| [Threat model](security/threat-model.md) | Assets, trust boundaries, threats, mitigations, residual risks |

### Operations

| Document | Purpose |
|---|---|
| [Runbooks](operations/runbooks.md) | Migration, worker, and incident runbooks |
| [Configuration reference](operations/configuration.md) | Environment variable reference and connector settings |
| [Deployment guide](operations/deployment-guide.md) | Environment separation, config checklist, migration rollout, worker topology, release gates |
| [Observability and incidents](operations/observability-and-incidents.md) | Required logs/metrics/traces, alert conditions, dead-letter triage, incident response |

### Testing

| Document | Purpose |
|---|---|
| [Test strategy](testing/test-strategy.md) | Test pyramid, safety cases, contract tests, development validation matrix, release criteria |
| [Testing strategy (foundation)](testing/testing-strategy.md) | Original testing strategy document |

### Contributing

| Document | Purpose |
|---|---|
| [Engineering standards](contributing/engineering-standards.md) | Branch/PR expectations, code and API review checklist, migration rules, definition of done |

### Features

| Document | Purpose |
|---|---|
| [Feature index](features/README.md) | Domain-by-domain feature specifications index |
| [Intelligence ingestion](features/intelligence-ingestion.md) | Collection, normalization, provenance, enrichment |
| [Assets and endpoints](features/assets-and-endpoints.md) | Inventory, exposure, agent enrollment |
| [Investigation and cases](features/investigation-and-cases.md) | Investigations, cases, tasks, timeline |
| [Detection and response](features/detection-and-response.md) | Alerts, sightings, correlation, automation |
| [AI analyst](features/ai-analyst.md) | Grounded chat, cited brief, reports |

### Product

| Document | Purpose |
|---|---|
| [User flows](product/user-flows.md) | Analyst workflows: intelligence exploration, asset exposure, case, alert triage, correlation brief, automation approval, AI report |
| [Community and enterprise strategy](product/community-and-enterprise-strategy.md) | Product strategy |

## Documentation rules

- Change the relevant document in the same pull request as a material product or contract change.
- Database schema changes must update `data/schema-and-provenance.md` and include a migration note.
- API additions/changes must update `api/api-conventions.md` and route-contract tests.
- Never document a value as safe when it is unknown, unenriched, stale, or disputed.
- AI output must remain grounded in retrieved platform records and cite supporting sources.
