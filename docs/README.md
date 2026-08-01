# OpenIntelligence Documentation

This directory is the maintained project knowledge base for **OpenIntelligence**, a multi-tenant cyber threat intelligence platform that connects external intelligence, internal assets, endpoint telemetry, investigation workflows, and grounded AI-assisted intelligence production.

## Start here

| Document | Purpose |
|---|---|
| [Project plan](plan.md) | Product direction, milestones, delivery gates, and current priorities |
| [Architecture](architecture.md) | System boundaries, components, trust model, and data flow |
| [Feature catalog](features.md) | Implemented, in-progress, planned, and deferred capabilities |
| [API guide](api.md) | Versioning, authentication, route families, and API behavior |
| [Data model](data-model.md) | Canonical entities, tenancy, provenance, and schema rules |
| [Operations](operations.md) | Local development, migrations, workers, configuration, and validation |
| [Security](security.md) | Security controls and non-negotiable safety rules |
| [Roadmap](roadmap.md) | Ordered engineering backlog and readiness criteria |

## Documentation rules

- Update the relevant document in the same pull request as any behavior, schema, API, security, or operational change.
- Mark a capability **implemented** only when it is integrated, guarded by tests, and ready for development validation—not merely present on a feature branch.
- Do not document unknown intelligence as safe, clean, or zero risk.
- Never place credentials, API keys, certificates, personal data, or customer data in documentation.
- The API contract, Alembic migration history, and SQLAlchemy metadata must describe the same data contract.
