# API Guide

## Versioning and base path

All public REST endpoints use the versioned base path:

```text
/api/v1
```

The final route registry is maintained in `app/api/v1/router.py`. It must mount each supported router once and only once.

## Authentication and tenancy

API clients authenticate with an API key. The server derives the tenant and key identity; callers must never submit a tenant ID to choose another tenant context.

Scopes follow least privilege:

- `read` — retrieve permitted tenant data.
- `write` — create or change tenant data.
- specialized scopes may be added for high-impact functions such as AI generation or endpoint command requests.

Creating an AI brief is a write operation because it persists state and invokes an AI provider.

## API families

| Family | Examples |
|---|---|
| Health | `/health`, `/health/ready` |
| Ingestion & intelligence | feeds, normalized records, indicators, vulnerabilities |
| Assets & agents | assets, software, vulnerabilities, enrollment, heartbeat |
| Research | search, actors, IOCs, campaigns, malware |
| Analyst workflows | investigations, cases, tasks, case timeline |
| Detection | alert rules, alerts, sightings |
| Correlation & AI | correlations, deterministic assessments, cited AI briefs |
| Automation | playbooks, proposed/approved runs, outbox delivery |
| Reporting | grounded reports and document retrieval |

## Contract rules

- Use standard HTTP status codes; unknown entity types are validation errors, not silent empty results.
- List endpoints paginate and return a consistent page envelope.
- Do not expose data across tenants.
- Responses representing external claims should include or link to provenance.
- Write endpoints must be idempotent where retries can produce duplicate side effects.
- Endpoint and connector operations must fail safely and visibly; they may not silently drop requests.
