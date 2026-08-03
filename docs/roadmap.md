# Roadmap and status

## Implemented in source

- P0 foundation: migrations, normalized ingest, `/api/v1`, mTLS gateway, API keys, CI and security scanning.
- CTI and console: tenant-aware intelligence, assets, alerts, cases, investigations, reports, and 54+ route surfaces.
- Runtime: API, frontend, connector delivery, internal automation, alert evaluation, and intent expiry services.
- Write workbench: eight allowlisted operations behind server credentials and an independent operator token.
- Priority foundation: users, roles, assignments, sessions, typed relationships, revisions, saved searches, global search, connector checkpoints, safe inventory commands, AI evaluations, and detection rules.
- Operations: request IDs, bounded Prometheus metrics, dependency readiness, backup/restore scripts, dependency updates, SBOM inventory, and container scanning.

## Important boundaries

| Capability | Current boundary |
| --- | --- |
| Human identity | User/role/session persistence exists; API keys still authenticate requests. OIDC/SAML verification and MFA ceremony are not wired. |
| Endpoint commands | Only `collect_inventory` is publishable. No arbitrary shell, destructive response, or runtime-configurable allowlist exists. |
| Relationships | Typed edge and revision persistence/API exist; historical entities are not backfilled automatically. |
| Search | Database exact/substring search is available. OpenSearch indexing and ranking are not wired. |
| Connector replay | Checkpoint persistence exists. Record-level quarantine replay needs connector-specific normalization entry points. |
| AI governance | Citation enforcement and evaluation records exist. A complete golden-set evaluation runner and approval UI remain. |
| Detection engineering | Sigma/YARA/Suricata/Snort storage exists. Format-specific compilers and deployment adapters remain. |
| Production | No build, migration, CI, restore, or deployment outcome has been observed from this environment. |

## Next verification gate

1. Python 3.12 compile, Ruff, pytest, Alembic single-head and upgrade.
2. Frontend dependency install, lint, type-check, tests, and production build.
3. Compose startup, tenant bootstrap, user/role creation, agent enrollment, heartbeat, command poll, search, graph, AI evaluation, and detection-rule smoke paths.
4. Backup and destructive restore drill against a disposable database.
5. Commit `frontend/package-lock.json`, then replace `npm install` with `npm ci`.

Source presence is not runtime health. This roadmap does not call the platform production-ready.
