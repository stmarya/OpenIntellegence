# Roadmap and status

## Complete

### P0 — foundation

Schema and migrations, source normalization across 14 feeds, REST `/api/v1`,
agent gateway, API key service with authentication and rate limiting, initial AI
layer.

### Detection and correlation

Tenant-filtered bounded rule evaluation, cooldown and fingerprint idempotency,
evidence resolver limits, feed health without operational leakage, unknown CVSS
preserved, AI withholding behaviour test.

### Automation reliability and endpoint request control

Capability gating wired into creation, proposal and dispatch; 422 before
persistence; internal action separation; endpoint intents excluded from
automation; dead-letter replay with fresh idempotency. Intent expiry now runs on
a schedule via `app/workers/intent_expiry_runner.py`.

### Console

Global shell, 53 route surfaces, shared component library, safe empty and
unavailable states, server-side fetch boundary, snapshot-backed repositories,
control-plane-only endpoint intent surface.

### Schema reconciliation

Seven defects found by reading each page against the schema it consumes, rather
than against the schema it assumed. Two of them had pages denying evidence they
had already fetched, and one rendered every malware family as having no
capabilities. Pattern recorded in `docs/frontend.md`: verify the response
envelope and the field types before writing the consuming type.

## Not built

These are absent by decision or by dependency, and the console names each gap
rather than faking it.

| Item | Blocks |
| --- | --- |
| Typed relationship edges | Relationship and graph tabs on every entity |
| Per-entity revision history | History and timeline tabs |
| Advisory entity | `/advisories` is gated |
| Collection, detection-content, requirement, ransomware-group detail endpoints | Detail routes for those four |
| User and role model | Any per-person attribution |
| Cross-tenant sharing | The sharing surface states its absence |
| Write surfaces (create case, create investigation, acknowledge alert, trigger ingest, quarantine replay) | The console is read-only |
| Endpoint command delivery | Intents remain recorded decisions |

## Next

1. **Validation sweep. Nothing in this repository has ever been compiled or executed.** `ruff`, `pytest`, `alembic upgrade head`, `npm run lint`, `npm run type-check`, `next build`. Requires Python 3.12+ (PEP 695 generics in `app/api/schemas.py`).
2. Continue reading the remaining API modules against their consuming pages: `workflows.py`, `correlations.py`, `governance.py`. Defect density so far is roughly one per file.
3. Backend work for the eight items above, in dependency order — typed edges and revision history unblock the most console surface.
4. Write surfaces, once a scope model beyond a read key exists.
5. Connector configuration for development, then production hardening.

"Code complete" is not "ready", and this document will not describe it as ready
until the project builds.
