# API Conventions

## Base path and contracts

All public backend routes are under `/api/v1`. New routers must be registered exactly once through `app/api/v1/router.py`; `app/main.py` mounts that registry once.

## Authorization

- API keys are scoped; read endpoints use `read`, mutations use `write`.
- Persisted AI generation is a mutation and requires `write` at minimum.
- Endpoint command execution requires approval controls and will move to user/role separation-of-duties when the identity layer is introduced.

## Response semantics

- List endpoints return data, pagination, and provenance/partial-data context when applicable.
- `404` means a resource is absent *within the caller tenant*.
- Do not expose a cross-tenant existence oracle.
- Use explicit status fields for `unenriched`, `unverified`, `partial`, `stale`, and `dead_letter` states.

## Compatibility

- Additive changes are preferred.
- Breaking changes require a versioning decision, migration note, contract tests, and a documented client transition path.
- Every router family must be covered by API contract tests.
