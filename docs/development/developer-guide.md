# Developer Guide

## Local setup

Use Python with the project virtual environment. Configure only local secret values; never use production credentials.

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

## Change workflow

1. Read the applicable feature specification and data/API/security contract.
2. Make a focused branch and keep one concern per PR.
3. For a schema change: update model, forward Alembic migration, API/service usage, contract tests, and `docs/data/`.
4. For an endpoint: register it exactly once through `app/api/v1/router.py`, apply tenant/scopes, and extend route-contract tests.
5. For a worker: keep network delivery outside request handlers, use idempotency/leases where applicable, and document failure handling.
6. In the PR, state validation actually executed and any limitation.

## Definition of done

- Tenant filtering on all tenant-owned reads/writes.
- No secrets in code, logs, fixtures, migrations, or documentation.
- Unknown/unverified/stale data is explicit.
- Tests cover the success path and meaningful safety/failure path.
- Documentation and status tracker are updated.
