# Operations Runbooks

## Database migration

Before any environment migration:

```bash
alembic heads
alembic current
alembic upgrade head
```

Expected state: one head. Stop rollout on multiple heads, schema mismatch, or failed migration. Do not manually edit the `alembic_version` table to bypass a migration.

## Connector delivery worker

```bash
python -m app.workers.connector_delivery
```

The worker claims messages with a lease, uses `FOR UPDATE SKIP LOCKED`, persists receipts, retries transient failures, and moves terminal failures to `dead_letter`. An expired delivery lease may be safely reclaimed.

## Development validation

Run static and unit checks before containers; run integration validation against a disposable database. Exercise connector delivery only through mock endpoints until configuration and security reviews are complete.

## Incident priorities

1. Cross-tenant exposure, leaked secret, or unauthorized command: disable credential/connector and preserve audit evidence.
2. Migration failure: halt deployment and restore from tested backup/forward fix path.
3. Dead-letter growth: inspect connector health, error class, idempotency, and replay authorization.
