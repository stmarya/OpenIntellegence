# Database Migration Playbook

## Invariants

- Exactly one Alembic head.
- Deployed revisions are immutable; repair by forward migration.
- ORM metadata, migrations, and runtime field usage must agree.
- Every tenant-owned table has a tenant isolation strategy and appropriate indexes.

## New migration checklist

1. Identify upgrade path from both a fresh database and the immediately previous deployed revision.
2. Add columns nullable or with safe server defaults before enforcing non-null where existing rows may exist.
3. Add foreign keys only after backfill/validation where necessary.
4. Add unique constraints/indexes needed for concurrency invariants.
5. Provide downgrade where it is safe; document irreversible data transformations.
6. Run `alembic heads`, `alembic current`, and `alembic upgrade head` against a disposable Postgres database.

## Prohibited shortcuts

- Editing `alembic_version` to skip a failure.
- Rewriting a released revision to make a local fresh install work.
- Adding runtime fields without migration support.
- Treating compile success as schema validation.

## Current integration rule

The schema-parity integration must reconcile baseline models with all domain models and form a single 0001→0007 lineage. Any corrective change for already-created baseline tables is forward-only.