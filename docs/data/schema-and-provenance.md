# Data Contract, Schema & Provenance

## Schema source of truth

A production contract requires these layers to agree:

1. SQLAlchemy ORM models;
2. Alembic migrations;
3. API schemas and services;
4. database constraints and indexes.

A model field is not considered available until it is present in the migration path and guarded by tests. Migrations are forward-only for deployed environments; do not rewrite released history destructively.

## Identity and tenancy

- New CTI/workflow domains use UUID identity consistently.
- Tenant-owned records require `tenant_id` plus tenant-filtered reads and writes.
- Relationships and event payloads must never expose cross-tenant IDs.

## Provenance contract

Every normalized intelligence record should retain:

- source/provider and source record identifier;
- collected/observed/published timestamps when available;
- ingestion timestamp and normalization version;
- confidence and enrichment state;
- original/raw evidence reference where retention permits.

## Interpretation rules

- Unknown CVSS is `null`, never `0.0`.
- Unenriched IOC is not clean.
- Stale endpoint agents remain visible.
- Attribution may be multi-party, partial, or disputed.
- Deduplication merges operationally identical events without erasing source evidence.
