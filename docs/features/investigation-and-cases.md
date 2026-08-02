# Investigation and Case Management

> **Status: unmerged feature work** — this document describes capabilities
> implemented in the `copilot/internal-orchestration-workers-case-create-report`
> branch and not yet merged to `main`.

## Data model

### Investigations

An `Investigation` represents an analyst-led inquiry into a threat hypothesis.
Key fields:

| Column            | Description                                          |
|-------------------|------------------------------------------------------|
| `id`              | UUID primary key                                     |
| `tenant_id`       | Owning tenant — all queries are scoped to this       |
| `title`           | Short human-readable title                           |
| `hypothesis`      | Free-text analytical hypothesis                      |
| `status`          | `open` / `closed`                                    |
| `priority`        | `low` / `medium` / `high` / `critical`               |
| `confidence`      | 0–100 analyst confidence score (nullable)            |
| `owner`           | Assigned analyst                                     |
| `opened_at`       | When the investigation was opened                    |
| `closed_at`       | When it was closed (null while open)                 |

### Cases

A `Case` is a structured work item derived from an investigation, a
correlation, or an automated playbook run.  Cases are the primary unit of
analyst work.

| Column             | Description                                         |
|--------------------|-----------------------------------------------------|
| `id`               | UUID primary key                                    |
| `tenant_id`        | Owning tenant                                       |
| `investigation_id` | Optional link to a parent `Investigation`           |
| `title`            | Case title                                          |
| `case_type`        | Classifies the work: `automated`, `manual`, etc.    |
| `status`           | `new` / `in_progress` / `resolved` / `closed`       |
| `priority`         | `low` / `medium` / `high` / `critical`              |
| `owner`            | Assigned analyst                                    |
| `sla_due_at`       | SLA deadline (nullable)                             |
| `source_outbox_id` | Idempotency key set by the worker; unique per case  |

## Automated case creation

The `case.create` internal action (see [Detection and Response](detection-and-response.md))
creates a `Case` row after an approved playbook run is dispatched.  The
`source_outbox_id` column ensures idempotent behavior: if the worker is
restarted after a crash it will find the existing case and return its ID
without creating a duplicate.

The `investigation_id` link is resolved from the run context at worker time,
so correlations and investigations can be connected without any API call from
the analyst interface.

## Case tasks and events

Each `Case` can have child `CaseTask` and `CaseEvent` rows.  Tasks are
structured work items; events are the audit trail (comments, status changes,
assignments).  These are created through the REST API rather than by the
automated worker.

## Schema migration

Migration `0008_orchestration_worker_source.py` adds the `source_outbox_id`
column (nullable `VARCHAR(320)`, unique, indexed) to both the `cases` and
`reports` tables.  Existing rows are unaffected.
