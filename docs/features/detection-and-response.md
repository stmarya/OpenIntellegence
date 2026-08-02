# Detection and Response

> **Status: unmerged feature work** — this document describes capabilities
> implemented in the `copilot/internal-orchestration-workers-case-create-report`
> branch and not yet merged to `main`.

## Overview

OpenIntelligence supports an approval-first detection-and-response workflow.
When a correlation or alert crosses a configurable risk threshold, an analyst
can propose an automation run, obtain the required approvals, and dispatch a
playbook that triggers internal actions — without any human writing a line of
code.

## Approval-first lifecycle

Every automation action passes through a mandatory approval gate before any
side-effect is produced.  The states in order are:

```
proposed → (partially_approved) → approved → dispatched
                ↘  rejected
```

Only a run in the `dispatched` state generates outbox items.  The internal
workers re-check this gate at processing time, so a late state change (e.g.
an admin rollback) is still caught.

## Internal action: `case.create`

When a dispatched run includes a `case.create` step the internal orchestration
worker:

1. Verifies the parent run is in `dispatched` state (approval gate).
2. Checks whether a `Case` row with `source_outbox_id = <idempotency_key>`
   already exists (idempotency / crash recovery).
3. Creates a tenant-scoped `Case` row linked to the investigation or
   correlation context supplied in the run context or step payload.
4. Persists a receipt containing the new `case_id` in
   `AutomationOutbox.delivery_result`.

The worker never creates a second case for the same outbox item, even if it is
reclaimed after a process crash.

### Context fields recognised in `step_payload`

| Field              | Description                                      |
|--------------------|--------------------------------------------------|
| `title`            | Case title (falls back to `run_context.summary`) |
| `case_type`        | Defaults to `"automated"`                        |
| `priority`         | Defaults to `"medium"`                           |
| `owner`            | Optional analyst assignment                      |
| `investigation_id` | Links the new case to an existing investigation  |

### Context fields recognised in `run_context`

| Field              | Description                                      |
|--------------------|--------------------------------------------------|
| `summary`          | Used as title fallback                           |
| `investigation_id` | Links the new case to an existing investigation  |

## Retry and dead-letter policy

Failed runs follow a bounded exponential back-off (30 s × 2ⁿ, max 1 h) up to
`connector_max_attempts` (default 5).  A run that fails all attempts, or fails
for a non-retryable reason (unapproved state, unknown action, tenant mismatch),
is moved to `dead_letter`.  No silent drops.

## Tenant isolation

All created entities inherit `tenant_id` from the outbox item.  The worker
explicitly rejects any item whose parent run belongs to a different tenant.
External delivery is never performed.
