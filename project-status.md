# Project Status

This file tracks the status of backend roadmap items.  Items are listed in
the order they were implemented.

---

## Merged to `main`

| Item | Branch | Notes |
|------|--------|-------|
| Initial schema | — | Core ORM models, Alembic migrations 0001–0007 |
| Approval-first orchestration | `copilot/p0-backend-integration` | Playbooks, runs, approval/reject/dispatch endpoints, connector delivery worker |
| Connector delivery runtime | `copilot/p0-backend-integration` | Slack, Jira, SIEM webhook outbox workers with leases, receipts, and retry/dead-letter |

---

## Unmerged feature work

### Internal orchestration workers — `case.create` and `report.generate`

**Branch:** `copilot/internal-orchestration-workers-case-create-report`

**Status:** Implementation complete, deterministic tests passing, not yet
merged to `main`.

#### What was added

| File | Purpose |
|------|---------|
| `app/workers/orchestration_workers.py` | Internal action worker with approval gate, leasing, idempotency, receipts, and retry/dead-letter for `case.create` and `report.generate` |
| `alembic/versions/0008_orchestration_worker_source.py` | Adds `source_outbox_id` (unique, indexed) to `cases` and `reports` for idempotent retries |
| `app/db/workflow_models.py` | `source_outbox_id` field on `Case` |
| `app/db/models.py` | `source_outbox_id` field on `Report`; new `ReportStatus.PENDING` and `ReportStatus.GENERATED` states |
| `tests/test_orchestration_workers.py` | 34 deterministic unit tests covering approval gate, idempotency, tenant isolation, receipts, retry, and dead-letter |
| `docs/features/detection-and-response.md` | Feature documentation |
| `docs/features/investigation-and-cases.md` | Data model and case creation docs |
| `docs/features/ai-analyst.md` | Report generation pipeline and worker docs |

#### Guarantees

- `case.create` never duplicates a case on retry (idempotency via `source_outbox_id`).
- `report.generate` never fabricates content (`content_markdown = None`).
- Both actions require the parent run to be in `dispatched` state (approval gate re-check).
- All created entities are scoped to the outbox item's `tenant_id`.
- No external services, HTTP calls, or LLM invocations from the worker.
- Unsupported actions are dead-lettered, not silently dropped.

#### Not production-ready

This branch contains code and tests only.  It has not been:

- Load tested
- Reviewed by a security engineer
- Deployed to a staging environment
- Connected to a live LLM pipeline for report generation

Do not claim production readiness on the basis of this branch alone.
