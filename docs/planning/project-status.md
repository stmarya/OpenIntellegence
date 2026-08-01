# Project Status & Delivery Tracker

> **Purpose:** shared source of truth for the team. This document records what has been executed, what is in progress, what blocks readiness, and the exact sequence before development validation.
>
> **Update rule:** update this file in the same PR whenever a workstream changes state. Status is only `Done` after code is merged and required checks have passed; an open PR is `In review` or `In progress`, never `Done`.

## Current milestone

**Milestone:** Backend integration hardening  
**Objective:** turn independently-developed CTI backend vertical slices into one deployable, migration-safe, tenant-safe service.

| Gate | Status | Definition of done |
|---|---|---|
| Feature foundations | In progress | Existing foundation and domain PRs integrated into one backend |
| Schema contract | In progress | ORM, Alembic, database constraints, runtime services, and API agree |
| API assembly | In progress | Every supported v1 router is registered once and covered by contract tests |
| Migration safety | In progress | One Alembic head; fresh and upgrade paths work |
| Development validation | Not started | Static, unit, migration, container, and integration checks pass in dev |

## Delivered to `main`

| Delivery | Outcome | Evidence |
|---|---|---|
| Backend foundation | `/api/v1`, API keys/scopes, rate limiting, ingestion/normalization, assets, agent enrollment/heartbeat, exposure context, RAG chat, reports, Docker/Alembic baseline | Merged PR #1 |

## Implemented in open feature work

| Workstream | Scope | Status | Reference |
|---|---|---|---|
| API verification | CI and initial API route contract tests | In review / requires expansion | PR #2 |
| Intelligence Explorer | Search across vulnerabilities, indicators, actors, ransomware victims, assets | In review / integration pending | PR #3 |
| Entity details | Threat actor and IOC detail APIs | In review / integration pending | PR #4 |
| Campaign and malware | Domain models, list/detail APIs, attribution uncertainty | In review / integration pending | PR #5 |
| Investigation & cases | Investigations, evidence links, cases, tasks, append-only events | In review / integration pending | PR #6 |
| Alerts & sightings | Rule models, alert lifecycle, sightings | In review / integration pending | PR #7 |
| Correlation & AI | Deterministic risk scoring and cited AI briefs | In review / integration pending | PR #8 |
| Orchestration | Approval-first playbooks, runs, outbox | In review / integration pending | PR #9 |
| Connector runtime | Slack, Jira, SIEM delivery worker | In review / integration pending | PR #10 |

## Reliability and security fixes prepared

| Fix | Why it matters | Status | Reference |
|---|---|---|---|
| Outbox lease recovery and retry policy | Prevents abandoned delivery records after worker crash; handles transient failures | In review / depends on connector runtime | PR #11 |
| AI brief write authorization | Read-only API keys cannot create persistent/billable AI work | In review / depends on correlation | PR #12 |
| Alert deduplication concurrency | Concurrent identical alert events aggregate rather than return a unique-constraint error | In review / depends on alerting | PR #13 |

## Active integration backbone

| Workstream | Status | Scope | Reference |
|---|---|---|---|
| Schema parity, router consolidation, migration lineage | In progress | Canonical ORM/schema contract; unified `/api/v1` router; linear migration history; contract/lineage tests | PR #14 |
| Modular engineering handbook | In review | Architecture, planning, data, API, security, operations, and feature specifications | PR #18 |

## Known blockers — must close before development validation

1. **Schema parity:** baseline ORM and migration disagree on identity types and required operational fields. This can create runtime database failures despite successful import/compile.
2. **Router conflicts:** feature branches independently modify the v1 router; all supported routers must be consolidated into one registry.
3. **Migration lineage:** feature migrations need one forward-only linear chain with a single head.
4. **No completed dev validation yet:** do not state that CI, database migrations, or runtime tests passed until they execute in an environment with dependencies and services available.

## Next execution sequence

### Phase A — unblock integration

1. Complete and review PR #14.
2. Integrate feature routers and migrations in a deliberate sequence; do not blindly merge conflicting branches.
3. Apply the reliability fixes from PRs #11–#13 to their corresponding integrated domains.
4. Expand API contract coverage to every supported route family.

### Phase B — intelligence automation hardening

1. Implement an `AlertEvaluationWorker` for enabled rules, cooldown behavior, and source/asset/IOC signal evaluation.
2. Resolve correlation evidence server-side from assets, exposures, vulnerabilities, sightings, and CTI records.
3. Add deterministic tests for alert evaluation, scoring, tenant isolation, and approval transitions.

### Phase C — orchestration maturity

1. Add connector capability registry and health state.
2. Add delivery metrics and authorized dead-letter replay.
3. Implement internal workers for `case.create` and `report.generate`.
4. Design signed, policy-controlled, user/role-approved endpoint command execution.

### Phase D — development validation

```bash
pip install -e ".[dev]"
ruff check .
pytest
alembic upgrade head
docker compose up --build
```

Required validation areas: health/readiness, authentication/scopes, tenant isolation, ingestion, agent mTLS, RAG grounding/citations, case workflows, alerting, scoring, approvals, leases/retry/dead-letter, and mock connector delivery.

## Decision log

| Decision | Rationale |
|---|---|
| Backend first | A CTI UI is only trustworthy when provenance, tenant isolation, and workflow state are reliable underneath. |
| Provenance mandatory | Analysts must be able to trace a claim to source evidence and ingestion context. |
| Unknown is not safe | Unknown CVSS, unenriched IOC, stale endpoint, and disputed attribution must remain visible states. |
| Approval-first automation | High-impact connector and endpoint actions must not execute solely from AI or unreviewed signal output. |
| Forward-only migration safety | Deployed migration history must be extended safely, not destructively rewritten. |

## Team update template

Use this format in PR descriptions and weekly updates:

```text
Workstream:
Status: Not started | In progress | In review | Blocked | Done
Outcome delivered:
Scope changed:
Validation executed:
Known limitation / risk:
Next dependency:
Documentation updated:
```
