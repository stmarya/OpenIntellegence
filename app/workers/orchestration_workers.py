"""Internal orchestration workers for ``case.create`` and ``report.generate``.

These workers consume ``AutomationOutbox`` items that have already been
approved and dispatched through the approval-first lifecycle.  They never
call external services or LLMs; every side-effect is a local database write.

Lifecycle (mirrors connector_delivery.py):
  queued / retry  →  claim (lease)  →  delivering  →  delivered
                                                    ↘  retry
                                                    ↘  dead_letter

Approval gate
-------------
An outbox item only exists because the parent ``AutomationRun`` was approved
and dispatched via the API.  The worker still re-checks that the run is in
the ``dispatched`` state before writing any records, so a race between
dispatch and the worker can never produce orphaned entities.

Idempotency
-----------
Each ``Case`` and ``Report`` row carries a ``source_outbox_id`` column that
is indexed with a unique constraint.  Before inserting a new row the worker
queries by ``source_outbox_id = item.idempotency_key``.  If a row already
exists from a previous (crashed) attempt, the worker returns the existing ID
and marks the outbox item as delivered — no duplicate is created.

Tenant isolation
----------------
``item.tenant_id`` is always copied into the created entity.  The worker
explicitly rejects items whose parent run belongs to a different tenant.

No external delivery
--------------------
``case.create`` writes a ``Case`` row.  ``report.generate`` writes a
``Report`` row in ``pending`` state.  Neither handler invokes HTTP, queues a
job, or calls a language model.  Report content is intentionally left
``None``; a separate pipeline is responsible for generation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.base import get_session_factory
from app.db.models import Report, ReportStatus
from app.db.orchestration_models import AutomationOutbox, AutomationRun
from app.db.workflow_models import Case

# ---------------------------------------------------------------------------
# Supported internal actions — these never require external credentials.
# ---------------------------------------------------------------------------

INTERNAL_ACTIONS: frozenset[str] = frozenset({"case.create", "report.generate"})


def internal_registry() -> dict[str, bool]:
    """Return capability map: action → always-enabled (True).

    Used by capability discovery endpoints to advertise which internal actions
    have a live handler without requiring any settings.
    """
    return {action: True for action in INTERNAL_ACTIONS}


# ---------------------------------------------------------------------------
# Receipt dataclass (internal analogue of DeliveryReceipt)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionReceipt:
    success: bool
    entity_id: str | None = None
    detail: dict | None = None
    retryable: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Retry back-off (same formula as connector_delivery)
# ---------------------------------------------------------------------------


def retry_delay(attempts: int) -> timedelta:
    return timedelta(seconds=min(3600, 30 * (2 ** min(attempts, 7))))


# ---------------------------------------------------------------------------
# Per-action handlers
# ---------------------------------------------------------------------------


async def _handle_case_create(
    session: AsyncSession,
    item: AutomationOutbox,
    run: AutomationRun,
) -> ActionReceipt:
    """Create a tenant-scoped case; return existing case ID on retry."""
    # Idempotency check — was a case already created by this outbox item?
    existing = (
        await session.execute(
            select(Case).where(Case.source_outbox_id == item.idempotency_key)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return ActionReceipt(
            True,
            entity_id=existing.id,
            detail={"idempotent": True, "case_id": existing.id},
        )

    step_payload: dict = item.payload.get("step_payload", {})
    run_context: dict = item.payload.get("run_context", {})

    # Link optional investigation/correlation context provided in the run.
    investigation_id: str | None = run_context.get("investigation_id") or step_payload.get(
        "investigation_id"
    )

    title: str = (
        step_payload.get("title")
        or run_context.get("summary")
        or f"Automated case — run {run.id[:8]}"
    )

    case = Case(
        id=str(uuid4()),
        tenant_id=item.tenant_id,
        investigation_id=investigation_id,
        title=title[:512],
        case_type=step_payload.get("case_type", "automated"),
        status="new",
        priority=step_payload.get("priority", "medium"),
        owner=step_payload.get("owner"),
        source_outbox_id=item.idempotency_key,
    )
    session.add(case)
    await session.flush()

    return ActionReceipt(
        True,
        entity_id=case.id,
        detail={
            "case_id": case.id,
            "title": case.title,
            "case_type": case.case_type,
            "investigation_id": investigation_id,
        },
    )


async def _handle_report_generate(
    session: AsyncSession,
    item: AutomationOutbox,
    run: AutomationRun,
) -> ActionReceipt:
    """Create a tenant-scoped report record in *pending* state; no LLM call.

    The record acts as a request token.  A separate generation pipeline
    (out of scope for this worker) picks up ``status='pending'`` rows and
    advances them to ``generated`` or ``failed``.  This worker never
    fabricates report content.
    """
    # Idempotency check
    existing = (
        await session.execute(
            select(Report).where(Report.source_outbox_id == item.idempotency_key)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return ActionReceipt(
            True,
            entity_id=existing.id,
            detail={"idempotent": True, "report_id": existing.id},
        )

    step_payload: dict = item.payload.get("step_payload", {})
    run_context: dict = item.payload.get("run_context", {})

    template: str = step_payload.get("template", "generic")
    title: str = (
        step_payload.get("title")
        or run_context.get("summary")
        or f"Automated report — run {run.id[:8]}"
    )

    # Provenance: capture the run context as citations so the origin is
    # traceable even before generation starts.
    provenance_citation: dict = {
        "source": "automation_run",
        "run_id": run.id,
        "playbook_id": run.playbook_id,
        "source_type": run.source_type,
        "source_id": run.source_id,
    }

    report = Report(
        id=str(uuid4()),
        tenant_id=item.tenant_id,
        template=template[:64],
        title=title[:512],
        # Distinct pending state: record created, generation not yet started.
        status=ReportStatus.PENDING,
        progress=0,
        content_markdown=None,  # Never fabricated
        citations=[provenance_citation],
        requested_by=f"automation_run:{run.id}",
        source_outbox_id=item.idempotency_key,
    )
    session.add(report)
    await session.flush()

    return ActionReceipt(
        True,
        entity_id=report.id,
        detail={
            "report_id": report.id,
            "template": report.template,
            "title": report.title,
            "status": report.status,
        },
    )


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class InternalActionWorker:
    """Processes ``case.create`` and ``report.generate`` outbox items.

    The worker only claims outbox items whose action is in INTERNAL_ACTIONS.
    Items with unsupported actions are moved to ``dead_letter`` immediately.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def claim(self, session: AsyncSession, limit: int = 20) -> list[AutomationOutbox]:
        now, token = datetime.now(UTC), token_urlsafe(24)
        pending = and_(
            AutomationOutbox.action.in_(list(INTERNAL_ACTIONS)),
            AutomationOutbox.state.in_(["queued", "retry"]),
            or_(AutomationOutbox.available_at.is_(None), AutomationOutbox.available_at <= now),
            or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
        )
        abandoned = and_(
            AutomationOutbox.action.in_(list(INTERNAL_ACTIONS)),
            AutomationOutbox.state == "delivering",
            AutomationOutbox.lease_until < now,
        )
        stmt = (
            select(AutomationOutbox)
            .where(or_(pending, abandoned))
            .order_by(AutomationOutbox.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        rows = (await session.execute(stmt)).scalars().all()
        for row in rows:
            row.state = "delivering"
            row.lease_token = token
            row.lease_until = now + timedelta(minutes=2)
        await session.commit()
        return rows

    async def process(self, session: AsyncSession, item: AutomationOutbox) -> None:
        """Run the approval gate, dispatch the action handler, and record receipt."""
        item.attempts += 1

        # --- Unsupported action (should not reach here, but guard anyway) ---
        if item.action not in INTERNAL_ACTIONS:
            item.state = "dead_letter"
            item.lease_token = None
            item.lease_until = None
            item.delivery_result = {"error": f"Unsupported action: {item.action!r}"}
            item.last_error = f"Unsupported action: {item.action!r}"
            await session.commit()
            return

        # --- Approval gate: verify the parent run is in dispatched state ---
        run: AutomationRun | None = await session.get(AutomationRun, item.run_id)
        if run is None:
            receipt = ActionReceipt(False, error="Parent AutomationRun not found.")
        elif run.tenant_id != item.tenant_id:
            # Tenant isolation: the run and outbox item must belong to the same tenant.
            receipt = ActionReceipt(
                False,
                error="Tenant isolation violation: run tenant does not match outbox tenant.",
            )
        elif run.state != "dispatched":
            # Items only enter the outbox after dispatch, but a concurrent state
            # change (e.g. manual admin rollback) could violate this.
            receipt = ActionReceipt(
                False,
                error=f"Approval gate: run is in state {run.state!r}, expected 'dispatched'.",
            )
        else:
            try:
                if item.action == "case.create":
                    receipt = await _handle_case_create(session, item, run)
                else:
                    receipt = await _handle_report_generate(session, item, run)
            except Exception as exc:
                receipt = ActionReceipt(False, retryable=True, error=f"Handler error: {exc}")

        # --- Update outbox item state ---
        item.lease_token = None
        item.lease_until = None

        if receipt.success:
            item.state = "delivered"
            item.delivered_at = datetime.now(UTC)
            item.delivery_result = {
                "entity_id": receipt.entity_id,
                "detail": receipt.detail or {},
            }
            item.last_error = None
        elif receipt.retryable and item.attempts < self.settings.connector_max_attempts:
            item.state = "retry"
            item.available_at = datetime.now(UTC) + retry_delay(item.attempts)
            item.last_error = receipt.error
        else:
            item.state = "dead_letter"
            item.delivery_result = {"error": receipt.error, "detail": receipt.detail or {}}
            item.last_error = receipt.error

        await session.commit()

    async def run_once(self) -> int:
        factory = get_session_factory()
        async with factory() as session:
            items = await self.claim(session)
            for item in items:
                await self.process(session, item)
            return len(items)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    worker = InternalActionWorker(get_settings())
    while True:
        count = await worker.run_once()
        await asyncio.sleep(1 if count else 5)


if __name__ == "__main__":
    asyncio.run(main())
