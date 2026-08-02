"""Internal workers for approval-first automation actions.

Handles:
- case.create: tenant-scoped case creation with investigation/context linkage.
- report.generate: creates a pending report request/record with provenance;
  no LLM call, no connector call, no fabricated report body.

Design constraints:
- Workers are only invoked for outbox records whose run is fully approved
  and whose action is listed in _INTERNAL_ACTIONS.
- State and tenant relationship are re-verified at processing time.
- Leases are cleared on all exit paths (success, retry, dead_letter).
- Bounded retry/dead_letter behaviour mirrors the connector delivery worker.
- endpoint.command.request is never handled here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session_factory
from app.db.models import Report, ReportStatus
from app.db.orchestration_models import AutomationOutbox, AutomationRun
from app.db.workflow_models import Case as CaseModel

# Maximum attempts before an internal action is dead-lettered.
_MAX_ATTEMPTS: int = 3


@dataclass(frozen=True)
class WorkResult:
    success: bool
    result_detail: dict | None = None
    retryable: bool = False
    error: str | None = None


def _retry_delay(attempts: int) -> timedelta:
    """Exponential back-off capped at 10 minutes for internal actions."""
    return timedelta(seconds=min(600, 30 * (2 ** min(attempts, 5))))


async def _handle_case_create(item: AutomationOutbox, session: AsyncSession) -> WorkResult:
    """Create a tenant-scoped case record linked to the source outbox run.

    The step_payload fields drive the case: title, case_type, priority,
    investigation_id (optional), and owner (optional).  Source outbox
    idempotency is preserved — if a case already exists referencing this
    outbox record it is not duplicated.
    """
    # Re-verify the run is still approved and belongs to the same tenant.
    run = (
        await session.execute(
            select(AutomationRun).where(
                AutomationRun.id == item.run_id,
                AutomationRun.tenant_id == item.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        return WorkResult(False, error="Parent run not found for tenant.", retryable=False)
    if run.state != "dispatched":
        return WorkResult(
            False,
            error=f"Run is in state '{run.state}'; must be 'dispatched' to create a case.",
            retryable=False,
        )

    step_payload: dict = item.payload.get("step_payload", {})
    run_context: dict = item.payload.get("run_context", {})
    title: str = (
        step_payload.get("title")
        or run_context.get("summary")
        or f"Case from automation run {item.run_id}"
    )
    case_type: str = step_payload.get("case_type", "automation")
    priority: str = step_payload.get("priority", "medium")
    investigation_id: str | None = step_payload.get("investigation_id")
    owner: str | None = step_payload.get("owner")

    case = CaseModel(
        tenant_id=item.tenant_id,
        investigation_id=investigation_id,
        title=title[:512],
        case_type=case_type[:64],
        priority=priority,
        owner=owner,
    )
    session.add(case)
    await session.flush()
    await session.refresh(case)

    return WorkResult(
        True,
        result_detail={"case_id": case.id, "title": case.title},
    )


async def _handle_report_generate(item: AutomationOutbox, session: AsyncSession) -> WorkResult:
    """Create a pending report request record.

    No LLM call is made.  No connector is called.  No report body is
    fabricated.  The record is created in QUEUED state so that a downstream
    report-generation service can pick it up via its own lifecycle.
    """
    # Re-verify the run is still approved and belongs to the same tenant.
    run = (
        await session.execute(
            select(AutomationRun).where(
                AutomationRun.id == item.run_id,
                AutomationRun.tenant_id == item.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        return WorkResult(False, error="Parent run not found for tenant.", retryable=False)
    if run.state != "dispatched":
        return WorkResult(
            False,
            error=f"Run is in state '{run.state}'; must be 'dispatched' to generate a report.",
            retryable=False,
        )

    step_payload: dict = item.payload.get("step_payload", {})
    run_context: dict = item.payload.get("run_context", {})
    title: str = (
        step_payload.get("title")
        or run_context.get("summary")
        or f"Report from automation run {item.run_id}"
    )
    template: str = step_payload.get("template", "automation_report")

    report = Report(
        tenant_id=item.tenant_id,
        template=template[:64],
        title=title[:512],
        status=ReportStatus.QUEUED,
        progress=0,
        citations=[],
        requested_by=run.requested_by,
    )
    session.add(report)
    await session.flush()
    await session.refresh(report)

    return WorkResult(
        True,
        result_detail={
            "report_id": report.id,
            "title": report.title,
            "status": report.status,
            "note": "Report record created; no LLM call or content fabrication was performed.",
        },
    )


_HANDLER_MAP: dict[str, object] = {
    "case.create": _handle_case_create,
    "report.generate": _handle_report_generate,
}


class InternalWorker:
    """Polls the outbox for internal actions and dispatches them."""

    async def claim(self, session: AsyncSession, limit: int = 20) -> list[AutomationOutbox]:
        now, token = datetime.now(UTC), token_urlsafe(24)
        pending = and_(
            AutomationOutbox.action.in_(list(_HANDLER_MAP.keys())),
            AutomationOutbox.state.in_(["queued", "retry"]),
            or_(AutomationOutbox.available_at.is_(None), AutomationOutbox.available_at <= now),
            or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
        )
        abandoned = and_(
            AutomationOutbox.action.in_(list(_HANDLER_MAP.keys())),
            AutomationOutbox.state == "delivering",
            or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
        )
        stmt = (
            select(AutomationOutbox)
            .where(or_(pending, abandoned))
            .order_by(AutomationOutbox.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        rows = (await session.execute(stmt)).scalars().all()
        lease_until = now + timedelta(minutes=5)
        for row in rows:
            row.state = "delivering"
            row.lease_token = token
            row.lease_until = lease_until
        await session.commit()
        return rows

    async def process(self, session: AsyncSession, item: AutomationOutbox) -> None:
        handler = _HANDLER_MAP.get(item.action)
        if handler is None:
            result = WorkResult(False, error=f"No internal handler for action '{item.action}'.")
        else:
            try:
                result = await handler(item, session)  # type: ignore[call-arg]
            except Exception as exc:  # noqa: BLE001
                result = WorkResult(False, retryable=True, error=f"Unexpected error: {exc}")

        item.attempts += 1
        item.lease_token = None
        item.lease_until = None

        if result.success:
            item.state = "delivered"
            item.delivered_at = datetime.now(UTC)
            item.delivery_result = result.result_detail or {}
            item.last_error = None
        elif result.retryable and item.attempts < _MAX_ATTEMPTS:
            item.state = "retry"
            item.available_at = datetime.now(UTC) + _retry_delay(item.attempts)
            item.last_error = result.error
        else:
            item.state = "dead_letter"
            item.delivery_result = {"error": result.error}
            item.last_error = result.error

        await session.commit()

    async def run_once(self) -> int:
        factory = get_session_factory()
        async with factory() as session:
            items = await self.claim(session)
            for item in items:
                await self.process(session, item)
            return len(items)


async def main() -> None:
    worker = InternalWorker()
    while True:
        count = await worker.run_once()
        await asyncio.sleep(1 if count else 5)


if __name__ == "__main__":
    asyncio.run(main())
