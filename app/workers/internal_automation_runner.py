"""Lease-safe process entrypoint for internal automation actions."""
from __future__ import annotations
import asyncio
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from sqlalchemy import or_, select
from app.core.config import get_settings
from app.db.base import get_session_factory
from app.db.orchestration_models import AutomationOutbox
from app.workers.internal_automation import INTERNAL_ACTIONS, InternalAutomationWorker

async def run_once(limit: int = 20) -> int:
    factory = get_session_factory()
    now = datetime.now(UTC)
    async with factory() as session:
        rows = (await session.execute(
            select(AutomationOutbox).where(
                AutomationOutbox.action.in_(INTERNAL_ACTIONS),
                AutomationOutbox.state.in_({"queued", "retry"}),
                or_(AutomationOutbox.available_at.is_(None), AutomationOutbox.available_at <= now),
                or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
            ).order_by(AutomationOutbox.created_at).limit(limit).with_for_update(skip_locked=True)
        )).scalars().all()
        token = token_urlsafe(24)
        for item in rows:
            item.state = "delivering"
            item.lease_token = token
            item.lease_until = now + timedelta(minutes=2)
        await session.flush()
        worker = InternalAutomationWorker()
        for item in rows:
            await worker.process(session, item)
        await session.commit()
        return len(rows)

async def main() -> None:
    interval = get_settings().internal_automation_interval_seconds
    while True:
        count = await run_once()
        await asyncio.sleep(1 if count else interval)

if __name__ == "__main__":
    asyncio.run(main())
