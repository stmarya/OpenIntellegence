"""Process entrypoint for bounded alert-rule evaluation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.core.config import get_settings
from app.db.base import get_session_factory
from app.workers.alert_evaluation import AlertEvaluationWorker


async def run_once() -> int:
    """Evaluate enabled rules once and commit as a single bounded unit of work."""
    factory = get_session_factory()
    async with factory() as session:
        count = await AlertEvaluationWorker().evaluate(session, datetime.now(UTC))
        await session.commit()
        return count


async def main() -> None:
    """Run continuously; deployment owns process supervision and cadence."""
    settings = get_settings()
    interval = max(1, getattr(settings, "alert_evaluation_interval_seconds", 30))
    while True:
        await run_once()
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())
