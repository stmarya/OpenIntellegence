"""Process entrypoint for the endpoint-intent expiry sweep.

Without a scheduled caller, ``sweep_expired_intents`` only ran if something
else happened to invoke it, which meant an intent whose approval window had
closed could sit in ``pending`` indefinitely and still read as actionable. The
expiry guarantee is only worth as much as the cadence that enforces it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.core.config import get_settings
from app.db.base import get_session_factory
from app.workers.intent_expiry import sweep_expired_intents


async def run_once() -> int:
    """Sweep elapsed pending intents once and commit as one bounded unit.

    The sweep selects only pending rows, so this is idempotent: a duplicate
    run caused by overlapping supervision produces no extra audit rows.
    """
    factory = get_session_factory()
    async with factory() as session:
        count = await sweep_expired_intents(session, now=datetime.now(UTC))
        await session.commit()
        return count


async def main() -> None:
    """Run continuously; deployment owns process supervision and cadence."""
    settings = get_settings()
    interval = max(1, getattr(settings, "intent_expiry_interval_seconds", 60))
    while True:
        await run_once()
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())
