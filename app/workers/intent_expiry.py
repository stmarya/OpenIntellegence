"""Deterministic expiry sweep for endpoint intents.

An intent whose approval window has closed must stop being actionable, and the
transition has to be recorded rather than merely inferred at read time.
Otherwise two operators reading the same ledger at different moments would see
different histories.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.endpoint_intent_models import EndpointIntent, EndpointIntentAudit

SWEEP_ACTOR = "system:intent_expiry"


def _elapsed(expires_at: datetime, now: datetime) -> bool:
    # SQLite returns naive datetimes; treat a stored naive value as UTC rather
    # than letting the comparison raise.
    reference = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=UTC)
    return reference <= now


async def sweep_expired_intents(session: AsyncSession, *, now: datetime | None = None) -> int:
    """Mark every elapsed pending intent as expired. Returns the count changed.

    Only pending rows are selected, so the sweep is idempotent and re-running it
    produces no further audit noise.
    """
    moment = now or datetime.now(UTC)
    rows = (
        await session.execute(select(EndpointIntent).where(EndpointIntent.state == "pending"))
    ).scalars().all()

    changed = 0
    for intent in rows:
        if not _elapsed(intent.expires_at, moment):
            continue
        intent.state = "expired"
        session.add(
            EndpointIntentAudit(
                intent_id=intent.id,
                actor=SWEEP_ACTOR,
                event_type="expired",
                detail={"reason": "approval_window_elapsed", "swept_at": moment.isoformat()},
                event_at=moment,
            )
        )
        changed += 1

    if changed:
        await session.flush()
    return changed
