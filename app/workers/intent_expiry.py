"""Deterministic expiry sweeps for endpoint intents and agent commands."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.endpoint_intent_models import EndpointIntent, EndpointIntentAudit
from app.db.platform_models import AgentCommand

SWEEP_ACTOR = "system:intent_expiry"


def _elapsed(expires_at: datetime, now: datetime) -> bool:
    """Compare timezone-aware and SQLite-returned naive timestamps safely."""
    reference = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=UTC)
    return reference <= now


async def sweep_expired_intents(session: AsyncSession, *, now: datetime | None = None) -> int:
    """Persist elapsed approval and delivery states; return the number changed.

    Both queries select only actionable states, so repeated or overlapping sweeps
    do not create duplicate audit events or rewrite terminal command results.
    """
    moment = now or datetime.now(UTC)
    intents = (
        await session.execute(select(EndpointIntent).where(EndpointIntent.state == "pending"))
    ).scalars().all()
    commands = (
        await session.execute(select(AgentCommand).where(AgentCommand.state == "available"))
    ).scalars().all()

    changed = 0
    for intent in intents:
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

    for command in commands:
        if not _elapsed(command.expires_at, moment):
            continue
        command.state = "expired"
        command.result = {"reason": "delivery_window_elapsed"}
        intent = await session.get(EndpointIntent, command.intent_id)
        if intent is not None:
            intent.delivery_state = "expired"
            intent.delivery_result = command.result
        changed += 1

    if changed:
        await session.flush()
    return changed
