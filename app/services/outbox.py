"""Connector action validation and outbox state helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models import OutboxMessage, OutboxReceipt, OutboxState
from app.ingest.base import build_http_client, registry


async def connector_capabilities(settings: Settings) -> list[dict]:
    """Tenant-safe connector action capabilities with delivery readiness."""
    client = build_http_client(settings)
    try:
        capabilities: list[dict] = []
        for name in registry.names():
            connector_cls = registry.get(name)
            connector = connector_cls(settings, client)
            action = f"ingest.run.{name}"
            capabilities.append(
                {
                    "action": action,
                    "connector": name,
                    "kind": connector_cls.kind,
                    "rate_limit_per_minute": connector_cls.rate_limit_per_minute,
                    "supported": True,
                    "deliverable": bool(connector.is_enabled),
                    "reason": None if connector.is_enabled else "connector_disabled",
                }
            )
        return capabilities
    finally:
        await client.aclose()


async def ensure_action_supported(db: AsyncSession, settings: Settings, action: str) -> dict:
    capabilities = await connector_capabilities(settings)
    by_action = {entry["action"]: entry for entry in capabilities}
    capability = by_action.get(action)
    if capability is None or not capability["supported"]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": "Unsupported connector action.",
                "action": action,
                "available": sorted(by_action),
            },
        )
    if not capability["deliverable"]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": (
                    "Connector action is supported but not deliverable by "
                    "server configuration."
                ),
                "action": action,
                "reason": capability.get("reason"),
            },
        )
    return capability


async def enqueue_outbox_message(
    db: AsyncSession,
    *,
    tenant_id: str,
    action: str,
    payload: dict,
    idempotency_key: str,
    approved_by: str,
) -> OutboxMessage:
    msg = OutboxMessage(
        tenant_id=tenant_id,
        action=action,
        payload=payload,
        idempotency_key=idempotency_key,
        state=OutboxState.QUEUED,
        approved_by=approved_by,
    )
    db.add(msg)
    await db.flush()

    db.add(
        OutboxReceipt(
            outbox_message_id=msg.id,
            tenant_id=tenant_id,
            event="queued",
            actor_id=approved_by,
            detail={"action": action},
        )
    )
    await db.flush()
    return msg


async def outbox_state_counts(db: AsyncSession, tenant_id: str) -> dict[str, int]:
    rows = (
        await db.execute(
            select(OutboxMessage.state, func.count(OutboxMessage.id))
            .where(OutboxMessage.tenant_id == tenant_id)
            .group_by(OutboxMessage.state)
        )
    ).all()

    return normalize_outbox_counts(rows)


def normalize_outbox_counts(rows: list[tuple[object, int]]) -> dict[str, int]:
    counts = {
        "queued": 0,
        "delivering": 0,
        "retry": 0,
        "delivered": 0,
        "dead_letter": 0,
    }
    for state_value, count in rows:
        state_name = state_value.value if hasattr(state_value, "value") else str(state_value)
        counts[state_name] = int(count)
    return counts


def ensure_replayable_state(message: OutboxMessage) -> None:
    if message.state == OutboxState.DELIVERED or message.delivered_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot replay an already delivered message.",
        )
    if message.state != OutboxState.DEAD_LETTER:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only dead-letter messages can be replayed (current state: {message.state.value}).",
        )


async def replay_dead_letter(
    db: AsyncSession,
    *,
    tenant_id: str,
    message_id: int,
    actor_id: str,
) -> OutboxMessage:
    message = (
        await db.execute(
            select(OutboxMessage).where(
                OutboxMessage.id == message_id,
                OutboxMessage.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if message is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dead-letter message not found.")

    ensure_replayable_state(message)

    replay = OutboxMessage(
        tenant_id=message.tenant_id,
        action=message.action,
        payload=message.payload,
        idempotency_key=message.idempotency_key,
        state=OutboxState.QUEUED,
        approved_by=actor_id,
        replayed_from_id=message.id,
    )
    db.add(replay)
    await db.flush()

    db.add(
        OutboxReceipt(
            outbox_message_id=replay.id,
            tenant_id=tenant_id,
            event="replayed",
            actor_id=actor_id,
            detail={"replayed_from_id": message.id},
        )
    )
    message.state = OutboxState.RETRY
    message.last_error = "replayed"
    await db.flush()

    return replay


def mark_delivered(message: OutboxMessage) -> None:
    message.state = OutboxState.DELIVERED
    message.delivered_at = datetime.now(UTC)
