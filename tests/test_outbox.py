"""Outbox retry and dead-letter path tests.

These tests extend the existing connector delivery unit tests (test_connector_delivery.py)
to cover the state-machine transitions in DeliveryWorker.deliver:

- Successful delivery → "delivered"
- Retryable failure under max-attempts → "retry" with future available_at
- Non-retryable failure → "dead_letter" immediately
- Retryable failure at max-attempts → "dead_letter"
- Unknown action (no connector) → "dead_letter"

No network connections are made; connectors are replaced with stubs that
return the desired DeliveryReceipt.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.config import get_settings
from app.workers.connector_delivery import (
    DeliveryReceipt,
    DeliveryWorker,
    retry_delay,
)


def _make_item(
    *,
    action: str = "slack.notify",
    attempts: int = 0,
    state: str = "delivering",
) -> SimpleNamespace:
    """Return a minimal object that satisfies DeliveryWorker.deliver's needs."""
    return SimpleNamespace(
        action=action,
        attempts=attempts,
        state=state,
        delivered_at=None,
        delivery_result=None,
        last_error=None,
        available_at=None,
        lease_token="tok",
        lease_until=datetime.now(UTC) + timedelta(minutes=2),
    )


async def _run_deliver(item: SimpleNamespace, receipt: DeliveryReceipt) -> None:
    """Execute DeliveryWorker.deliver with a stub connector and mock session."""
    settings = get_settings()
    worker = DeliveryWorker(settings)

    # Replace the connector registry with a single stub
    stub = AsyncMock()
    stub.deliver.return_value = receipt
    worker.connectors = {item.action: stub}

    session = AsyncMock()
    session.commit = AsyncMock()
    await worker.deliver(session, item)
    session.commit.assert_awaited_once()


class TestSuccessfulDelivery:
    async def test_state_becomes_delivered(self) -> None:
        item = _make_item()
        await _run_deliver(item, DeliveryReceipt(True, remote_id="EXT-001"))
        assert item.state == "delivered"

    async def test_delivered_at_is_set(self) -> None:
        before = datetime.now(UTC)
        item = _make_item()
        await _run_deliver(item, DeliveryReceipt(True))
        assert item.delivered_at is not None
        assert item.delivered_at >= before

    async def test_last_error_is_cleared(self) -> None:
        item = _make_item()
        item.last_error = "previous transient error"
        await _run_deliver(item, DeliveryReceipt(True))
        assert item.last_error is None

    async def test_attempts_incremented(self) -> None:
        item = _make_item(attempts=2)
        await _run_deliver(item, DeliveryReceipt(True))
        assert item.attempts == 3


class TestRetryableFailure:
    async def test_state_becomes_retry_when_under_max_attempts(self) -> None:
        settings = get_settings()
        item = _make_item(attempts=0)
        await _run_deliver(item, DeliveryReceipt(False, retryable=True, error="503"))
        # Under connector_max_attempts (default 5), should retry
        if settings.connector_max_attempts > 1:
            assert item.state == "retry"

    async def test_available_at_is_in_the_future(self) -> None:
        settings = get_settings()
        now = datetime.now(UTC)
        item = _make_item(attempts=0)
        await _run_deliver(item, DeliveryReceipt(False, retryable=True, error="503"))
        if settings.connector_max_attempts > 1 and item.state == "retry":
            assert item.available_at is not None
            assert item.available_at > now

    async def test_last_error_recorded(self) -> None:
        settings = get_settings()
        item = _make_item(attempts=0)
        await _run_deliver(
            item, DeliveryReceipt(False, retryable=True, error="Service Unavailable")
        )
        if settings.connector_max_attempts > 1:
            assert item.last_error == "Service Unavailable"

    async def test_retryable_at_max_attempts_goes_to_dead_letter(self) -> None:
        settings = get_settings()
        # Exhaust the counter so the next failure cannot retry
        item = _make_item(attempts=settings.connector_max_attempts)
        await _run_deliver(
            item, DeliveryReceipt(False, retryable=True, error="still failing")
        )
        assert item.state == "dead_letter"


class TestNonRetryableFailure:
    async def test_state_becomes_dead_letter(self) -> None:
        item = _make_item(attempts=0)
        await _run_deliver(
            item, DeliveryReceipt(False, retryable=False, error="400 Bad Request")
        )
        assert item.state == "dead_letter"

    async def test_dead_letter_has_delivery_result(self) -> None:
        item = _make_item()
        await _run_deliver(
            item, DeliveryReceipt(False, retryable=False, error="Invalid payload")
        )
        assert item.delivery_result is not None
        assert "error" in item.delivery_result


class TestUnknownAction:
    async def test_unknown_connector_goes_to_dead_letter(self) -> None:
        settings = get_settings()
        worker = DeliveryWorker(settings)
        worker.connectors = {}  # no connectors at all

        item = _make_item(action="unknown.action")
        session = AsyncMock()
        session.commit = AsyncMock()
        await worker.deliver(session, item)

        assert item.state == "dead_letter"
        assert item.last_error is not None
        assert "unknown.action" in item.last_error

    async def test_lease_cleared_on_unknown_action(self) -> None:
        settings = get_settings()
        worker = DeliveryWorker(settings)
        worker.connectors = {}

        item = _make_item(action="ghost.connector")
        session = AsyncMock()
        await worker.deliver(session, item)

        assert item.lease_token is None
        assert item.lease_until is None


class TestRetryDelaySchedule:
    """Retry delay must grow exponentially and be bounded."""

    def test_first_retry_is_one_minute(self) -> None:
        assert retry_delay(1).total_seconds() == 60

    def test_second_retry_doubles(self) -> None:
        assert retry_delay(2).total_seconds() == 120

    def test_saturates_at_one_hour(self) -> None:
        assert retry_delay(99).total_seconds() == 3600

    def test_delay_is_non_decreasing(self) -> None:
        delays = [retry_delay(i).total_seconds() for i in range(1, 12)]
        for earlier, later in zip(delays, delays[1:]):
            assert later >= earlier
