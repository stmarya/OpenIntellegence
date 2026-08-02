"""Fast unit checks for delivery safety primitives; no network required."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.workers.connector_delivery import (
    DeliveryWorker,
    SiemWebhookConnector,
    _adf,
    _retryable_status,
    retry_delay,
)


def test_retry_delay_is_bounded_and_increasing() -> None:
    assert retry_delay(1).total_seconds() == 60
    assert retry_delay(2).total_seconds() == 120
    assert retry_delay(99).total_seconds() == 3600


def test_retry_policy_covers_transient_status_codes() -> None:
    assert _retryable_status(408)
    assert _retryable_status(429)
    assert _retryable_status(503)
    assert not _retryable_status(400)
    assert not _retryable_status(401)


def test_jira_description_is_atlassian_document_format() -> None:
    assert _adf("Evidence") == {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Evidence"}]}],
    }


@pytest.mark.asyncio
async def test_siem_connector_sends_configured_authorization_token(monkeypatch) -> None:
    sent_headers = {}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
            return False

        async def post(self, _url, json, headers):  # noqa: ANN001
            sent_headers.update(headers)
            assert json["action"] == "siem.push"
            return SimpleNamespace(status_code=202)

    monkeypatch.setattr("app.workers.connector_delivery.httpx.AsyncClient", lambda **_: _Client())
    connector = SiemWebhookConnector("https://siem.example/webhook", "Token real-secret", 5.0)
    item = SimpleNamespace(
        idempotency_key="run-1:0",
        action="siem.push",
        target="tenant-siem",
        payload={"step_payload": {"signal": "high"}},
    )

    receipt = await connector.deliver(item)  # type: ignore[arg-type]
    assert receipt.delivered is True
    assert sent_headers["Authorization"] == "Token real-secret"
    assert sent_headers["Authorization"] != "******"


@pytest.mark.asyncio
async def test_claim_query_reclaims_delivering_rows_with_null_lease_until() -> None:
    captured_sql = ""

    class _Result:
        def __init__(self, rows):
            self._rows = rows

        def scalars(self):
            return self

        def all(self):
            return self._rows

    class _Session:
        def __init__(self):
            self.rows = [
                SimpleNamespace(
                    state="queued",
                    lease_token=None,
                    lease_until=None,
                    created_at=datetime.now(UTC),
                )
            ]

        async def execute(self, stmt):
            nonlocal captured_sql
            captured_sql = str(stmt)
            return _Result(self.rows)

        async def commit(self):
            return None

    worker = DeliveryWorker(Settings())
    rows = await worker.claim(_Session(), limit=1)  # type: ignore[arg-type]
    assert len(rows) == 1
    assert "automation_outbox.state =" in captured_sql
    assert (
        "automation_outbox.lease_until IS NULL OR automation_outbox.lease_until <" in captured_sql
    )
