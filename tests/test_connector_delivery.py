"""Fast unit checks for delivery safety primitives; no network required."""

from types import SimpleNamespace

import pytest

from app.workers import connector_delivery
from app.workers.connector_delivery import _adf, _retryable_status, retry_delay


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
async def test_siem_connector_sends_bearer_auth_header() -> None:
    captured: dict = {}
    token_value = "token-value"

    class _Response:
        status_code = 202

    class _Client:
        def __init__(self, **_kwargs):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def post(self, url, json, headers):  # noqa: ANN001
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return _Response()

    connector = connector_delivery.SiemWebhookConnector(
        url="https://siem.example.test/hook",
        token=token_value,
        timeout=3.0,
    )
    item = SimpleNamespace(
        action="siem.push",
        target="tenant-1",
        payload={"event": "value"},
        idempotency_key="run-1:0",
    )

    original_client = connector_delivery.httpx.AsyncClient
    connector_delivery.httpx.AsyncClient = _Client  # type: ignore[assignment]
    try:
        receipt = await connector.deliver(item)  # type: ignore[arg-type]
    finally:
        connector_delivery.httpx.AsyncClient = original_client  # type: ignore[assignment]

    assert receipt.delivered is True
    assert captured["headers"]["Idempotency-Key"] == "run-1:0"
    assert captured["headers"]["Authorization"].startswith("Bearer ")
    assert captured["headers"]["Authorization"].split(" ", 1)[1] == token_value
