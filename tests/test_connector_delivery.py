"""Fast unit checks for delivery safety primitives; no network required."""

from app.workers.connector_delivery import _adf, _retryable_status, retry_delay


def test_retry_delay_is_bounded_and_increasing() -> None:
    assert retry_delay(1).total_seconds() == 60
    assert retry_delay(2).total_seconds() == 120
    assert retry_delay(99).total_seconds() == 3600


def test_retry_policy_covers_rate_limit_and_transient_gateway_errors() -> None:
    assert _retryable_status(408)
    assert _retryable_status(429)
    assert _retryable_status(503)
    assert not _retryable_status(400)
    assert not _retryable_status(401)


def test_jira_description_is_atlassian_document_format() -> None:
    assert _adf("Evidence") == {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Evidence"}]}]}
