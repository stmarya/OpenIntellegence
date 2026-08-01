"""Fast unit checks for delivery safety primitives; no network required."""

from app.workers.connector_delivery import retry_delay


def test_retry_delay_is_bounded_and_increasing() -> None:
    assert retry_delay(1).total_seconds() == 60
    assert retry_delay(2).total_seconds() == 120
    assert retry_delay(99).total_seconds() == 3600


def test_retry_delay_never_exceeds_one_hour() -> None:
    assert retry_delay(7).total_seconds() == 3600
    assert retry_delay(8).total_seconds() == 3600
