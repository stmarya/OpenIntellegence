"""Contracts for orchestration capability gating and worker ownership."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import HTTPException

from app.api.v1 import orchestration
from app.services.automation_capabilities import (
    CONNECTOR_ACTIONS,
    ENDPOINT_INTENT_ACTIONS,
    INTERNAL_ACTIONS,
    capabilities,
    validate_action,
)
from app.workers import connector_delivery


class _Secret:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


@dataclass
class _Settings:
    slack_webhook_url: object | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: object | None = None
    siem_webhook_url: object | None = None
    siem_webhook_token: object | None = None
    connector_delivery_timeout_seconds: float = 5.0
    connector_max_attempts: int = 5


def _slack_only() -> _Settings:
    return _Settings(slack_webhook_url=_Secret("https://example.invalid/hook"))


def test_unconfigured_connector_action_is_rejected() -> None:
    with pytest.raises(ValueError, match="action_not_configured"):
        validate_action("siem.push", _Settings())


def test_unknown_action_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported_action"):
        validate_action("shell.exec", _Settings())


def test_internal_actions_do_not_require_connector_configuration() -> None:
    for action in INTERNAL_ACTIONS:
        capability = validate_action(action, _Settings())
        assert capability.delivery_mode == "internal"


def test_capability_report_never_exposes_credentials() -> None:
    report = capabilities(_slack_only())
    serialized = str([capability.as_dict() for capability in report.values()])
    assert "https://example.invalid/hook" not in serialized


def test_endpoint_intent_steps_are_rejected_by_orchestration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orchestration, "get_settings", _slack_only)
    steps = [{"action": "endpoint.command.request", "target": "agent-1", "payload": {}}]
    with pytest.raises(HTTPException) as error:
        orchestration.validate_steps(steps)
    assert error.value.status_code == 422
    assert "control-plane" in str(error.value.detail)


def test_unconfigured_connector_steps_are_rejected_before_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orchestration, "get_settings", _slack_only)
    steps = [{"action": "siem.push", "target": "siem", "payload": {}}]
    with pytest.raises(HTTPException) as error:
        orchestration.validate_steps(steps)
    assert error.value.status_code == 422
    assert "not configured" in str(error.value.detail)


def test_configured_connector_and_internal_steps_are_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orchestration, "get_settings", _slack_only)
    steps = [
        {"action": "slack.notify", "target": "soc", "payload": {}},
        {"action": "case.create", "target": "internal", "payload": {}},
    ]
    orchestration.validate_steps(steps)


def test_worker_owns_only_configured_connector_actions() -> None:
    worker = connector_delivery.DeliveryWorker(_slack_only())
    owned = worker.owned_actions()
    assert owned == ["slack.notify"]
    assert set(owned) <= set(CONNECTOR_ACTIONS)
    assert not set(owned) & (set(INTERNAL_ACTIONS) | set(ENDPOINT_INTENT_ACTIONS))


@pytest.mark.asyncio
async def test_worker_claims_nothing_when_no_connector_is_configured() -> None:
    worker = connector_delivery.DeliveryWorker(_Settings())

    class _ForbiddenSession:
        async def execute(self, _statement: object) -> object:
            raise AssertionError("worker must not query the outbox without connectors")

    assert await worker.claim(_ForbiddenSession()) == []
