"""P0 orchestration safety and approval semantics tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.api.v1.orchestration import (
    RunCreate,
    _allowed_actions,
    _unconfigured_actions,
    propose_run,
)
from app.core.deps import Principal
from app.db.orchestration_models import AutomationPlaybook, AutomationRun


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeDb:
    def __init__(self, playbook):
        self._results = [None, playbook]
        self.added = []

    async def execute(self, _stmt):  # noqa: ANN001
        return _ScalarResult(self._results.pop(0))

    def add(self, obj) -> None:  # noqa: ANN001
        self.added.append(obj)

    async def flush(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        if self.added:
            item = self.added[-1]
            if isinstance(item, AutomationRun):
                item.id = "run-1"
                item.state = item.state or "proposed"
                item.approvals = item.approvals or []
                item.created_at = now


def _principal() -> Principal:
    return Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"write"}),
        rate_limit_per_hour=1000,
    )


def test_p0_actions_are_limited_to_deliverable_connectors() -> None:
    assert _allowed_actions() == frozenset({"slack.notify", "jira.issue.create", "siem.push"})
    assert "endpoint.command.request" not in _allowed_actions()


def test_unconfigured_actions_are_detected_before_dispatch() -> None:
    steps = [
        {"action": "slack.notify", "target": "secops"},
        {"action": "siem.push", "target": "siem"},
    ]
    assert _unconfigured_actions(steps, frozenset({"slack.notify"})) == ["siem.push"]


def test_unconfigured_actions_handles_missing_action_key() -> None:
    """Steps without an 'action' key must not raise KeyError."""
    steps = [
        {"target": "secops"},  # no 'action' key
        {"action": "siem.push", "target": "siem"},
    ]
    assert _unconfigured_actions(steps, frozenset()) == ["siem.push"]


def test_unconfigured_actions_handles_non_string_action() -> None:
    """Steps with a non-string action value must be silently skipped."""
    steps = [
        {"action": 42, "target": "secops"},
        {"action": None, "target": "siem"},
        {"action": "slack.notify", "target": "secops"},
    ]
    assert _unconfigured_actions(steps, frozenset()) == ["slack.notify"]


def test_unconfigured_actions_handles_empty_string_action() -> None:
    """Steps with an empty string action must be silently skipped."""
    steps = [
        {"action": "", "target": "secops"},
        {"action": "siem.push", "target": "siem"},
    ]
    assert _unconfigured_actions(steps, frozenset()) == ["siem.push"]


def test_unconfigured_actions_all_malformed_returns_empty() -> None:
    """All-malformed steps produce an empty list, not a KeyError or 500."""
    steps = [
        {"target": "a"},
        {"action": None},
        {"action": ""},
        {"action": 123},
    ]
    assert _unconfigured_actions(steps, frozenset()) == []


def test_unconfigured_actions_result_is_deterministically_sorted() -> None:
    """Result must be sorted so dispatch error messages are stable."""
    steps = [
        {"action": "siem.push", "target": "siem"},
        {"action": "jira.issue.create", "target": "jira"},
        {"action": "slack.notify", "target": "slack"},
    ]
    result = _unconfigured_actions(steps, frozenset())
    assert result == sorted(result)


@pytest.mark.asyncio
async def test_required_approvals_is_one_for_supported_p0_run() -> None:
    playbook = AutomationPlaybook(
        id="playbook-1",
        tenant_id="tenant-1",
        name="Notify",
        trigger_type="manual",
        steps=[{"action": "slack.notify", "target": "secops", "payload": {}}],
    )
    db = _FakeDb(playbook)
    out = await propose_run(
        RunCreate(
            playbook_id="playbook-1",
            source_type="manual",
            source_id="src-1",
            idempotency_key="idem-12345",
            context={},
        ),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.required_approvals == 1
