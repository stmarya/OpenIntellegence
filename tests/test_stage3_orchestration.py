"""Deterministic tests for Stage 3: capability registry, outbox health,
dead-letter replay, and internal worker behaviour.

No live database, network, or LLM calls are made.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. Capability registry — secret omission
# ---------------------------------------------------------------------------


def test_capability_registry_does_not_expose_urls_or_tokens() -> None:
    """CapabilityOut must only carry action, handler_type, state, reason.
    No URL, token, SecretStr value, or credential may appear.
    """
    from pydantic import BaseModel

    from app.api.v1.orchestration import CapabilityOut

    cap = CapabilityOut(
        action="slack.notify",
        handler_type="connector",
        state="unconfigured",
        reason="Connector credentials are not configured.",
    )
    # CapabilityOut is a Pydantic model — ensure serialised form has no secret fields.
    data = cap.model_dump()
    assert set(data.keys()) == {"action", "handler_type", "state", "reason"}


@pytest.mark.asyncio
async def test_list_capabilities_unconfigured_connector() -> None:
    """When connector credentials are missing, the action state is 'unconfigured'."""
    from unittest.mock import AsyncMock

    from app.api.v1.orchestration import list_capabilities
    from app.core.config import Settings
    from app.core.deps import Principal

    settings = Settings(
        slack_webhook_url=None,
        jira_base_url=None,
        jira_email=None,
        jira_api_token=None,
        siem_webhook_url=None,
    )
    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"read"}),
        rate_limit_per_hour=1000,
    )

    caps = await list_capabilities(settings=settings, principal=principal)
    cap_map = {c.action: c for c in caps}

    assert cap_map["slack.notify"].state == "unconfigured"
    assert cap_map["jira.issue.create"].state == "unconfigured"
    assert cap_map["siem.push"].state == "unconfigured"


@pytest.mark.asyncio
async def test_list_capabilities_internal_actions_always_enabled() -> None:
    """Internal actions (case.create, report.generate) are always enabled."""
    from app.api.v1.orchestration import list_capabilities
    from app.core.config import Settings
    from app.core.deps import Principal

    settings = Settings()
    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"read"}),
        rate_limit_per_hour=1000,
    )

    caps = await list_capabilities(settings=settings, principal=principal)
    cap_map = {c.action: c for c in caps}

    assert cap_map["case.create"].state == "enabled"
    assert cap_map["case.create"].handler_type == "internal"
    assert cap_map["report.generate"].state == "enabled"
    assert cap_map["report.generate"].handler_type == "internal"


@pytest.mark.asyncio
async def test_list_capabilities_deferred_actions_are_unavailable() -> None:
    """Deferred actions must appear as unavailable — no worker handles them."""
    from app.api.v1.orchestration import list_capabilities
    from app.core.config import Settings
    from app.core.deps import Principal

    settings = Settings()
    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"read"}),
        rate_limit_per_hour=1000,
    )

    caps = await list_capabilities(settings=settings, principal=principal)
    cap_map = {c.action: c for c in caps}

    assert cap_map["endpoint.command.request"].state == "unavailable"
    assert cap_map["endpoint.command.request"].handler_type == "planned"


# ---------------------------------------------------------------------------
# 2. Unavailable-action rejection
# ---------------------------------------------------------------------------


def test_endpoint_command_request_is_still_deferred() -> None:
    """endpoint.command.request must remain in _DEFERRED_ACTIONS."""
    from app.api.v1.orchestration import _ALLOWED_ACTIONS, _DEFERRED_ACTIONS

    assert "endpoint.command.request" in _DEFERRED_ACTIONS
    assert "endpoint.command.request" not in _ALLOWED_ACTIONS


def test_case_create_and_report_generate_are_allowed() -> None:
    """Internal workers are registered — these actions must now be allowed."""
    from app.api.v1.orchestration import _ALLOWED_ACTIONS

    assert "case.create" in _ALLOWED_ACTIONS
    assert "report.generate" in _ALLOWED_ACTIONS


# ---------------------------------------------------------------------------
# 3. Dead-letter replay — locking, idempotency, audit
# ---------------------------------------------------------------------------


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_replay_rejects_non_dead_letter_state() -> None:
    """Replaying a record that is not in dead_letter state must raise 409."""
    from fastapi import HTTPException

    from app.api.v1.orchestration import replay_dead_letter
    from app.core.deps import Principal
    from app.db.orchestration_models import AutomationOutbox

    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="slack.notify",
        target="t",
        payload={},
        idempotency_key="idem-1",
        state="queued",
        attempts=1,
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(outbox)

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"write"}),
        rate_limit_per_hour=1000,
    )

    with pytest.raises(HTTPException) as exc_info:
        await replay_dead_letter("ob-1", db=_Db(), principal=principal)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_replay_rejects_endpoint_command_action() -> None:
    """endpoint.command.request must never be replayed."""
    from fastapi import HTTPException

    from app.api.v1.orchestration import replay_dead_letter
    from app.core.deps import Principal
    from app.db.orchestration_models import AutomationOutbox

    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="endpoint.command.request",
        target="t",
        payload={},
        idempotency_key="idem-1",
        state="dead_letter",
        attempts=5,
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(outbox)

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"write"}),
        rate_limit_per_hour=1000,
    )

    with pytest.raises(HTTPException) as exc_info:
        await replay_dead_letter("ob-1", db=_Db(), principal=principal)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_replay_generates_new_idempotency_key_and_history() -> None:
    """A successful replay must generate a new idempotency key and persist history."""
    from app.api.v1.orchestration import replay_dead_letter
    from app.core.deps import Principal
    from app.db.orchestration_models import AutomationOutbox, AutomationOutboxReplayHistory

    original_key = "original-idem-key"
    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="slack.notify",
        target="t",
        payload={},
        idempotency_key=original_key,
        state="dead_letter",
        attempts=5,
        created_at=datetime.now(UTC),
    )

    added: list = []

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(outbox)

        def add(self, obj):
            added.append(obj)

        async def flush(self): pass

        async def refresh(self, obj):
            if not hasattr(obj, "created_at") or obj.created_at is None:
                obj.created_at = datetime.now(UTC)

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"write"}),
        rate_limit_per_hour=1000,
    )

    await replay_dead_letter("ob-1", db=_Db(), principal=principal)  # type: ignore[arg-type]

    # State must be reset.
    assert outbox.state == "queued"
    assert outbox.attempts == 0
    assert outbox.last_error is None
    assert outbox.available_at is None
    assert outbox.lease_token is None
    assert outbox.lease_until is None

    # New idempotency key must differ from the original.
    assert outbox.idempotency_key != original_key
    assert "replay:" in outbox.idempotency_key

    # A history record must have been persisted.
    history_records = [x for x in added if isinstance(x, AutomationOutboxReplayHistory)]
    assert len(history_records) == 1
    hist = history_records[0]
    assert hist.original_idempotency_key == original_key
    assert hist.new_idempotency_key == outbox.idempotency_key
    assert hist.replayed_by == "api_key:key-1"


# ---------------------------------------------------------------------------
# 4. Internal worker — approval check, idempotency, lease cleanup, no-LLM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_generate_creates_queued_record_no_llm() -> None:
    """report.generate must create a QUEUED Report record with no LLM call."""
    from app.db.models import ReportStatus
    from app.db.orchestration_models import AutomationOutbox, AutomationRun
    from app.db.workflow_models import Case as CaseModel
    from app.workers.internal_workers import _handle_report_generate

    run = AutomationRun(
        id="run-1",
        tenant_id="tenant-1",
        playbook_id="pb-1",
        source_type="manual",
        source_id="src-1",
        idempotency_key="ik-1",
        state="dispatched",
        required_approvals=1,
        approvals=[],
        context={},
        requested_by="api_key:key-1",
    )
    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="report.generate",
        target="t",
        payload={
            "step_payload": {"title": "Threat Summary Report", "template": "threat_summary"},
            "run_context": {},
        },
        idempotency_key="idem-1",
        state="delivering",
        attempts=0,
    )

    added: list = []

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(run)

        def add(self, obj):
            added.append(obj)

        async def flush(self): pass

        async def refresh(self, obj):
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = "generated-id"

    result = await _handle_report_generate(outbox, _Db())  # type: ignore[arg-type]

    assert result.success is True
    assert "report_id" in result.result_detail  # type: ignore[index]
    assert result.result_detail["status"] == ReportStatus.QUEUED  # type: ignore[index]
    assert "no LLM" in result.result_detail["note"]  # type: ignore[index]

    # Verify Report record was added (not fabricated with content).
    from app.db.models import Report

    reports = [x for x in added if isinstance(x, Report)]
    assert len(reports) == 1
    assert reports[0].content_markdown is None
    assert reports[0].status == ReportStatus.QUEUED


@pytest.mark.asyncio
async def test_case_create_worker_links_to_investigation() -> None:
    """case.create must create a Case record with the supplied investigation_id."""
    from app.db.orchestration_models import AutomationOutbox, AutomationRun
    from app.db.workflow_models import Case as CaseModel
    from app.workers.internal_workers import _handle_case_create

    run = AutomationRun(
        id="run-1",
        tenant_id="tenant-1",
        playbook_id="pb-1",
        source_type="manual",
        source_id="src-1",
        idempotency_key="ik-1",
        state="dispatched",
        required_approvals=1,
        approvals=[],
        context={},
        requested_by="api_key:key-1",
    )
    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="case.create",
        target="t",
        payload={
            "step_payload": {
                "title": "Incident Case",
                "case_type": "incident",
                "investigation_id": "inv-42",
            },
            "run_context": {},
        },
        idempotency_key="idem-1",
        state="delivering",
        attempts=0,
    )

    added: list = []

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(run)

        def add(self, obj):
            added.append(obj)

        async def flush(self): pass

        async def refresh(self, obj):
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = "case-generated-id"

    result = await _handle_case_create(outbox, _Db())  # type: ignore[arg-type]

    assert result.success is True
    cases = [x for x in added if isinstance(x, CaseModel)]
    assert len(cases) == 1
    assert cases[0].tenant_id == "tenant-1"
    assert cases[0].investigation_id == "inv-42"
    assert cases[0].case_type == "incident"


@pytest.mark.asyncio
async def test_worker_rejects_unapproved_run() -> None:
    """Workers must re-check run state; runs not in 'dispatched' state are rejected."""
    from app.db.orchestration_models import AutomationOutbox, AutomationRun
    from app.workers.internal_workers import _handle_case_create

    run = AutomationRun(
        id="run-1",
        tenant_id="tenant-1",
        playbook_id="pb-1",
        source_type="manual",
        source_id="src-1",
        idempotency_key="ik-1",
        state="approved",  # NOT dispatched
        required_approvals=1,
        approvals=[],
        context={},
        requested_by="api_key:key-1",
    )
    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="case.create",
        target="t",
        payload={"step_payload": {}, "run_context": {}},
        idempotency_key="idem-1",
        state="delivering",
        attempts=0,
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(run)

        def add(self, obj): pass

        async def flush(self): pass

        async def refresh(self, obj): pass

    result = await _handle_case_create(outbox, _Db())  # type: ignore[arg-type]

    assert result.success is False
    assert not result.retryable


@pytest.mark.asyncio
async def test_internal_worker_clears_lease_on_success() -> None:
    """The internal worker must clear lease_token and lease_until on all paths."""
    from app.db.orchestration_models import AutomationOutbox, AutomationRun
    from app.workers.internal_workers import InternalWorker, WorkResult, _handle_case_create

    run = AutomationRun(
        id="run-1",
        tenant_id="tenant-1",
        playbook_id="pb-1",
        source_type="manual",
        source_id="src-1",
        idempotency_key="ik-1",
        state="dispatched",
        required_approvals=1,
        approvals=[],
        context={},
        requested_by="api_key:key-1",
    )
    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="case.create",
        target="t",
        payload={"step_payload": {"title": "T"}, "run_context": {}},
        idempotency_key="idem-1",
        state="delivering",
        attempts=0,
        lease_token="lease-abc",
        lease_until=datetime.now(UTC) + timedelta(minutes=5),
    )

    committed = []

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(run)

        def add(self, obj):
            pass

        async def flush(self): pass

        async def refresh(self, obj):
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = "new-id"

        async def commit(self):
            committed.append(True)

    worker = InternalWorker()
    await worker.process(_Db(), outbox)  # type: ignore[arg-type]

    assert outbox.lease_token is None
    assert outbox.lease_until is None
    assert outbox.state == "delivered"
    assert committed  # commit was called


@pytest.mark.asyncio
async def test_internal_worker_clears_lease_on_error() -> None:
    """The lease must be cleared even when the handler raises an exception."""
    from app.db.orchestration_models import AutomationOutbox, AutomationRun
    from app.workers.internal_workers import InternalWorker

    outbox = AutomationOutbox(
        id="ob-1",
        run_id="run-1",
        tenant_id="tenant-1",
        step_index=0,
        action="case.create",
        target="t",
        payload={"step_payload": {}, "run_context": {}},
        idempotency_key="idem-1",
        state="delivering",
        attempts=0,
        lease_token="lease-xyz",
        lease_until=datetime.now(UTC) + timedelta(minutes=5),
    )

    class _Db:
        async def execute(self, _stmt):
            raise RuntimeError("DB exploded")

        def add(self, obj): pass

        async def flush(self): pass

        async def refresh(self, obj): pass

        async def commit(self): pass

    worker = InternalWorker()
    await worker.process(_Db(), outbox)  # type: ignore[arg-type]

    assert outbox.lease_token is None
    assert outbox.lease_until is None
    # An unexpected error becomes retryable.
    assert outbox.state in {"retry", "dead_letter"}
