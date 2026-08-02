"""Deterministic unit tests for internal orchestration workers.

All tests use in-memory fakes; no database, network, or LLM calls are made.

Covered scenarios
-----------------
* Approval gate rejects unapproved / missing runs and the wrong tenant.
* ``case.create`` produces a Case with correct tenant, title, and provenance.
* ``report.generate`` produces a Report in ``pending`` state with provenance
  citations; no content is fabricated.
* Idempotency: a second call with an existing ``source_outbox_id`` returns the
  original entity ID and does not insert a duplicate.
* Retry/dead-letter transitions follow the bounded back-off schedule.
* ``internal_registry`` advertises both actions as enabled.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

# Import app.db.base first so ORM registration completes before any individual
# model module is imported — avoids a circular-import race in test collection.
import app.db.base  # noqa: F401
from app.db.models import Report, ReportStatus
from app.db.orchestration_models import AutomationOutbox, AutomationRun
from app.db.workflow_models import Case
from app.workers.orchestration_workers import (
    INTERNAL_ACTIONS,
    ActionReceipt,
    InternalActionWorker,
    _handle_case_create,
    _handle_report_generate,
    internal_registry,
    retry_delay,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TENANT_A = "tenant-aaaa-0000-0000-000000000001"
TENANT_B = "tenant-bbbb-0000-0000-000000000002"
RUN_ID = "run-0000-0000-0000-000000000001"
OUTBOX_ID = "outbox-000000000001"
IDEMPOTENCY_KEY = f"{RUN_ID}:0"


def _make_run(
    state: str = "dispatched",
    tenant_id: str = TENANT_A,
) -> AutomationRun:
    run = AutomationRun(
        id=RUN_ID,
        tenant_id=tenant_id,
        playbook_id="pb-0001",
        source_type="correlation",
        source_id="corr-0001",
        idempotency_key="idem-run-0001",
        state=state,
        required_approvals=1,
        approvals=[{"actor": "api_key:k1", "approved_at": "2026-01-01T00:00:00Z"}],
        context={},
        requested_by="api_key:k1",
        rejected_reason=None,
        dispatched_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return run


def _make_outbox(
    action: str = "case.create",
    tenant_id: str = TENANT_A,
    idempotency_key: str = IDEMPOTENCY_KEY,
    attempts: int = 0,
    state: str = "delivering",
    step_payload: dict | None = None,
    run_context: dict | None = None,
) -> AutomationOutbox:
    item = AutomationOutbox(
        id=OUTBOX_ID,
        tenant_id=tenant_id,
        run_id=RUN_ID,
        step_index=0,
        action=action,
        target="internal",
        payload={
            "step_payload": step_payload or {},
            "run_context": run_context or {},
        },
        idempotency_key=idempotency_key,
        state=state,
        delivery_result=None,
        delivered_at=None,
        attempts=attempts,
        last_error=None,
        available_at=None,
        lease_token="tok",
        lease_until=datetime(2099, 1, 1, tzinfo=UTC),
    )
    return item


def _make_existing_case(source_outbox_id: str = IDEMPOTENCY_KEY) -> Case:
    return Case(
        id="existing-case-id",
        tenant_id=TENANT_A,
        title="Existing case",
        case_type="automated",
        status="new",
        priority="medium",
        source_outbox_id=source_outbox_id,
    )


def _make_existing_report(source_outbox_id: str = IDEMPOTENCY_KEY) -> Report:
    return Report(
        id="existing-report-id",
        tenant_id="tenant-1",  # reports FK to tenants, use simple string
        template="generic",
        title="Existing report",
        status=ReportStatus.PENDING,
        source_outbox_id=source_outbox_id,
    )


class _FakeSession:
    """Minimal async-session fake for worker unit tests."""

    def __init__(
        self,
        get_result: Any = None,
        query_result: Any = None,
    ) -> None:
        self._get_result = get_result
        self._query_result = query_result
        self.added: list = []
        self.flushed = False
        self.committed = False

    async def get(self, model_class: type, pk: str) -> Any:  # noqa: ANN401
        return self._get_result

    async def execute(self, stmt: Any) -> Any:  # noqa: ANN401
        return _ScalarResult(self._query_result)

    def add(self, obj: Any) -> None:  # noqa: ANN401
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed = True

    async def commit(self) -> None:
        self.committed = True


class _ScalarResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value

    def scalars(self) -> "_ScalarList":
        return _ScalarList([self._value] if self._value is not None else [])


class _ScalarList:
    def __init__(self, values: list) -> None:
        self._values = values

    def all(self) -> list:
        return self._values


def _default_settings():
    """Minimal settings object for the worker."""
    from app.core.config import Settings

    return Settings.model_construct(connector_max_attempts=5)


# ---------------------------------------------------------------------------
# internal_registry
# ---------------------------------------------------------------------------


class TestInternalRegistry:
    def test_both_actions_are_enabled(self) -> None:
        reg = internal_registry()
        assert "case.create" in reg
        assert "report.generate" in reg

    def test_all_values_are_true(self) -> None:
        reg = internal_registry()
        assert all(reg.values()), "All internal actions must be marked enabled"

    def test_internal_actions_constant_matches_registry(self) -> None:
        assert set(internal_registry().keys()) == INTERNAL_ACTIONS


# ---------------------------------------------------------------------------
# retry_delay
# ---------------------------------------------------------------------------


class TestRetryDelay:
    def test_first_attempt_is_60_seconds(self) -> None:
        assert retry_delay(1).total_seconds() == 60

    def test_delay_is_bounded_at_one_hour(self) -> None:
        assert retry_delay(99).total_seconds() == 3600

    def test_delay_increases_with_attempts(self) -> None:
        assert retry_delay(2).total_seconds() > retry_delay(1).total_seconds()


# ---------------------------------------------------------------------------
# _handle_case_create
# ---------------------------------------------------------------------------


class TestHandleCaseCreate:
    @pytest.mark.asyncio
    async def test_creates_case_with_correct_tenant(self) -> None:
        session = _FakeSession(
            get_result=_make_run(),
            query_result=None,  # no existing case
        )
        item = _make_outbox("case.create", step_payload={"title": "Test Case"})
        run = _make_run()

        receipt = await _handle_case_create(session, item, run)

        assert receipt.success is True
        assert receipt.entity_id is not None
        assert len(session.added) == 1
        created_case = session.added[0]
        assert isinstance(created_case, Case)
        assert created_case.tenant_id == TENANT_A
        assert created_case.source_outbox_id == IDEMPOTENCY_KEY

    @pytest.mark.asyncio
    async def test_links_investigation_id_from_run_context(self) -> None:
        session = _FakeSession(query_result=None)
        run = _make_run()
        item = _make_outbox(
            "case.create",
            run_context={"investigation_id": "inv-0001", "summary": "Suspicious lateral movement"},
        )

        receipt = await _handle_case_create(session, item, run)

        assert receipt.success is True
        case = session.added[0]
        assert case.investigation_id == "inv-0001"

    @pytest.mark.asyncio
    async def test_links_investigation_id_from_step_payload(self) -> None:
        session = _FakeSession(query_result=None)
        run = _make_run()
        item = _make_outbox(
            "case.create",
            step_payload={"investigation_id": "inv-step-0001"},
        )

        receipt = await _handle_case_create(session, item, run)

        case = session.added[0]
        assert case.investigation_id == "inv-step-0001"

    @pytest.mark.asyncio
    async def test_title_falls_back_to_run_context_summary(self) -> None:
        session = _FakeSession(query_result=None)
        run = _make_run()
        item = _make_outbox(
            "case.create",
            run_context={"summary": "C2 beacon detected"},
        )

        receipt = await _handle_case_create(session, item, run)

        case = session.added[0]
        assert "C2 beacon detected" in case.title

    @pytest.mark.asyncio
    async def test_receipt_contains_case_id(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("case.create")
        run = _make_run()

        receipt = await _handle_case_create(session, item, run)

        assert receipt.detail is not None
        assert "case_id" in receipt.detail
        assert receipt.detail["case_id"] == receipt.entity_id

    @pytest.mark.asyncio
    async def test_idempotent_retry_returns_existing_case_no_insert(self) -> None:
        existing = _make_existing_case()
        session = _FakeSession(query_result=existing)
        item = _make_outbox("case.create")
        run = _make_run()

        receipt = await _handle_case_create(session, item, run)

        assert receipt.success is True
        assert receipt.entity_id == "existing-case-id"
        assert receipt.detail and receipt.detail.get("idempotent") is True
        # No new row added
        assert session.added == []


# ---------------------------------------------------------------------------
# _handle_report_generate
# ---------------------------------------------------------------------------


class TestHandleReportGenerate:
    @pytest.mark.asyncio
    async def test_creates_report_in_pending_state(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        receipt = await _handle_report_generate(session, item, run)

        assert receipt.success is True
        assert len(session.added) == 1
        report = session.added[0]
        assert isinstance(report, Report)
        assert report.status == ReportStatus.PENDING

    @pytest.mark.asyncio
    async def test_no_content_fabricated(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        await _handle_report_generate(session, item, run)

        report = session.added[0]
        assert report.content_markdown is None

    @pytest.mark.asyncio
    async def test_provenance_citation_stored(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        await _handle_report_generate(session, item, run)

        report = session.added[0]
        assert len(report.citations) == 1
        citation = report.citations[0]
        assert citation["source"] == "automation_run"
        assert citation["run_id"] == RUN_ID

    @pytest.mark.asyncio
    async def test_report_tenant_matches_outbox_tenant(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        await _handle_report_generate(session, item, run)

        report = session.added[0]
        assert report.tenant_id == TENANT_A

    @pytest.mark.asyncio
    async def test_receipt_contains_report_id(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        receipt = await _handle_report_generate(session, item, run)

        assert receipt.detail is not None
        assert "report_id" in receipt.detail
        assert receipt.detail["report_id"] == receipt.entity_id

    @pytest.mark.asyncio
    async def test_receipt_contains_pending_status(self) -> None:
        session = _FakeSession(query_result=None)
        item = _make_outbox("report.generate")
        run = _make_run()

        receipt = await _handle_report_generate(session, item, run)

        assert receipt.detail["status"] == ReportStatus.PENDING

    @pytest.mark.asyncio
    async def test_idempotent_retry_returns_existing_report_no_insert(self) -> None:
        existing = _make_existing_report()
        session = _FakeSession(query_result=existing)
        item = _make_outbox("report.generate")
        run = _make_run()

        receipt = await _handle_report_generate(session, item, run)

        assert receipt.success is True
        assert receipt.entity_id == "existing-report-id"
        assert receipt.detail and receipt.detail.get("idempotent") is True
        assert session.added == []


# ---------------------------------------------------------------------------
# InternalActionWorker.process — state machine
# ---------------------------------------------------------------------------


class _FakeSessionWithGet(_FakeSession):
    """Session that returns different results for get() vs execute()."""

    def __init__(self, get_result: Any = None, query_result: Any = None) -> None:
        super().__init__(get_result=get_result, query_result=query_result)

    async def get(self, model_class: type, pk: str) -> Any:  # noqa: ANN401
        return self._get_result


class TestInternalActionWorkerProcess:
    def _worker(self) -> InternalActionWorker:
        return InternalActionWorker(_default_settings())

    # --- Approval gate tests ---

    @pytest.mark.asyncio
    async def test_unsupported_action_is_dead_lettered(self) -> None:
        item = _make_outbox("endpoint.command.request")
        session = _FakeSessionWithGet(get_result=_make_run())
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"
        assert item.last_error and "Unsupported action" in item.last_error

    @pytest.mark.asyncio
    async def test_missing_run_is_dead_lettered(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(get_result=None)  # run not found
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"
        assert item.last_error and "not found" in item.last_error

    @pytest.mark.asyncio
    async def test_unapproved_run_is_dead_lettered(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(get_result=_make_run(state="approved"))
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"
        assert item.last_error and "Approval gate" in item.last_error

    @pytest.mark.asyncio
    async def test_proposed_run_is_dead_lettered(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(get_result=_make_run(state="proposed"))
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"

    # --- Tenant isolation ---

    @pytest.mark.asyncio
    async def test_cross_tenant_run_is_dead_lettered(self) -> None:
        item = _make_outbox("case.create", tenant_id=TENANT_A)
        # Run belongs to a different tenant
        session = _FakeSessionWithGet(get_result=_make_run(tenant_id=TENANT_B))
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"
        assert item.last_error and "isolation" in item.last_error.lower()

    @pytest.mark.asyncio
    async def test_created_entity_has_outbox_tenant(self) -> None:
        item = _make_outbox("case.create", tenant_id=TENANT_A)
        session = _FakeSessionWithGet(
            get_result=_make_run(tenant_id=TENANT_A),
            query_result=None,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "delivered"
        added_cases = [o for o in session.added if isinstance(o, Case)]
        assert len(added_cases) == 1
        assert added_cases[0].tenant_id == TENANT_A

    # --- Successful case.create receipt ---

    @pytest.mark.asyncio
    async def test_case_create_sets_delivered_state_and_receipt(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=None,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "delivered"
        assert item.delivered_at is not None
        assert item.delivery_result is not None
        assert "entity_id" in item.delivery_result
        assert "case_id" in item.delivery_result["detail"]

    # --- Successful report.generate receipt ---

    @pytest.mark.asyncio
    async def test_report_generate_sets_delivered_state_and_receipt(self) -> None:
        item = _make_outbox("report.generate")
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=None,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "delivered"
        assert item.delivery_result is not None
        assert "entity_id" in item.delivery_result
        assert "report_id" in item.delivery_result["detail"]

    @pytest.mark.asyncio
    async def test_report_generate_receipt_shows_pending_status(self) -> None:
        item = _make_outbox("report.generate")
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=None,
        )
        worker = self._worker()

        await worker.process(session, item)

        detail = item.delivery_result["detail"]
        assert detail["status"] == ReportStatus.PENDING

    # --- Idempotency / retry ---

    @pytest.mark.asyncio
    async def test_case_create_idempotent_on_retry(self) -> None:
        existing = _make_existing_case()
        item = _make_outbox("case.create", attempts=1)
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=existing,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "delivered"
        assert item.delivery_result["entity_id"] == "existing-case-id"
        # No duplicate row inserted
        assert not any(isinstance(o, Case) for o in session.added)

    @pytest.mark.asyncio
    async def test_report_generate_idempotent_on_retry(self) -> None:
        existing = _make_existing_report()
        item = _make_outbox("report.generate", attempts=1)
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=existing,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "delivered"
        assert item.delivery_result["entity_id"] == "existing-report-id"
        assert not any(isinstance(o, Report) for o in session.added)

    # --- Dead-letter after max attempts ---

    @pytest.mark.asyncio
    async def test_dead_letters_after_max_attempts_on_unapproved_run(self) -> None:
        # Non-retryable failure: unapproved run is always dead-lettered regardless of attempts.
        item = _make_outbox("case.create", attempts=4)
        session = _FakeSessionWithGet(get_result=_make_run(state="proposed"))
        worker = self._worker()

        await worker.process(session, item)

        assert item.state == "dead_letter"

    # --- Lease is always cleared ---

    @pytest.mark.asyncio
    async def test_lease_cleared_on_success(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(
            get_result=_make_run(),
            query_result=None,
        )
        worker = self._worker()

        await worker.process(session, item)

        assert item.lease_token is None
        assert item.lease_until is None

    @pytest.mark.asyncio
    async def test_lease_cleared_on_dead_letter(self) -> None:
        item = _make_outbox("case.create")
        session = _FakeSessionWithGet(get_result=None)  # run not found → dead_letter
        worker = self._worker()

        await worker.process(session, item)

        assert item.lease_token is None
        assert item.lease_until is None

    # --- Attempts counter ---

    @pytest.mark.asyncio
    async def test_attempts_incremented_on_each_process_call(self) -> None:
        item = _make_outbox("case.create", attempts=0)
        session = _FakeSessionWithGet(get_result=None)  # run not found → dead_letter
        worker = self._worker()

        await worker.process(session, item)

        assert item.attempts == 1
