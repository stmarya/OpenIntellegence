"""Regression tests for server-generated timestamp fields on write APIs."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.api.v1.alerting import AlertRuleCreate, create_rule
from app.api.v1.correlations import CorrelationEvaluate, generate_ai_brief
from app.api.v1.orchestration import (
    PlaybookCreate,
    PlaybookStep,
    RunCreate,
    create_playbook,
    dispatch_run,
    propose_run,
)
from app.core.deps import Principal
from app.db.alert_models import AlertRule
from app.db.correlation_models import Correlation, CorrelationAiBrief
from app.db.orchestration_models import AutomationOutbox, AutomationPlaybook, AutomationRun

FIXED_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _principal() -> Principal:
    return Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"admin"}),
        rate_limit_per_hour=1000,
    )


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _AlertDb:
    def __init__(self) -> None:
        self.refresh_calls = 0

    def add(self, _obj) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def refresh(self, obj) -> None:  # noqa: ANN001
        self.refresh_calls += 1
        if isinstance(obj, AlertRule):
            obj.id = "rule-1"
            obj.enabled = True
            obj.created_at = FIXED_TS


@pytest.mark.asyncio
async def test_create_rule_refreshes_created_at() -> None:
    db = _AlertDb()
    out = await create_rule(
        AlertRuleCreate(name="Rule A", trigger_type="custom", condition={}),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.created_at == FIXED_TS
    assert db.refresh_calls == 1


class _OrchDb:
    def __init__(self) -> None:
        self.refresh_calls = 0
        self._execute_results: list[object | None] = []
        self._playbook = AutomationPlaybook(
            id="playbook-1",
            tenant_id="tenant-1",
            name="PB",
            trigger_type="manual",
            steps=[{"action": "siem.push", "target": "secops", "payload": {}}],
            enabled=True,
        )

    def set_execute_results(self, *values: object | None) -> None:
        self._execute_results = list(values)

    def add(self, _obj) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def refresh(self, obj) -> None:  # noqa: ANN001
        self.refresh_calls += 1
        if isinstance(obj, AutomationPlaybook):
            obj.id = obj.id or "playbook-1"
            obj.enabled = True
            obj.created_at = FIXED_TS
        elif isinstance(obj, AutomationRun):
            obj.id = obj.id or "run-1"
            obj.state = obj.state or "proposed"
            obj.required_approvals = obj.required_approvals or 1
            obj.approvals = obj.approvals or []
            obj.context = obj.context or {}
            obj.requested_by = obj.requested_by or "api_key:key-1"
            obj.created_at = FIXED_TS
        elif isinstance(obj, AutomationOutbox):
            obj.id = obj.id or f"outbox-{obj.step_index}"
            obj.state = obj.state or "queued"
            obj.created_at = FIXED_TS

    async def execute(self, _stmt):  # noqa: ANN001
        value = self._execute_results.pop(0) if self._execute_results else None
        return _FakeScalarResult(value)

    async def get(self, model, _id):  # noqa: ANN001
        if model is AutomationPlaybook:
            return self._playbook
        return None


@pytest.mark.asyncio
async def test_orchestration_create_paths_refresh_timestamped_records() -> None:
    db = _OrchDb()
    principal = _principal()

    playbook = await create_playbook(
        PlaybookCreate(
            name="Playbook",
            trigger_type="manual",
            steps=[PlaybookStep(action="siem.push", target="secops", payload={})],
        ),
        db=db,  # type: ignore[arg-type]
        principal=principal,
    )
    assert playbook.created_at == FIXED_TS

    db.set_execute_results(None, db._playbook)
    run = await propose_run(
        RunCreate(
            playbook_id="playbook-1",
            source_type="correlation",
            source_id="corr-1",
            idempotency_key="idem-key-1",
            context={"k": "v"},
        ),
        db=db,  # type: ignore[arg-type]
        principal=principal,
    )
    assert run.created_at == FIXED_TS

    run_obj = AutomationRun(
        id="run-1",
        tenant_id=principal.tenant_id,
        playbook_id="playbook-1",
        source_type="correlation",
        source_id="corr-1",
        idempotency_key="idem-key-1",
        state="approved",
        required_approvals=1,
        approvals=[{"actor": "api_key:key-1"}],
        context={"k": "v"},
        requested_by="api_key:key-1",
    )
    db.set_execute_results(run_obj)
    outbox = await dispatch_run("run-1", db=db, principal=principal)  # type: ignore[arg-type]
    assert outbox and outbox[0].created_at == FIXED_TS


class _CorrelationDb:
    def __init__(self, correlation: Correlation) -> None:
        self._correlation = correlation

    def add(self, _obj) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def refresh(self, obj) -> None:  # noqa: ANN001
        if isinstance(obj, CorrelationAiBrief):
            obj.id = "brief-1"
            obj.created_at = FIXED_TS

    async def execute(self, _stmt):  # noqa: ANN001
        return _FakeScalarResult(self._correlation)


class _FakeCitation:
    def model_dump(self) -> dict:
        return {"entity_type": "doc", "entity_id": "1", "title": "x"}


class _FakeRagService:
    def __init__(self) -> None:
        self.client = self

    async def answer(self, _prompt: str, top_k: int = 12):  # noqa: ARG002
        return ("grounded answer", [_FakeCitation()])

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_generate_ai_brief_sets_generated_at() -> None:
    principal = _principal()
    correlation = Correlation(
        id="corr-1",
        tenant_id=principal.tenant_id,
        title="corr-title",
        primary_entity_type="asset",
        primary_entity_id="asset-1",
        evidence=CorrelationEvaluate(
            title="corr-title",
            primary_entity_type="asset",
            primary_entity_id="asset-1",
        ).model_dump(),
        factor_breakdown=[],
        risk_score=50,
        risk_tier="medium",
        automation_candidates=[],
        evaluated_at=FIXED_TS,
    )
    db = _CorrelationDb(correlation)

    from app.api.v1 import correlations as correlations_module

    original_rag = correlations_module._rag
    correlations_module._rag = lambda _db: _FakeRagService()  # type: ignore[assignment]
    try:
        out = await generate_ai_brief("corr-1", db=db, principal=principal)  # type: ignore[arg-type]
    finally:
        correlations_module._rag = original_rag  # type: ignore[assignment]

    assert out.generated_at is not None
