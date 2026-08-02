"""Regression tests for required workflow timestamps on create paths."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.api.v1.workflows import (
    CaseEventCreate,
    InvestigationCreate,
    add_event,
    create_investigation,
)
from app.core.deps import Principal
from app.db.workflow_models import CaseEvent, Investigation

FIXED_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeDbSession:
    def __init__(self) -> None:
        self.refresh_calls = 0

    def add(self, obj) -> None:  # noqa: ANN001
        self._last_added = obj

    async def flush(self) -> None:
        return None

    async def refresh(self, obj) -> None:  # noqa: ANN001
        self.refresh_calls += 1
        if isinstance(obj, Investigation):
            obj.id = "investigation-1"
            obj.status = obj.status or "open"
            obj.priority = obj.priority or "medium"
            obj.opened_at = FIXED_TS
            obj.created_at = FIXED_TS
        elif isinstance(obj, CaseEvent):
            obj.id = "event-1"
            obj.event_at = FIXED_TS

    async def execute(self, _stmt):  # noqa: ANN001
        return _FakeScalarResult("case-1")


def _principal() -> Principal:
    return Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"admin"}),
        rate_limit_per_hour=1000,
    )


@pytest.mark.asyncio
async def test_create_investigation_refreshes_and_returns_opened_at() -> None:
    db = _FakeDbSession()
    out = await create_investigation(
        InvestigationCreate(title="Investigate feed lag"),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.opened_at == FIXED_TS
    assert out.created_at == FIXED_TS
    assert db.refresh_calls == 1


@pytest.mark.asyncio
async def test_add_event_refreshes_and_returns_event_at() -> None:
    db = _FakeDbSession()
    out = await add_event(
        "case-1",
        CaseEventCreate(event_type="note", body="Initial note"),
        db=db,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert out.event_at == FIXED_TS
    assert db.refresh_calls == 1
