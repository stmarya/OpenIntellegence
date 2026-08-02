"""Behavior contracts for withholding correlation AI briefs."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.api.v1 import correlations


class _Result:
    def __init__(self, item: object) -> None:
        self.item = item

    def scalar_one_or_none(self) -> object:
        return self.item


class _UnavailableBriefDb:
    def __init__(self, item: object) -> None:
        self.item = item
        self.added: list[object] = []

    async def execute(self, _statement: object) -> _Result:
        return _Result(self.item)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        return None

    async def refresh(self, _item: object) -> None:
        return None


@pytest.mark.asyncio
async def test_unavailable_evidence_persists_unverified_brief_without_rag(monkeypatch: pytest.MonkeyPatch) -> None:
    correlation = SimpleNamespace(id="correlation-1", evidence={"resolution_status": "unavailable"})
    db = _UnavailableBriefDb(correlation)
    principal = SimpleNamespace(tenant_id="tenant-1")

    def fail_if_rag_is_initialized(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("RAG must not be initialized for unavailable evidence")

    monkeypatch.setattr(correlations, "_rag", fail_if_rag_is_initialized)

    brief = await correlations.generate_ai_brief("correlation-1", db, principal)

    assert brief.status == "unverified"
    assert brief.citations == []
    assert "withheld" in brief.content
    assert len(db.added) == 1
    assert getattr(db.added[0], "citations") == []
