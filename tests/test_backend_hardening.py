from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.db.models import OutboxState
from app.services.alerts import within_cooldown
from app.services.correlation import CorrelationScoringService, merge_resolved_and_caller_evidence
from app.services.outbox import (
    ensure_action_supported,
    ensure_replayable_state,
    normalize_outbox_counts,
)


def test_within_cooldown_respects_window() -> None:
    now = datetime.now(UTC)
    assert within_cooldown(
        last_triggered_at=now - timedelta(seconds=5), cooldown_seconds=10, now=now
    )
    assert not within_cooldown(
        last_triggered_at=now - timedelta(seconds=11), cooldown_seconds=10, now=now
    )
    assert not within_cooldown(last_triggered_at=None, cooldown_seconds=10, now=now)


def test_resolved_evidence_kept_and_caller_context_separate() -> None:
    resolved = {
        "vulnerability": {"is_kev": True, "cvss_score": None, "source": "vulnerabilities"},
        "tenant_exposure": {"open_asset_exposures": 3, "source": "asset_exposures"},
    }
    caller = {
        "vulnerability": {"is_kev": False, "cvss_score": 0.0},
        "note": "analyst hypothesis",
    }

    merged = merge_resolved_and_caller_evidence(resolved, caller)

    assert merged["vulnerability"]["is_kev"] is True
    assert merged["vulnerability"]["cvss_score"] is None
    assert merged["analyst_context"] == caller


def test_correlation_scoring_preserves_unknowns_without_zeroing() -> None:
    service = CorrelationScoringService()
    score = service.score(
        {
            "vulnerability": {"is_kev": None, "exploit_maturity": None},
            "tenant_exposure": {"open_asset_exposures": None},
            "ioc_sightings": {"count": None},
            "ransomware_relevance": {"recent_victim_count": None},
        }
    )
    assert score == 0


@pytest.mark.asyncio
async def test_unsupported_connector_action_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_capabilities(_settings):
        return [
            {
                "action": "ingest.run.nvd",
                "supported": True,
                "deliverable": True,
                "reason": None,
            }
        ]

    monkeypatch.setattr("app.services.outbox.connector_capabilities", fake_capabilities)

    with pytest.raises(HTTPException) as exc:
        await ensure_action_supported(
            db=SimpleNamespace(),
            settings=SimpleNamespace(),
            action="ingest.run.unknown",
        )

    assert exc.value.status_code == 422


def test_outbox_status_aggregation() -> None:
    counts = normalize_outbox_counts(
        [
            (OutboxState.QUEUED, 2),
            (OutboxState.DELIVERING, 1),
            (OutboxState.RETRY, 4),
            (OutboxState.DELIVERED, 7),
            (OutboxState.DEAD_LETTER, 3),
        ]
    )
    assert counts == {
        "queued": 2,
        "delivering": 1,
        "retry": 4,
        "delivered": 7,
        "dead_letter": 3,
    }


def test_dead_letter_replay_state_transitions_enforced() -> None:
    with pytest.raises(HTTPException):
        ensure_replayable_state(
            SimpleNamespace(state=OutboxState.DELIVERED, delivered_at=datetime.now(UTC))
        )

    with pytest.raises(HTTPException):
        ensure_replayable_state(SimpleNamespace(state=OutboxState.QUEUED, delivered_at=None))

    ensure_replayable_state(SimpleNamespace(state=OutboxState.DEAD_LETTER, delivered_at=None))
