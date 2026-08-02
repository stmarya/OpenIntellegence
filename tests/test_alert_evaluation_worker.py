from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.alert_models import AlertRule
from app.db.models import RunStatus
from app.workers.alert_evaluation import AlertEvaluationWorker, Candidate


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _ExecResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _ScalarResult(self._rows)

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _Session:
    def __init__(self, rows):
        self._rows = rows
        self.seen_sql: list[str] = []

    async def execute(self, stmt):  # noqa: ANN001
        self.seen_sql.append(str(stmt))
        return _ExecResult(self._rows)

    async def flush(self):
        return None


def _rule(trigger_type: str, condition: dict | None = None) -> AlertRule:
    return AlertRule(
        id="rule-1",
        tenant_id="tenant-1",
        name="rule",
        trigger_type=trigger_type,
        condition=condition or {},
        severity="high",
        enabled=True,
        cooldown_minutes=30,
    )


@pytest.mark.asyncio
async def test_custom_rules_are_explicitly_skipped() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    result = await worker._evaluate_rule(_Session([]), _rule("custom"), datetime.now(UTC))  # type: ignore[arg-type]
    assert result.candidates == 0
    assert "intentionally not executable" in (result.skipped_reason or "")


@pytest.mark.asyncio
async def test_ioc_matcher_is_bounded_and_tenant_scoped() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    sightings = [
        SimpleNamespace(
            id="s1",
            tenant_id="tenant-1",
            entity_type="ip",
            entity_id="1.1.1.1",
            observed_at=now,
            source="otx",
            context={},
        ),
        SimpleNamespace(
            id="s2",
            tenant_id="tenant-1",
            entity_type="ip",
            entity_id="1.1.1.1",
            observed_at=now,
            source="otx",
            context={},
        ),
    ]
    session = _Session(sightings)
    candidates = await worker._evaluate_ioc_sighting(
        session,
        _rule("ioc_sighting", {"max_results": 1, "min_count": 1}),
        now,
    )
    assert candidates
    assert candidates[0].payload["bounded_result"]["truncated"] is True
    assert any("sightings.tenant_id" in sql for sql in session.seen_sql)


@pytest.mark.asyncio
async def test_agent_stale_matcher_bounded() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    agents = [
        SimpleNamespace(id="a1", tenant_id="tenant-1", last_heartbeat_at=now),
        SimpleNamespace(id="a2", tenant_id="tenant-1", last_heartbeat_at=now),
    ]
    candidates = await worker._evaluate_agent_stale(
        _Session(agents),
        _rule("agent_stale", {"max_results": 1, "stale_minutes": 1}),
        now,
    )
    assert len(candidates) == 1
    assert candidates[0].payload["bounded_result"]["truncated"] is True


@pytest.mark.asyncio
async def test_kev_matcher_preserves_unknown_cvss() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        (
            SimpleNamespace(id="e1", detected_at=now),
            SimpleNamespace(
                id="v1",
                cve_id="CVE-1",
                cvss_score=None,
                exploit_maturity=SimpleNamespace(value="unknown"),
            ),
            SimpleNamespace(id="asset-1", hostname="host-1"),
        )
    ]
    candidates = await worker._evaluate_kev_exposure(_Session(rows), _rule("kev_exposure"), now)
    assert candidates[0].risk_score is None
    assert candidates[0].payload["matched_factors"][1]["value"] is None


@pytest.mark.asyncio
async def test_ransomware_matcher_uses_persisted_context() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    sightings = [
        SimpleNamespace(
            id="s1",
            entity_type="domain",
            entity_id="victim.example",
            source="feed",
            observed_at=now,
            context={"ransomware_relevant": True},
        )
    ]
    candidates = await worker._evaluate_ransomware_relevance(
        _Session(sightings), _rule("ransomware_relevance"), now
    )
    assert len(candidates) == 1
    assert candidates[0].payload["matched_factors"][0]["factor"] == "ransomware_relevant"


@pytest.mark.asyncio
async def test_feed_degraded_matcher_detects_failed_and_partial_runs() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    runs = [
        SimpleNamespace(id="r1", status=RunStatus.SUCCESS, started_at=now),
        SimpleNamespace(id="r2", status=RunStatus.FAILED, started_at=now),
    ]
    candidates = await worker._evaluate_feed_degraded(_Session(runs), _rule("feed_degraded"), now)
    assert len(candidates) == 1
    assert candidates[0].payload["matched_factors"][0]["value"] == 1


@pytest.mark.asyncio
async def test_race_fallback_updates_risk_score_and_occurrences() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    existing = SimpleNamespace(
        occurrences=1,
        last_triggered_at=now,
        title="old",
        summary="old",
        severity="low",
        entity_type=None,
        entity_id=None,
        risk_score=5,
        payload={},
    )

    async def _raise(*_args, **_kwargs):
        raise IntegrityError("insert", {}, Exception("race"))

    async def _lock(*_args, **_kwargs):
        return existing

    worker._insert_alert = _raise  # type: ignore[assignment]
    worker._lock_existing_alert = _lock  # type: ignore[assignment]
    candidate = Candidate(
        title="new",
        summary="new",
        severity="high",
        entity_type="asset",
        entity_id="a1",
        risk_score=99,
        payload={"k": "v"},
    )
    await worker._apply_candidate(_Session([]), _rule("kev_exposure"), candidate, now)
    assert existing.occurrences == 2
    assert existing.risk_score == 99


def test_worker_has_no_automation_dispatch_hooks() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "app" / "workers" / "alert_evaluation.py"
    ).read_text(encoding="utf-8")
    assert "dispatch_run" not in source
    assert "AutomationOutbox" not in source


@pytest.mark.asyncio
async def test_cooldown_aggregates_across_hour_bucket_boundaries() -> None:
    worker = AlertEvaluationWorker(SimpleNamespace())
    existing_time = datetime(2026, 1, 1, 12, 59, tzinfo=UTC)
    now = datetime(2026, 1, 1, 13, 0, tzinfo=UTC)
    existing = SimpleNamespace(
        occurrences=1,
        last_triggered_at=existing_time,
        title="old",
        summary="old",
        severity="low",
        entity_type="asset",
        entity_id="asset-1",
        risk_score=5,
        payload={},
    )

    async def _lock_recent(*_args, **_kwargs):
        return existing

    async def _insert(*_args, **_kwargs):
        raise AssertionError("insert should not be attempted within cooldown window")

    worker._lock_recent_cooldown_alert = _lock_recent  # type: ignore[assignment]
    worker._insert_alert = _insert  # type: ignore[assignment]
    candidate = Candidate(
        title="new",
        summary="new",
        severity="high",
        entity_type="asset",
        entity_id="asset-1",
        risk_score=99,
        payload={"k": "v"},
    )
    await worker._apply_candidate(_Session([]), _rule("kev_exposure"), candidate, now)
    assert existing.occurrences == 2
    assert existing.last_triggered_at == now
