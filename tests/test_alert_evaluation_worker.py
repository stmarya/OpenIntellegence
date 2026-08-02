"""Deterministic unit tests for the alert evaluation worker.

All tests run without a live database or external services. The mock session
implements the minimum async interface required by the worker methods.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        return self._rows[0]


class _ExecResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _ScalarResult(self._rows)

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        return self._rows[0]


class _Session:
    def __init__(self, rows):
        self._rows = rows
        self.seen_sql: list[str] = []

    async def execute(self, stmt):  # noqa: ANN001
        self.seen_sql.append(str(stmt))
        return _ExecResult(self._rows)

    async def flush(self):
        return None

    def begin_nested(self):
        return _Nested()

    def add(self, _item):  # noqa: ANN001
        return None


class _Nested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _rule(trigger_type: str, condition: dict | None = None, cooldown_minutes: int = 30) -> AlertRule:
    return AlertRule(
        id="rule-1",
        tenant_id="tenant-1",
        name="rule",
        trigger_type=trigger_type,
        condition=condition or {},
        severity="high",
        enabled=True,
        cooldown_minutes=cooldown_minutes,
    )


# ---------------------------------------------------------------------------
# Core worker behaviour
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Race/IntegrityError fallback (same-bucket concurrent insert)
# ---------------------------------------------------------------------------


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

    async def _no_cooldown(*_args, **_kwargs):
        return None

    async def _lock(*_args, **_kwargs):
        return existing

    worker._find_cooldown_alert = _no_cooldown  # type: ignore[assignment]
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


# ---------------------------------------------------------------------------
# Cooldown aggregation across hourly bucket boundaries (regression)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cooldown_aggregates_across_bucket_boundary() -> None:
    """A candidate matching an alert still within cooldown_minutes must
    aggregate into the existing alert even when the current evaluation falls
    in a different hourly bucket than the original alert.
    """
    worker = AlertEvaluationWorker(SimpleNamespace())
    # Simulate: original alert created at 10:50 (bucket H1), cooldown 90 min.
    # New evaluation at 11:10 (bucket H2) – still within cooldown.
    t0 = datetime(2026, 1, 1, 10, 50, tzinfo=UTC)
    t1 = datetime(2026, 1, 1, 11, 10, tzinfo=UTC)  # different bucket, still in cooldown

    cooldown_alert = SimpleNamespace(
        id="alert-old",
        occurrences=1,
        last_triggered_at=t0,
        title="old title",
        summary="old summary",
        severity="high",
        entity_type="asset",
        entity_id="asset-1",
        risk_score=50,
        payload={"old": True},
    )

    # Simulate _find_cooldown_alert returning the existing alert (within 90min cooldown)
    async def _find_cooldown(*_args, **_kwargs):
        return cooldown_alert

    worker._find_cooldown_alert = _find_cooldown  # type: ignore[assignment]

    # _insert_alert should NOT be called
    insert_called = []

    async def _should_not_insert(*_args, **_kwargs):
        insert_called.append(True)
        return None

    worker._insert_alert = _should_not_insert  # type: ignore[assignment]

    candidate = Candidate(
        title="new title",
        summary="new summary",
        severity="high",
        entity_type="asset",
        entity_id="asset-1",
        risk_score=75,
        payload={"new": True},
    )
    rule = _rule("kev_exposure", cooldown_minutes=90)
    await worker._apply_candidate(_Session([]), rule, candidate, t1)

    assert not insert_called, "_insert_alert must not be called during active cooldown"
    assert cooldown_alert.occurrences == 2
    assert cooldown_alert.risk_score == 75
    assert cooldown_alert.title == "new title"
    assert cooldown_alert.last_triggered_at == t1


@pytest.mark.asyncio
async def test_cooldown_lookup_includes_rule_id_and_entity() -> None:
    """_find_cooldown_alert must filter on rule_id and entity identity
    to prevent cooldown aggregation bleeding across different rules or entities.
    """
    worker = AlertEvaluationWorker(SimpleNamespace())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    session = _Session([])
    rule = _rule("ioc_sighting", cooldown_minutes=60)
    candidate = Candidate(
        title="t",
        summary="s",
        severity="high",
        entity_type="ip",
        entity_id="1.2.3.4",
        risk_score=None,
        payload={},
    )
    await worker._find_cooldown_alert(session, rule, candidate, now)
    assert session.seen_sql, "cooldown lookup must issue a SQL statement"
    sql = session.seen_sql[-1]
    assert "alerts.rule_id" in sql
    assert "alerts.entity_id" in sql


# ---------------------------------------------------------------------------
# No automation dispatch hooks (portability: path derived from __file__)
# ---------------------------------------------------------------------------


def test_worker_has_no_automation_dispatch_hooks() -> None:
    """Verify the worker source contains no automation dispatch calls.

    Uses a project-relative path derived from __file__ so this test is
    portable across developer machines, CI containers, and cloned paths.
    """
    worker_path = Path(__file__).parent.parent / "app" / "workers" / "alert_evaluation.py"
    source = worker_path.read_text(encoding="utf-8")
    assert "dispatch_run" not in source
    assert "AutomationOutbox" not in source


def test_worker_source_path_is_portable() -> None:
    """The alert_evaluation module must be locatable relative to this test
    file without relying on any absolute /home/runner or similar path.
    """
    worker_path = Path(__file__).parent.parent / "app" / "workers" / "alert_evaluation.py"
    assert worker_path.exists(), (
        f"Worker not found at project-relative path {worker_path}. "
        "Ensure the path is derived from __file__, not a hard-coded absolute path."
    )
