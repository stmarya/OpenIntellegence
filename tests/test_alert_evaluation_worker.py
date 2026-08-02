"""Deterministic contracts for bounded, tenant-safe alert evaluation."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

from app.api.v1 import alerting
from app.services.alerting import alert_fingerprint
from app.workers.alert_evaluation import AlertCandidate, AlertEvaluationWorker, MAX_RULE_RESULTS, SUPPORTED_TRIGGERS


def test_all_supported_rules_are_explicit_and_bounded() -> None:
    assert SUPPORTED_TRIGGERS == {"ioc_sighting", "agent_stale", "kev_exposure", "ransomware_relevance", "feed_degraded"}
    assert MAX_RULE_RESULTS == 100


def test_cooldown_fingerprint_changes_hour_but_keeps_identity() -> None:
    before = alert_fingerprint("tenant-a", rule_id="rule-a", entity_type="asset", entity_id="asset-a", severity="high", bucket=datetime(2026, 8, 2, 22, 59, tzinfo=UTC))
    after = alert_fingerprint("tenant-a", rule_id="rule-a", entity_type="asset", entity_id="asset-a", severity="high", bucket=datetime(2026, 8, 2, 23, 0, tzinfo=UTC))
    assert before != after
    source = inspect.getsource(AlertEvaluationWorker._aggregate)
    assert "last_triggered_at >= cutoff" in source
    assert "with_for_update" in source
    assert "except IntegrityError" in source


def test_feed_health_payload_is_safe_global_summary_only() -> None:
    source = inspect.getsource(AlertEvaluationWorker._feed_health)
    assert "SourceRun.source" in source and "SourceRun.status" in source
    assert "SourceRun.id" not in source
    assert "SourceRun.started_at" not in source
    assert "SourceRun.finished_at" not in source
    assert "SourceRun.error_message" not in source


def test_alert_api_uses_shared_fingerprint_not_private_hashing() -> None:
    source = inspect.getsource(alerting)
    assert "from app.services.alerting import alert_fingerprint" in source
    assert "alert_fingerprint(principal.tenant_id" in source
    assert "hashlib" not in source
    assert "def _fingerprint" not in source


def test_candidate_payload_never_requires_raw_source_run_detail() -> None:
    candidate = AlertCandidate("Source degraded", "Safe summary", "high", "source_health", "otx", {"health_scope": "global", "source": "otx", "status": "failed"})
    assert set(candidate.payload) == {"health_scope", "source", "status"}
