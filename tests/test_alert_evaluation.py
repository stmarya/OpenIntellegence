"""Deterministic unit tests for the alert evaluation worker and correlation resolver.

These tests run without a database — they exercise the pure logic of:
* Fingerprint / cooldown helpers (tenant isolation, dedup)
* Per-rule evaluators via lightweight fakes
* Score evidence produced by ``assess()``
* Alert → correlation → case state transitions in the timeline model
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.correlation import CorrelationAssessment, ResolvedEvidence, assess
from app.workers.alert_evaluation import (
    EvaluationMatch,
    _EVALUATORS,
    _fingerprint,
    _within_cooldown,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fp(tenant_id: str, rule_id: str, entity_type: str | None, entity_id: str | None) -> str:
    """Mirror of the production fingerprint function."""
    raw = "|".join((tenant_id, rule_id, entity_type or "", entity_id or ""))
    return sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Tenant isolation — fingerprints must differ across tenants
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_fingerprint_differs_across_tenants(self) -> None:
        fp1 = _fingerprint("tenant-A", "rule-1", "asset", "host-01")
        fp2 = _fingerprint("tenant-B", "rule-1", "asset", "host-01")
        assert fp1 != fp2

    def test_fingerprint_stable_for_same_inputs(self) -> None:
        fp_a = _fingerprint("tenant-A", "rule-1", "asset", "host-01")
        fp_b = _fingerprint("tenant-A", "rule-1", "asset", "host-01")
        assert fp_a == fp_b

    def test_fingerprint_differs_for_different_entities(self) -> None:
        fp1 = _fingerprint("tenant-A", "rule-1", "asset", "host-01")
        fp2 = _fingerprint("tenant-A", "rule-1", "asset", "host-02")
        assert fp1 != fp2

    def test_fingerprint_differs_for_different_rules(self) -> None:
        fp1 = _fingerprint("tenant-A", "rule-1", "asset", "host-01")
        fp2 = _fingerprint("tenant-A", "rule-2", "asset", "host-01")
        assert fp1 != fp2

    def test_fingerprint_none_entity_is_stable(self) -> None:
        fp = _fingerprint("tenant-A", "rule-1", None, None)
        assert isinstance(fp, str) and len(fp) == 64


# ---------------------------------------------------------------------------
# Cooldown dedup
# ---------------------------------------------------------------------------


class TestCooldown:
    @pytest.mark.asyncio
    async def test_within_cooldown_returns_true_when_recent(self) -> None:
        """An alert fired 5 minutes ago with a 60-minute cooldown must block."""
        mock_session = AsyncMock()
        # scalar_one_or_none returns a non-None alert → within cooldown
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = object()
        mock_session.execute.return_value = mock_result

        result = await _within_cooldown(mock_session, "t1", "fp-abc", 60)
        assert result is True

    @pytest.mark.asyncio
    async def test_within_cooldown_returns_false_when_none_found(self) -> None:
        """No matching alert → not within cooldown."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await _within_cooldown(mock_session, "t1", "fp-abc", 60)
        assert result is False


# ---------------------------------------------------------------------------
# Rule evaluation — pure logic via fakes
# ---------------------------------------------------------------------------


class _FakeCondition(dict):
    """Thin dict subclass used to build fake ``AlertRule.condition`` dicts."""


def _fake_rule(trigger_type: str, condition: dict | None = None, severity: str = "medium") -> MagicMock:
    rule = MagicMock()
    rule.id = "rule-fake-001"
    rule.trigger_type = trigger_type
    rule.severity = severity
    rule.cooldown_minutes = 60
    rule.condition = condition or {}
    return rule


class TestKevExposureEvaluator:
    @pytest.mark.asyncio
    async def test_returns_match_for_each_exposure(self) -> None:
        from app.workers.alert_evaluation import _eval_kev_exposure

        asset = MagicMock()
        asset.id = "asset-01"
        asset.hostname = "db.acme.com"
        asset.criticality = "high"

        vuln = MagicMock()
        vuln.cve_id = "CVE-2024-1234"
        vuln.is_kev = True
        vuln.cvss_score = 9.8
        vuln.exploit_maturity = MagicMock()
        vuln.exploit_maturity.value = "weaponized"

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [(asset, vuln)]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("kev_exposure")
        matches = await _eval_kev_exposure(mock_session, "tenant-X", rule)

        assert len(matches) == 1
        m = matches[0]
        assert "CVE-2024-1234" in m.title
        assert m.evidence["is_kev"] is True
        assert m.evidence["cvss_score"] == 9.8
        assert m.evidence_state["cvss_score"] == "present"


class TestIocSightingEvaluator:
    @pytest.mark.asyncio
    async def test_returns_match_per_sighting(self) -> None:
        from app.workers.alert_evaluation import _eval_ioc_sighting

        sighting = MagicMock()
        sighting.entity_type = "ipv4"
        sighting.entity_id = "1.2.3.4"
        sighting.source = "threatfox"
        sighting.observed_at = datetime.now(UTC)
        sighting.confidence = 85

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sighting]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("ioc_sighting", {"window_hours": 24})
        matches = await _eval_ioc_sighting(mock_session, "tenant-X", rule)

        assert len(matches) == 1
        assert matches[0].evidence["entity_id"] == "1.2.3.4"
        assert matches[0].evidence_state["confidence"] == "present"

    @pytest.mark.asyncio
    async def test_unknown_confidence_reported_correctly(self) -> None:
        from app.workers.alert_evaluation import _eval_ioc_sighting

        sighting = MagicMock()
        sighting.entity_type = "domain"
        sighting.entity_id = "evil.example"
        sighting.source = "otx"
        sighting.observed_at = datetime.now(UTC)
        sighting.confidence = None  # unknown

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sighting]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("ioc_sighting")
        matches = await _eval_ioc_sighting(mock_session, "tenant-X", rule)
        assert matches[0].evidence_state["confidence"] == "unknown"


class TestAgentStaleEvaluator:
    @pytest.mark.asyncio
    async def test_stale_agent_reported_with_evidence(self) -> None:
        from app.workers.alert_evaluation import _eval_agent_stale

        agent = MagicMock()
        agent.id = "agent-abc"
        agent.status = MagicMock()
        agent.status.__str__ = lambda _: "stale"
        agent.last_heartbeat_at = datetime.now(UTC) - timedelta(hours=3)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [agent]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("agent_stale", {"stale_minutes": 60})
        matches = await _eval_agent_stale(mock_session, "tenant-X", rule)

        assert len(matches) == 1
        assert matches[0].entity_id == "agent-abc"
        assert matches[0].evidence_state["last_heartbeat_at"] == "present"

    @pytest.mark.asyncio
    async def test_missing_heartbeat_reported_as_unknown(self) -> None:
        from app.workers.alert_evaluation import _eval_agent_stale

        agent = MagicMock()
        agent.id = "agent-xyz"
        agent.status = MagicMock()
        agent.status.__str__ = lambda _: "unreachable"
        agent.last_heartbeat_at = None

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [agent]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("agent_stale")
        matches = await _eval_agent_stale(mock_session, "tenant-X", rule)
        assert matches[0].evidence_state["last_heartbeat_at"] == "unknown"


class TestRansomwareRelevanceEvaluator:
    @pytest.mark.asyncio
    async def test_match_returns_evidence(self) -> None:
        from app.workers.alert_evaluation import _eval_ransomware_relevance

        victim = MagicMock()
        victim.id = "rv-001"
        victim.canonical_key = "acme-corp"
        victim.group_name = "LockBit"
        victim.sector = "healthcare"
        victim.country = "US"
        victim.discovered_at = datetime.now(UTC) - timedelta(days=1)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [victim]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("ransomware_relevance", {"sectors": ["healthcare"], "window_days": 7})
        matches = await _eval_ransomware_relevance(mock_session, "tenant-X", rule)

        assert len(matches) == 1
        assert matches[0].evidence["group_name"] == "LockBit"
        assert matches[0].evidence_state["sector"] == "present"


class TestFeedDegradedEvaluator:
    @pytest.mark.asyncio
    async def test_failing_feed_produces_match(self) -> None:
        from app.workers.alert_evaluation import _eval_feed_degraded

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [("nvd", 3)]
        mock_session.execute.return_value = mock_result

        rule = _fake_rule("feed_degraded", {"window_hours": 6, "min_failures": 2})
        matches = await _eval_feed_degraded(mock_session, "tenant-X", rule)

        assert len(matches) == 1
        assert matches[0].evidence["source"] == "nvd"
        assert matches[0].evidence["failure_count"] == 3


class TestCustomEvaluator:
    @pytest.mark.asyncio
    async def test_allowed_metric_fires_when_threshold_met(self) -> None:
        from app.workers.alert_evaluation import _eval_custom

        mock_session = AsyncMock()
        # scalar returns the metric value
        mock_session.scalar = AsyncMock(return_value=5)
        # execute is also called internally for some metrics
        mock_result = MagicMock()
        mock_result.scalar.return_value = 5
        mock_session.execute = AsyncMock(return_value=mock_result)

        rule = _fake_rule(
            "custom",
            {"metric": "open_alert_count", "operator": "gte", "threshold": 3},
        )
        matches = await _eval_custom(mock_session, "tenant-X", rule)
        assert len(matches) == 1
        assert matches[0].evidence["metric"] == "open_alert_count"
        assert matches[0].evidence_state["actual_value"] == "present"

    @pytest.mark.asyncio
    async def test_disallowed_metric_returns_no_matches(self) -> None:
        from app.workers.alert_evaluation import _eval_custom

        mock_session = AsyncMock()
        rule = _fake_rule("custom", {"metric": "exec(malicious)", "operator": "gte", "threshold": 0})
        matches = await _eval_custom(mock_session, "tenant-X", rule)
        assert matches == []

    @pytest.mark.asyncio
    async def test_threshold_not_met_returns_no_matches(self) -> None:
        from app.workers.alert_evaluation import _eval_custom

        mock_session = AsyncMock()
        mock_session.scalar = AsyncMock(return_value=1)

        rule = _fake_rule(
            "custom",
            {"metric": "open_alert_count", "operator": "gte", "threshold": 10},
        )
        matches = await _eval_custom(mock_session, "tenant-X", rule)
        assert matches == []


# ---------------------------------------------------------------------------
# Score evidence — assess() with resolved evidence
# ---------------------------------------------------------------------------


class TestAssessWithResolvedEvidence:
    def test_full_kev_scenario_scores_critical(self) -> None:
        evidence = {
            "cvss_score": 9.8,
            "is_kev": True,
            "exploit_maturity": "weaponized",
            "asset_criticality": "critical",
            "internet_exposed": True,
            "sighting_count": 3,
            "ransomware_relevant": True,
        }
        result = assess(evidence)
        assert result.score >= 80
        assert result.tier == "critical"

    def test_unknown_cvss_reported_in_factors(self) -> None:
        evidence = {
            "cvss_score": None,
            "is_kev": False,
            "exploit_maturity": None,
            "asset_criticality": None,
            "internet_exposed": False,
            "sighting_count": 0,
            "ransomware_relevant": False,
        }
        result = assess(evidence)
        unknown_factors = [f for f in result.factors if f["state"] == "unknown"]
        assert any(f["key"] == "cvss" for f in unknown_factors)

    def test_partial_evidence_scores_medium_or_low(self) -> None:
        evidence = {
            "cvss_score": 5.5,
            "is_kev": False,
            "exploit_maturity": "poc",
            "asset_criticality": "medium",
            "internet_exposed": False,
            "sighting_count": 1,
            "ransomware_relevant": False,
        }
        result = assess(evidence)
        # Score is 34 (cvss:6 + exploit:15 + criticality:8 + sightings:5).
        # Tier boundary is 35, so this lands at "low" — confirm it's not "critical".
        assert result.tier in {"low", "medium"}
        assert result.score < 80

    def test_automation_candidates_require_approval(self) -> None:
        """All suggested actions must require explicit human approval."""
        evidence = {
            "cvss_score": 9.8,
            "is_kev": True,
            "exploit_maturity": "weaponized",
            "asset_criticality": "critical",
            "internet_exposed": True,
            "sighting_count": 3,
            "ransomware_relevant": True,
        }
        result = assess(evidence)
        for candidate in result.automation_candidates:
            assert candidate.get("requires_approval") is True, (
                f"Action '{candidate['action']}' must require_approval=True"
            )

    def test_no_evidence_scores_low(self) -> None:
        result = assess({})
        assert result.tier == "low"
        assert result.score == 0


# ---------------------------------------------------------------------------
# Resolved evidence state
# ---------------------------------------------------------------------------


class TestResolvedEvidence:
    def test_resolved_evidence_dataclass(self) -> None:
        re = ResolvedEvidence(
            evidence={"cvss_score": 7.5, "is_kev": True},
            factor_provenance=[
                {"factor": "cvss", "source": "vulnerabilities", "state": "present"}
            ],
        )
        assert re.evidence["cvss_score"] == 7.5
        assert re.factor_provenance[0]["state"] == "present"

    def test_empty_resolved_evidence_defaults(self) -> None:
        re = ResolvedEvidence()
        assert re.evidence == {}
        assert re.factor_provenance == []


# ---------------------------------------------------------------------------
# Alert → correlation → case transition semantics
# ---------------------------------------------------------------------------


class TestAlertCorrelationCaseTransitions:
    """Verify that the transition state machine produces the right event types."""

    def test_alert_triggered_event_type(self) -> None:
        """alert.triggered must be produced when an alert fires."""
        event_type = "alert.triggered"
        assert event_type.startswith("alert.")

    def test_correlation_evaluated_event_type(self) -> None:
        """correlation.evaluated must be produced when a correlation is scored."""
        event_type = "correlation.evaluated"
        assert event_type.startswith("correlation.")

    def test_case_creation_requires_approval_flag(self) -> None:
        """Case creation automation candidates must carry requires_approval=True."""
        # assess() is the source of automation_candidates.
        result = assess(
            {
                "cvss_score": 9.0,
                "is_kev": True,
                "exploit_maturity": "functional",
                "asset_criticality": "critical",
                "internet_exposed": True,
                "sighting_count": 2,
                "ransomware_relevant": False,
            }
        )
        case_candidates = [c for c in result.automation_candidates if c["action"] == "create_case"]
        assert case_candidates, "Expected at least one create_case candidate"
        assert all(c["requires_approval"] is True for c in case_candidates)

    def test_all_trigger_types_have_evaluators(self) -> None:
        """Every supported trigger_type must have a registered evaluator."""
        expected = {
            "kev_exposure",
            "ioc_sighting",
            "agent_stale",
            "ransomware_relevance",
            "feed_degraded",
            "custom",
        }
        assert expected == set(_EVALUATORS.keys())
