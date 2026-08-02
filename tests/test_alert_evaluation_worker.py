from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.db.alert_models import Alert, AlertRule, Sighting
from app.db.models import Agent, Asset, AssetExposure, Vulnerability
from app.workers import alert_evaluation
from app.workers.alert_evaluation import AlertCandidate, AlertEvaluationWorker

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class _FakeResult:
    def __init__(self, *, scalar_one_or_none=None, scalar_one=None, scalar=None, rows=None) -> None:
        self._scalar_one_or_none = scalar_one_or_none
        self._scalar_one = scalar_one
        self._scalar = scalar
        self._rows = rows or []

    def scalar_one_or_none(self):
        return self._scalar_one_or_none

    def scalar_one(self):
        return self._scalar_one

    def scalar(self):
        return self._scalar

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, results: list[_FakeResult]) -> None:
        self._results = list(results)

    async def execute(self, _stmt):
        return self._results.pop(0)

    async def flush(self) -> None:
        return None


class _FactorySession:
    async def commit(self) -> None:
        return None


def _settings() -> Settings:
    return Settings()


def _rule(trigger_type: str, **kwargs) -> AlertRule:
    return AlertRule(
        id=kwargs.get("id", "rule-1"),
        tenant_id=kwargs.get("tenant_id", "tenant-1"),
        name=kwargs.get("name", "rule"),
        description=None,
        trigger_type=trigger_type,
        condition=kwargs.get("condition", {}),
        severity=kwargs.get("severity", "high"),
        enabled=kwargs.get("enabled", True),
        cooldown_minutes=kwargs.get("cooldown_minutes", 60),
        auto_create_case=kwargs.get("auto_create_case", False),
    )


@pytest.mark.asyncio
async def test_custom_rule_is_explicitly_skipped() -> None:
    worker = AlertEvaluationWorker(_settings())
    result = await worker.evaluate_rule(session=None, rule=_rule("custom"), now=NOW)  # type: ignore[arg-type]
    assert result.skip_reason == "unsupported_custom_trigger"


@pytest.mark.asyncio
async def test_disabled_rule_is_skipped_in_run_once(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = AlertEvaluationWorker(_settings())
    disabled = _rule("ioc_sighting", enabled=False)

    async def _fake_claim(_session, _limit=None):
        return [disabled]

    async def _should_not_evaluate(*_args, **_kwargs):
        raise AssertionError("disabled rule should never be evaluated")

    class _FakeFactoryContext:
        async def __aenter__(self):
            return _FactorySession()

        async def __aexit__(self, *_args):
            return False

    def _fake_factory():
        return _FakeFactoryContext()

    monkeypatch.setattr(alert_evaluation, "get_session_factory", lambda: _fake_factory)
    worker.claim_rules = _fake_claim  # type: ignore[method-assign]
    worker.evaluate_rule = _should_not_evaluate  # type: ignore[method-assign]

    result = await worker.run_once()
    assert result["processed"] == 1
    assert result["skipped"] == 1


@pytest.mark.asyncio
async def test_ioc_sighting_matcher_builds_grouped_candidate() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("ioc_sighting")

    async def _fake_fetch(_session, tenant_id, _condition, _now):
        assert tenant_id == "tenant-1"
        return [
            Sighting(
                id="s-1",
                tenant_id="tenant-1",
                entity_type="indicator",
                entity_id="1.2.3.4",
                source="otx",
                observed_at=NOW - timedelta(minutes=5),
                confidence=80,
                context={},
            ),
            Sighting(
                id="s-2",
                tenant_id="tenant-1",
                entity_type="indicator",
                entity_id="1.2.3.4",
                source="manual",
                observed_at=NOW - timedelta(minutes=1),
                confidence=90,
                context={},
            ),
        ]

    worker.fetch_ioc_sightings = _fake_fetch  # type: ignore[method-assign]
    matches = await worker.match_ioc_sighting(None, rule, NOW)  # type: ignore[arg-type]
    assert len(matches) == 1
    assert matches[0].entity_id == "1.2.3.4"
    assert {e["record_id"] for e in matches[0].evidence} == {"s-1", "s-2"}


@pytest.mark.asyncio
async def test_agent_stale_matcher_candidate() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("agent_stale")

    async def _fake_fetch(_session, tenant_id, _condition, _now):
        assert tenant_id == "tenant-1"
        return [
            Agent(
                id="a-1",
                tenant_id="tenant-1",
                asset_id=None,
                version="1.0",
                os_family="linux",
                status="stale",
                cert_serial=None,
                cert_fingerprint=None,
                cert_issued_at=None,
                cert_expires_at=None,
                enrolled_at=None,
                last_heartbeat_at=NOW - timedelta(hours=2),
                last_inventory_at=None,
                revoked_at=None,
                revocation_reason=None,
            )
        ]

    worker.fetch_stale_agents = _fake_fetch  # type: ignore[method-assign]
    matches = await worker.match_agent_stale(None, rule, NOW)  # type: ignore[arg-type]
    assert len(matches) == 1
    assert matches[0].entity_type == "agent"
    assert matches[0].matched_factors["trigger_type"] == "agent_stale"


@pytest.mark.asyncio
async def test_kev_exposure_matcher_candidate() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("kev_exposure")
    exposure = AssetExposure(
        id="exp-1",
        asset_id="asset-1",
        vulnerability_id="vuln-1",
        matched_via="cpe",
        match_evidence="match",
        detected_at=NOW - timedelta(days=1),
        resolved_at=None,
        sla_due_at=None,
    )
    asset = Asset(
        id="asset-1",
        tenant_id="tenant-1",
        hostname="host-1",
        asset_type="endpoint",
        criticality="high",
        os_family="linux",
        os_version="1",
        os_eol=False,
        ip_address=None,
        mac_address=None,
        exposed_cve_count=1,
        risk_score=80,
        tags=[],
        meta={},
        last_seen_at=NOW,
    )
    vuln = Vulnerability(
        id="vuln-1",
        cve_id="CVE-2026-0001",
        title="v",
        description="d",
        cvss_score=9.1,
        cvss_vector=None,
        severity="critical",
        epss_score=None,
        published_at=None,
        last_modified_at=None,
        is_kev=True,
        kev_added_at=None,
        kev_due_at=None,
        vendor=None,
        product=None,
        cpe_uris=[],
        exploit_maturity="unknown",
        sources=["cisa_kev"],
        first_seen=NOW,
        last_seen=NOW,
    )

    async def _fake_fetch(_session, tenant_id, _condition):
        assert tenant_id == "tenant-1"
        return [(exposure, asset, vuln)]

    worker.fetch_kev_exposures = _fake_fetch  # type: ignore[method-assign]
    matches = await worker.match_kev_exposure(None, rule, NOW)  # type: ignore[arg-type]
    assert len(matches) == 1
    assert matches[0].entity_type == "asset"
    assert matches[0].risk_score == 91


@pytest.mark.asyncio
async def test_kev_exposure_unknown_cvss_preserved() -> None:
    """CVSS None must not be coerced to 0.0; risk_score and highest_cvss must remain None."""
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("kev_exposure")
    exposure = AssetExposure(
        id="exp-2",
        asset_id="asset-2",
        vulnerability_id="vuln-2",
        matched_via="cpe",
        match_evidence="match",
        detected_at=NOW - timedelta(days=1),
        resolved_at=None,
        sla_due_at=None,
    )
    asset = Asset(
        id="asset-2",
        tenant_id="tenant-1",
        hostname="host-2",
        asset_type="endpoint",
        criticality="medium",
        os_family="linux",
        os_version="1",
        os_eol=False,
        ip_address=None,
        mac_address=None,
        exposed_cve_count=1,
        risk_score=None,
        tags=[],
        meta={},
        last_seen_at=NOW,
    )
    vuln_no_cvss = Vulnerability(
        id="vuln-2",
        cve_id="CVE-2026-0002",
        title="v",
        description="d",
        cvss_score=None,
        cvss_vector=None,
        severity="high",
        epss_score=None,
        published_at=None,
        last_modified_at=None,
        is_kev=True,
        kev_added_at=None,
        kev_due_at=None,
        vendor=None,
        product=None,
        cpe_uris=[],
        exploit_maturity="unknown",
        sources=["cisa_kev"],
        first_seen=NOW,
        last_seen=NOW,
    )

    async def _fake_fetch(_session, tenant_id, _condition):
        assert tenant_id == "tenant-1"
        return [(exposure, asset, vuln_no_cvss)]

    worker.fetch_kev_exposures = _fake_fetch  # type: ignore[method-assign]
    matches = await worker.match_kev_exposure(None, rule, NOW)  # type: ignore[arg-type]
    assert len(matches) == 1
    assert matches[0].risk_score is None, "unknown CVSS must not produce a risk_score of 0"
    assert matches[0].matched_factors["highest_cvss"] is None, "highest_cvss must be None when CVSS is unknown"


@pytest.mark.asyncio
async def test_ransomware_relevance_matcher_candidate() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("ransomware_relevance")

    async def _fake_fetch(_session, tenant_id, _condition, _now):
        assert tenant_id == "tenant-1"
        return [
            Sighting(
                id="s-r1",
                tenant_id="tenant-1",
                entity_type="ransomware_victim",
                entity_id="victim-1",
                source="ransomlook",
                observed_at=NOW - timedelta(hours=3),
                confidence=70,
                context={},
            )
        ]

    worker.fetch_ransomware_sightings = _fake_fetch  # type: ignore[method-assign]
    matches = await worker.match_ransomware_relevance(None, rule, NOW)  # type: ignore[arg-type]
    assert len(matches) == 1
    assert matches[0].entity_id == "victim-1"


@pytest.mark.asyncio
async def test_feed_degraded_matcher_and_missing_source_skip() -> None:
    worker = AlertEvaluationWorker(_settings())

    missing_source = await worker.match_feed_degraded(None, _rule("feed_degraded"), NOW)  # type: ignore[arg-type]
    assert missing_source.skip_reason == "feed_degraded_missing_source"

    async def _fake_feed_data(_session, tenant_id, source, _now, _recent, _baseline):
        assert tenant_id == "tenant-1"
        assert source == "otx"
        return 0, 120, [], ["s-1"]

    worker.fetch_feed_window_data = _fake_feed_data  # type: ignore[method-assign]
    result = await worker.match_feed_degraded(
        None,  # type: ignore[arg-type]
        _rule(
            "feed_degraded", condition={"source": "otx", "recent_minutes": 60, "baseline_hours": 24}
        ),
        NOW,
    )
    assert result.skip_reason is None
    assert len(result.candidates) == 1
    assert result.candidates[0].entity_id == "otx"


@pytest.mark.asyncio
async def test_cooldown_aggregation_updates_existing_alert() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("ioc_sighting", cooldown_minutes=120)
    existing = Alert(
        id="alert-1",
        tenant_id="tenant-1",
        rule_id="rule-1",
        fingerprint="f1",
        title="Existing",
        summary=None,
        severity="high",
        status="open",
        entity_type="indicator",
        entity_id="ioc-1",
        risk_score=10,
        payload={},
        first_triggered_at=NOW - timedelta(minutes=30),
        last_triggered_at=NOW - timedelta(minutes=30),
        occurrences=2,
        acknowledged_at=None,
        acknowledged_by=None,
    )
    session = _FakeSession([_FakeResult(scalar_one_or_none=existing)])

    candidate = AlertCandidate(
        entity_type="indicator",
        entity_id="ioc-1",
        title="IOC",
        summary="summary",
        severity="high",
        risk_score=50,
        observed_at=NOW,
        matched_factors={"trigger_type": "ioc_sighting"},
        evidence=[{"record_type": "sighting", "record_id": "s-1"}],
        provenance={"sources": ["otx"]},
    )
    status = await worker.upsert_alert(session, rule, candidate, NOW)
    assert status == "aggregated"
    assert existing.occurrences == 3
    assert existing.risk_score == 50


def test_auto_create_case_is_pending_candidate_only() -> None:
    worker = AlertEvaluationWorker(_settings())
    rule = _rule("ioc_sighting", auto_create_case=True)
    candidate = AlertCandidate(
        entity_type="indicator",
        entity_id="ioc-1",
        title="IOC",
        summary=None,
        severity="high",
        risk_score=None,
        observed_at=NOW,
        matched_factors={"trigger_type": "ioc_sighting"},
        evidence=[{"record_type": "sighting", "record_id": "s-1"}],
        provenance={"sources": ["otx"]},
    )
    payload = worker._alert_payload(rule, candidate, NOW)
    assert payload["case_candidate"]["state"] == "pending_approval"
    assert payload["case_candidate"]["requested"] is True
