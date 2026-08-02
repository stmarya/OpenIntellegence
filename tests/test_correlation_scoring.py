from datetime import UTC, datetime

from app.services.alerting import alert_fingerprint
from app.services.correlation import assess
from app.services.evidence_resolver import SUPPORTED_ENTITY_TYPES, empty_evidence


def test_alert_fingerprint_is_deterministic_within_hour() -> None:
    bucket = datetime(2026, 8, 2, 22, 59, tzinfo=UTC)
    first = alert_fingerprint("tenant-1", rule_id="rule-1", entity_type="asset", entity_id="asset-1", severity="high", bucket=bucket)
    second = alert_fingerprint("tenant-1", rule_id="rule-1", entity_type="asset", entity_id="asset-1", severity="high", bucket=bucket)
    assert first == second


def test_unknown_evidence_stays_unknown_and_does_not_create_actions() -> None:
    result = assess({
        "cvss_score": None, "is_kev": None, "exploit_maturity": None,
        "asset_criticality": None, "internet_exposed": None,
        "sighting_count": None, "ransomware_relevant": None,
    })
    assert result.score == 0
    assert result.automation_candidates == []
    assert {factor["state"] for factor in result.factors} == {"unknown"}


def test_false_is_distinct_from_unknown() -> None:
    result = assess({
        "cvss_score": None, "is_kev": False, "exploit_maturity": "none",
        "asset_criticality": "low", "internet_exposed": False,
        "sighting_count": 0, "ransomware_relevant": False,
    })
    by_key = {factor["key"]: factor for factor in result.factors}
    assert by_key["kev"]["state"] == "absent"
    assert by_key["internet_exposure"]["state"] == "absent"
    assert by_key["cvss"]["state"] == "unknown"


def test_evidence_envelope_exposes_unavailable_and_unknown_values() -> None:
    evidence = empty_evidence("asset", "missing-asset")
    assert evidence["resolution_status"] == "unavailable"
    assert evidence["vulnerability_context"]["cvss_score"] is None
    assert evidence["ioc_sightings"]["count"] is None
    assert SUPPORTED_ENTITY_TYPES == {"asset", "vulnerability", "indicator"}
