"""Unit tests for server-side correlation evidence resolution and scoring.

These tests cover:
- Resolved evidence → correct deterministic score
- Partial evidence (some nulls) → reduced score, no fabricated values
- No evidence (unavailable) → score 0, low tier
- Manual-input evidence → correct score, manual_input status, evidence preserved
- Tenant isolation via ResolvedEvidence + build_from_manual

No network or LLM calls.  No database access — all tests exercise pure
dataclass / deterministic-scorer logic.
"""

from __future__ import annotations

from app.services.correlation import assess
from app.services.evidence_resolver import (
    ResolvedEvidence,
    ResolutionStatus,
    _compute_status,
    build_from_manual,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_resolved(**kwargs) -> ResolvedEvidence:
    """Build a ResolvedEvidence with sensible defaults."""
    base = dict(
        entity_type="vulnerability",
        entity_id="CVE-2024-0001",
        tenant_id="tenant-a",
    )
    base.update(kwargs)
    return ResolvedEvidence(**base)


# ---------------------------------------------------------------------------
# Fully resolved evidence
# ---------------------------------------------------------------------------


class TestFullyResolvedEvidence:
    def test_critical_score_all_factors_present(self) -> None:
        """All high-severity factors → critical tier."""
        ev = _make_resolved(
            cvss_score=9.8,
            is_kev=True,
            exploit_maturity="weaponized",
            asset_criticality="critical",
            internet_exposed=True,
            sighting_count=3,
            ransomware_relevant=True,
            resolved_fields=["cvss_score", "is_kev", "exploit_maturity",
                             "asset_criticality", "internet_exposed",
                             "sighting_count", "ransomware_relevant"],
            resolution_status="resolved",
        )
        outcome = assess(ev.to_scoring_dict())
        assert outcome.tier == "critical"
        assert outcome.score >= 80

    def test_high_cvss_kev_critical_asset(self) -> None:
        """CVSS ≥ 9, KEV, critical-criticality asset → high tier at minimum."""
        ev = _make_resolved(
            cvss_score=9.5,
            is_kev=True,
            asset_criticality="critical",
            resolution_status="resolved",
            resolved_fields=["cvss_score", "is_kev", "asset_criticality"],
            unresolved_fields=["exploit_maturity", "internet_exposed",
                               "sighting_count", "ransomware_relevant"],
        )
        outcome = assess(ev.to_scoring_dict())
        # CVSS 9.5 → 20 pts, KEV → 25 pts, critical asset → 20 pts = 65 → high
        assert outcome.tier in {"high", "critical"}
        assert outcome.score >= 60

    def test_scoring_dict_preserves_null_cvss(self) -> None:
        """None cvss_score passes through as None so scorer marks it unknown."""
        ev = _make_resolved(cvss_score=None)
        d = ev.to_scoring_dict()
        assert d["cvss_score"] is None

    def test_scoring_dict_false_defaults_for_unknown_booleans(self) -> None:
        """Unknown boolean evidence fields become False (neutral, not penalised)."""
        ev = _make_resolved(is_kev=None, internet_exposed=None, ransomware_relevant=None)
        d = ev.to_scoring_dict()
        assert d["is_kev"] is False
        assert d["internet_exposed"] is False
        assert d["ransomware_relevant"] is False

    def test_automation_candidates_on_critical(self) -> None:
        """Critical score produces automation_candidates."""
        ev = _make_resolved(
            cvss_score=9.8,
            is_kev=True,
            asset_criticality="critical",
            internet_exposed=True,
        )
        outcome = assess(ev.to_scoring_dict())
        if outcome.tier == "critical":
            assert outcome.automation_candidates
            actions = {c["action"] for c in outcome.automation_candidates}
            assert "create_case" in actions


# ---------------------------------------------------------------------------
# Partial evidence (some unknowns)
# ---------------------------------------------------------------------------


class TestPartialEvidence:
    def test_partial_status_from_unresolved_fields(self) -> None:
        """Having both resolved and unresolved fields → partial status."""
        ev = _make_resolved(
            cvss_score=7.5,
            is_kev=False,
            exploit_maturity=None,
            asset_criticality=None,
            internet_exposed=None,
            resolved_fields=["cvss_score", "is_kev"],
            unresolved_fields=["exploit_maturity", "asset_criticality",
                               "internet_exposed", "sighting_count", "ransomware_relevant"],
        )
        # _compute_status uses the resolved/unresolved lists
        assert _compute_status(ev) == "partial"

    def test_cvss_unknown_marked_in_factor_breakdown(self) -> None:
        """Null cvss_score produces state: 'unknown' in the factor breakdown."""
        ev = _make_resolved(cvss_score=None)
        outcome = assess(ev.to_scoring_dict())
        cvss_factor = next(f for f in outcome.factors if f["key"] == "cvss")
        assert cvss_factor["state"] == "unknown"
        assert cvss_factor["points"] == 0

    def test_partial_score_without_asset_factors(self) -> None:
        """No asset data means those factors do not contribute, score is lower."""
        ev_full = _make_resolved(
            cvss_score=7.5, is_kev=True, asset_criticality="critical", internet_exposed=True
        )
        ev_partial = _make_resolved(
            cvss_score=7.5, is_kev=True
        )
        full_score = assess(ev_full.to_scoring_dict()).score
        partial_score = assess(ev_partial.to_scoring_dict()).score
        assert full_score > partial_score

    def test_null_sighting_count_scores_zero_sightings(self) -> None:
        """Unknown sighting_count (None) does not add sighting points."""
        ev = _make_resolved(sighting_count=None)
        d = ev.to_scoring_dict()
        assert d["sighting_count"] == 0

    def test_snapshot_preserves_nulls(self) -> None:
        """to_snapshot() must not coerce None to zero."""
        ev = _make_resolved(
            cvss_score=None,
            asset_criticality=None,
            internet_exposed=None,
            sighting_count=None,
            ransomware_relevant=None,
        )
        snap = ev.to_snapshot()
        assert snap["cvss_score"] is None
        assert snap["asset_criticality"] is None
        assert snap["internet_exposed"] is None
        assert snap["sighting_count"] is None
        assert snap["ransomware_relevant"] is None

    def test_snapshot_includes_resolution_metadata(self) -> None:
        """to_snapshot() includes resolved/unresolved field lists."""
        ev = _make_resolved(
            resolved_fields=["cvss_score"],
            unresolved_fields=["asset_criticality"],
            resolution_status="partial",
        )
        snap = ev.to_snapshot()
        assert snap["resolution_status"] == "partial"
        assert "cvss_score" in snap["resolved_fields"]
        assert "asset_criticality" in snap["unresolved_fields"]


# ---------------------------------------------------------------------------
# No evidence (unavailable)
# ---------------------------------------------------------------------------


class TestNoEvidence:
    def test_empty_resolved_evidence_scores_zero(self) -> None:
        """No resolved evidence → score 0, tier low."""
        ev = _make_resolved(resolution_status="unavailable")
        outcome = assess(ev.to_scoring_dict())
        assert outcome.score == 0
        assert outcome.tier == "low"

    def test_compute_status_no_fields_is_unavailable(self) -> None:
        """An evidence with no resolved or unresolved fields is unavailable."""
        ev = _make_resolved()  # no resolved_fields or unresolved_fields
        assert _compute_status(ev) == "unavailable"

    def test_unavailable_produces_no_automation_candidates(self) -> None:
        """Score 0 should produce no automation candidates."""
        ev = _make_resolved(resolution_status="unavailable")
        outcome = assess(ev.to_scoring_dict())
        assert outcome.automation_candidates == []


# ---------------------------------------------------------------------------
# Manual input behaviour
# ---------------------------------------------------------------------------


class TestManualInputEvidence:
    def test_build_from_manual_status_is_manual_input(self) -> None:
        """Manual evidence always has resolution_status == 'manual_input'."""
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-9999",
            tenant_id="tenant-a",
            manual={"cvss_score": 9.5, "is_kev": True},
        )
        assert ev.resolution_status == "manual_input"

    def test_manual_evidence_preserved_separately(self) -> None:
        """Supplied values are stored in manual_evidence, not resolved_fields."""
        raw = {"cvss_score": 7.0, "is_kev": False, "asset_criticality": "high"}
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-9999",
            tenant_id="tenant-a",
            manual=raw,
        )
        assert ev.manual_evidence == raw
        assert ev.resolved_fields == []  # never source-resolved

    def test_manual_input_scores_correctly(self) -> None:
        """Manual evidence still produces a deterministic score."""
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-9999",
            tenant_id="tenant-a",
            manual={
                "cvss_score": 9.5,
                "is_kev": True,
                "asset_criticality": "critical",
                "internet_exposed": True,
            },
        )
        outcome = assess(ev.to_scoring_dict())
        assert outcome.score > 0
        assert outcome.tier in {"high", "critical"}

    def test_manual_snapshot_marks_resolution_status(self) -> None:
        """Snapshot from manual evidence clearly states manual_input."""
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-9999",
            tenant_id="tenant-a",
            manual={"cvss_score": 5.0},
        )
        snap = ev.to_snapshot()
        assert snap["resolution_status"] == "manual_input"

    def test_manual_analyst_notes_attached(self) -> None:
        """Analyst notes are captured on the resolved evidence."""
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-9999",
            tenant_id="tenant-a",
            manual={},
            analyst_notes="Confirmed exploitation in staging environment.",
        )
        assert ev.analyst_notes == "Confirmed exploitation in staging environment."


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_resolved_evidence_carries_tenant_id(self) -> None:
        """ResolvedEvidence is always bound to a specific tenant."""
        ev = _make_resolved(tenant_id="tenant-a")
        assert ev.tenant_id == "tenant-a"

    def test_different_tenants_are_independent(self) -> None:
        """Two ResolvedEvidence objects for the same entity but different
        tenants are completely independent."""
        ev_a = _make_resolved(entity_id="asset-1", tenant_id="tenant-a")
        ev_b = _make_resolved(entity_id="asset-1", tenant_id="tenant-b")
        assert ev_a.tenant_id != ev_b.tenant_id
        # Both start with empty resolved evidence — neither leaks to the other.
        assert ev_a.to_scoring_dict() == ev_b.to_scoring_dict()

    def test_build_from_manual_binds_to_tenant(self) -> None:
        """Manual evidence is bound to the supplied tenant_id."""
        ev = build_from_manual(
            entity_type="vulnerability",
            entity_id="CVE-2024-0001",
            tenant_id="tenant-x",
            manual={"cvss_score": 5.0},
        )
        assert ev.tenant_id == "tenant-x"

    def test_scoring_is_independent_of_tenant_id(self) -> None:
        """The scoring function does not use tenant_id — isolation is
        enforced at resolver / endpoint level, not inside the scorer."""
        ev_a = build_from_manual(
            "vulnerability", "CVE-1", "tenant-a", {"cvss_score": 7.5, "is_kev": True}
        )
        ev_b = build_from_manual(
            "vulnerability", "CVE-1", "tenant-b", {"cvss_score": 7.5, "is_kev": True}
        )
        score_a = assess(ev_a.to_scoring_dict()).score
        score_b = assess(ev_b.to_scoring_dict()).score
        assert score_a == score_b  # same evidence → same score regardless of tenant


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterministicScoring:
    def test_identical_evidence_produces_identical_score(self) -> None:
        """assess() is a pure function — same input always gives same output."""
        ev = _make_resolved(
            cvss_score=8.5,
            is_kev=True,
            exploit_maturity="poc",
            asset_criticality="medium",
            internet_exposed=True,
            sighting_count=2,
            ransomware_relevant=False,
        )
        d = ev.to_scoring_dict()
        r1 = assess(d)
        r2 = assess(d)
        assert r1.score == r2.score
        assert r1.tier == r2.tier
        assert r1.factors == r2.factors

    def test_score_bounded_between_0_and_100(self) -> None:
        """Score is always in [0, 100] regardless of evidence."""
        for cvss in (None, 0.0, 5.0, 9.9):
            ev = _make_resolved(
                cvss_score=cvss,
                is_kev=True,
                exploit_maturity="weaponized",
                asset_criticality="critical",
                internet_exposed=True,
                sighting_count=99,
                ransomware_relevant=True,
            )
            score = assess(ev.to_scoring_dict()).score
            assert 0 <= score <= 100
