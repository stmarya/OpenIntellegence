"""Pure, explainable correlation scoring."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationAssessment:
    score: int
    tier: str
    factors: list[dict]
    automation_candidates: list[dict]


def assess(evidence: dict) -> CorrelationAssessment:
    factors: list[dict] = []

    def add(key: str, label: str, points: int, present: bool) -> None:
        if present:
            factors.append({"key": key, "label": label, "points": points, "state": "present"})

    cvss = evidence.get("cvss_score")
    if cvss is not None:
        add(
            "cvss",
            f"CVSS {cvss}",
            20 if cvss >= 9 else 14 if cvss >= 7 else 6 if cvss >= 4 else 0,
            True,
        )
    else:
        factors.append({"key": "cvss", "label": "CVSS unknown", "points": 0, "state": "unknown"})

    add("kev", "Known Exploited Vulnerability", 25, bool(evidence.get("is_kev")))
    add(
        "exploit",
        "Public or active exploit evidence",
        15,
        evidence.get("exploit_maturity") in {"poc", "functional", "weaponized", "active"},
    )
    criticality = {
        "critical": 20,
        "high": 14,
        "medium": 8,
        "low": 3,
    }.get(str(evidence.get("asset_criticality", "")).lower(), 0)
    add(
        "asset_criticality",
        f"Asset criticality: {evidence.get('asset_criticality')}",
        criticality,
        criticality > 0,
    )
    add("internet_exposure", "Internet-exposed asset", 15, bool(evidence.get("internet_exposed")))
    sightings = max(0, min(int(evidence.get("sighting_count") or 0), 3))
    add("sightings", f"{sightings} corroborating sighting(s)", sightings * 5, sightings > 0)
    add(
        "ransomware",
        "Ransomware or sector relevance",
        10,
        bool(evidence.get("ransomware_relevant")),
    )

    score = min(100, sum(int(x["points"]) for x in factors))
    tier = (
        "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    )

    candidates: list[dict] = []
    if score >= 80:
        candidates += [
            {
                "action": "create_case",
                "reason": "Critical correlated risk",
                "requires_approval": True,
            },
            {
                "action": "notify_owner",
                "reason": "Critical exposure requires ownership",
                "requires_approval": True,
            },
        ]
    elif score >= 60:
        candidates += [
            {"action": "create_case", "reason": "High correlated risk", "requires_approval": True},
        ]
    if evidence.get("internet_exposed") and evidence.get("is_kev"):
        candidates += [
            {
                "action": "request_containment_review",
                "reason": "Internet-exposed KEV",
                "requires_approval": True,
            }
        ]

    return CorrelationAssessment(
        score=score,
        tier=tier,
        factors=factors,
        automation_candidates=candidates,
    )
