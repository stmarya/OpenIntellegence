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

    def add(key: str, label: str, points: int, state: str) -> None:
        if state == "present":
            factors.append({"key": key, "label": label, "points": points, "state": "present"})
        elif state == "unknown":
            factors.append({"key": key, "label": label, "points": 0, "state": "unknown"})
        else:
            factors.append({"key": key, "label": label, "points": 0, "state": "absent"})

    cvss = evidence.get("cvss_score")
    if cvss is not None:
        add(
            "cvss",
            f"CVSS {cvss}",
            20 if cvss >= 9 else 14 if cvss >= 7 else 6 if cvss >= 4 else 0,
            "present",
        )
    else:
        add("cvss", "CVSS unknown", 0, "unknown")

    is_kev = evidence.get("is_kev")
    add(
        "kev",
        "Known Exploited Vulnerability",
        25,
        "present" if is_kev is True else "absent" if is_kev is False else "unknown",
    )
    exploit_state = (
        "present"
        if evidence.get("exploit_maturity") in {"poc", "functional", "weaponized", "active"}
        else "absent"
        if evidence.get("exploit_maturity") is not None
        else "unknown"
    )
    add(
        "exploit",
        "Public or active exploit evidence",
        15,
        exploit_state,
    )
    criticality = {
        "critical": 20,
        "high": 14,
        "medium": 8,
        "low": 3,
    }.get(str(evidence.get("asset_criticality", "")).lower(), 0)
    criticality_state = (
        "present"
        if criticality > 0
        else "absent"
        if evidence.get("asset_criticality") is not None
        else "unknown"
    )
    add(
        "asset_criticality",
        f"Asset criticality: {evidence.get('asset_criticality')}",
        criticality,
        criticality_state,
    )
    internet_exposed = evidence.get("internet_exposed")
    add(
        "internet_exposure",
        "Internet-exposed asset",
        15,
        "present"
        if internet_exposed is True
        else "absent"
        if internet_exposed is False
        else "unknown",
    )
    raw_sightings = evidence.get("sighting_count")
    sightings = None if raw_sightings is None else max(0, min(int(raw_sightings), 3))
    add(
        "sightings",
        "Corroborating sighting(s)"
        if sightings is None
        else f"{sightings} corroborating sighting(s)",
        0 if sightings is None else sightings * 5,
        "unknown" if sightings is None else "present" if sightings > 0 else "absent",
    )
    ransomware_relevant = evidence.get("ransomware_relevant")
    add(
        "ransomware",
        "Ransomware or sector relevance",
        10,
        "present"
        if ransomware_relevant is True
        else "absent"
        if ransomware_relevant is False
        else "unknown",
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
