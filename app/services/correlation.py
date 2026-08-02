"""Pure, explainable correlation scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class CorrelationAssessment:
    score: int
    tier: str
    factors: list[dict]
    automation_candidates: list[dict]


FactorState = Literal["present", "absent", "unknown"]


def assess(evidence: dict) -> CorrelationAssessment:
    """Score already-resolved server evidence.

    ``None`` always represents unknown. It is intentionally different from
    ``False`` or ``0`` so callers cannot turn missing enrichment into a clean
    state or lower-risk assertion.
    """
    factors: list[dict] = []

    def add(key: str, label: str, points: int, state: FactorState) -> None:
        factors.append(
            {
                "key": key,
                "label": label,
                "points": points if state == "present" else 0,
                "state": state,
            }
        )

    cvss = evidence.get("cvss_score")
    if cvss is None:
        add("cvss", "CVSS unknown", 0, "unknown")
    else:
        add(
            "cvss",
            f"CVSS {cvss}",
            20 if cvss >= 9 else 14 if cvss >= 7 else 6 if cvss >= 4 else 0,
            "present",
        )

    is_kev = evidence.get("is_kev")
    add(
        "kev",
        "Known Exploited Vulnerability",
        25,
        "present" if is_kev is True else "absent" if is_kev is False else "unknown",
    )

    maturity = evidence.get("exploit_maturity")
    add(
        "exploit",
        "Public or active exploit evidence",
        15,
        "present"
        if maturity in {"poc", "functional", "weaponized", "active"}
        else "absent"
        if maturity is not None
        else "unknown",
    )

    criticality_value = evidence.get("asset_criticality")
    criticality = {"critical": 20, "high": 14, "medium": 8, "low": 3}.get(
        str(criticality_value).lower(), 0
    )
    add(
        "asset_criticality",
        f"Asset criticality: {criticality_value}",
        criticality,
        "present" if criticality > 0 else "absent" if criticality_value is not None else "unknown",
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
        "Corroborating sightings unknown" if sightings is None else f"{sightings} corroborating sighting(s)",
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

    score = min(100, sum(int(item["points"]) for item in factors))
    tier = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"

    candidates: list[dict] = []
    if score >= 80:
        candidates.extend(
            [
                {"action": "create_case", "reason": "Critical correlated risk", "requires_approval": True},
                {"action": "notify_owner", "reason": "Critical exposure requires ownership", "requires_approval": True},
            ]
        )
    elif score >= 60:
        candidates.append({"action": "create_case", "reason": "High correlated risk", "requires_approval": True})
    if internet_exposed is True and is_kev is True:
        candidates.append(
            {"action": "request_containment_review", "reason": "Internet-exposed KEV", "requires_approval": True}
        )

    return CorrelationAssessment(score=score, tier=tier, factors=factors, automation_candidates=candidates)
