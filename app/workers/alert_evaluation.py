"""Alert evaluation worker.

Evaluates enabled tenant alert rules against server-side DB facts, respects
fingerprint/cooldown deduplication, and persists explicit evidence with
unknown/partial state annotation.

Safety guarantee
----------------
This worker NEVER executes risky response actions automatically.  It only
creates or updates Alert rows and records TimelineEvent entries. Any remediation
action is deferred to the approval-gated AutomationRun pathway.

Supported trigger types
-----------------------
* kev_exposure        – assets with open KEV exposures in the tenant
* ioc_sighting        – new IOC sightings in the tenant within the window
* agent_stale         – agents whose heartbeat has exceeded the stale threshold
* ransomware_relevance – ransomware victims matching tenant sector/domain hints
* feed_degraded        – source runs that have been failing recently
* custom              – simple threshold conditions on numeric platform facts
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.alert_models import Alert, AlertRule, Sighting
from app.db.base import get_session_factory
from app.db.correlation_models import TimelineEvent
from app.db.models import Agent, AgentStatus, Asset, AssetExposure, RansomwareVictim, RunStatus, SourceRun, Vulnerability

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvaluationMatch:
    """A single rule-match candidate produced by an evaluator."""

    title: str
    summary: str
    entity_type: str | None
    entity_id: str | None
    severity: str
    evidence: dict
    # Client-readable status for each evidence field: "present", "partial", "unknown"
    evidence_state: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Per-rule evaluators
# ---------------------------------------------------------------------------


async def _eval_kev_exposure(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Find assets with open KEV exposures."""
    rows = (
        await session.execute(
            select(Asset, Vulnerability)
            .join(AssetExposure, AssetExposure.asset_id == Asset.id)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(
                Asset.tenant_id == tenant_id,
                Vulnerability.is_kev.is_(True),
                AssetExposure.resolved_at.is_(None),
            )
            .order_by(Vulnerability.cvss_score.desc().nulls_last())
            .limit(rule.condition.get("max_matches", 20))
        )
    ).all()

    matches: list[EvaluationMatch] = []
    for asset, vuln in rows:
        cvss = vuln.cvss_score
        evidence = {
            "cve_id": vuln.cve_id,
            "is_kev": True,
            "cvss_score": cvss,
            "exploit_maturity": (
                vuln.exploit_maturity.value
                if hasattr(vuln.exploit_maturity, "value")
                else str(vuln.exploit_maturity)
            ),
            "asset_criticality": asset.criticality,
            "asset_hostname": asset.hostname,
        }
        matches.append(
            EvaluationMatch(
                title=f"KEV exposure: {vuln.cve_id} on {asset.hostname}",
                summary=(
                    f"Asset '{asset.hostname}' ({asset.criticality} criticality) "
                    f"has an open exposure to KEV {vuln.cve_id} "
                    f"(CVSS {'unknown' if cvss is None else cvss})."
                ),
                entity_type="asset",
                entity_id=asset.id,
                severity=rule.severity,
                evidence=evidence,
                evidence_state={
                    "cvss_score": "present" if cvss is not None else "unknown",
                    "is_kev": "present",
                },
            )
        )
    return matches


async def _eval_ioc_sighting(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Find IOC sightings within the configured look-back window."""
    window_hours = rule.condition.get("window_hours", 24)
    since = datetime.now(UTC) - timedelta(hours=window_hours)
    min_confidence = rule.condition.get("min_confidence", 0)

    stmt = (
        select(Sighting)
        .where(
            Sighting.tenant_id == tenant_id,
            Sighting.observed_at >= since,
        )
        .order_by(Sighting.observed_at.desc())
        .limit(rule.condition.get("max_matches", 20))
    )
    if min_confidence:
        stmt = stmt.where(
            (Sighting.confidence >= min_confidence) | Sighting.confidence.is_(None)
        )

    rows = (await session.execute(stmt)).scalars().all()
    matches: list[EvaluationMatch] = []
    for sighting in rows:
        evidence = {
            "entity_type": sighting.entity_type,
            "entity_id": sighting.entity_id,
            "source": sighting.source,
            "observed_at": sighting.observed_at.isoformat(),
            "confidence": sighting.confidence,
        }
        matches.append(
            EvaluationMatch(
                title=f"IOC sighting: {sighting.entity_type} {sighting.entity_id}",
                summary=(
                    f"IOC '{sighting.entity_id}' ({sighting.entity_type}) "
                    f"sighted via {sighting.source} at {sighting.observed_at.isoformat()}."
                ),
                entity_type=sighting.entity_type,
                entity_id=sighting.entity_id,
                severity=rule.severity,
                evidence=evidence,
                evidence_state={
                    "confidence": "present" if sighting.confidence is not None else "unknown",
                },
            )
        )
    return matches


async def _eval_agent_stale(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Find agents that have gone stale (missed heartbeat threshold)."""
    stale_minutes = rule.condition.get("stale_minutes", 60)
    cutoff = datetime.now(UTC) - timedelta(minutes=stale_minutes)

    rows = (
        await session.execute(
            select(Agent).where(
                Agent.tenant_id == tenant_id,
                Agent.status.in_([AgentStatus.STALE, AgentStatus.UNREACHABLE]),
                # Also catch agents whose heartbeat has lapsed even if status
                # hasn't been updated yet.
                (
                    Agent.last_heartbeat_at <= cutoff
                ) | Agent.last_heartbeat_at.is_(None),
            )
        )
    ).scalars().all()

    matches: list[EvaluationMatch] = []
    for agent in rows:
        last_hb = agent.last_heartbeat_at
        evidence = {
            "agent_id": agent.id,
            "status": str(agent.status),
            "last_heartbeat_at": last_hb.isoformat() if last_hb else None,
        }
        matches.append(
            EvaluationMatch(
                title=f"Agent stale: {agent.id}",
                summary=(
                    f"Agent '{agent.id}' is {agent.status}. "
                    f"Last heartbeat: {'unknown' if last_hb is None else last_hb.isoformat()}."
                ),
                entity_type="agent",
                entity_id=agent.id,
                severity=rule.severity,
                evidence=evidence,
                evidence_state={
                    "last_heartbeat_at": "present" if last_hb else "unknown",
                },
            )
        )
    return matches


async def _eval_ransomware_relevance(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Find ransomware victims that match the tenant's configured sectors."""
    sectors = rule.condition.get("sectors", [])
    window_days = rule.condition.get("window_days", 7)
    since = datetime.now(UTC) - timedelta(days=window_days)

    stmt = select(RansomwareVictim).where(
        RansomwareVictim.discovered_at >= since
    )
    if sectors:
        stmt = stmt.where(RansomwareVictim.sector.in_(sectors))

    rows = (await session.execute(stmt.limit(rule.condition.get("max_matches", 10)))).scalars().all()
    matches: list[EvaluationMatch] = []
    for victim in rows:
        evidence = {
            "victim_id": victim.id,
            "canonical_key": victim.canonical_key,
            "group_name": victim.group_name,
            "sector": victim.sector,
            "country": victim.country,
            "discovered_at": victim.discovered_at.isoformat(),
        }
        matches.append(
            EvaluationMatch(
                title=f"Ransomware relevance: {victim.group_name} targeted {victim.sector}",
                summary=(
                    f"Ransomware group '{victim.group_name}' listed a "
                    f"'{victim.sector}' victim on {victim.discovered_at.date()}."
                ),
                entity_type="ransomware_victim",
                entity_id=victim.id,
                severity=rule.severity,
                evidence=evidence,
                evidence_state={
                    "sector": "present" if victim.sector else "unknown",
                    "country": "present" if victim.country else "unknown",
                },
            )
        )
    return matches


async def _eval_feed_degraded(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Detect feeds that have been failing recently."""
    window_hours = rule.condition.get("window_hours", 6)
    min_failures = rule.condition.get("min_failures", 2)
    since = datetime.now(UTC) - timedelta(hours=window_hours)

    # Count failures per source within the window.
    stmt = (
        select(SourceRun.source, func.count().label("failures"))
        .where(
            SourceRun.status == RunStatus.FAILED,
            SourceRun.started_at >= since,
        )
        .group_by(SourceRun.source)
        .having(func.count() >= min_failures)
    )
    rows = (await session.execute(stmt)).all()
    matches: list[EvaluationMatch] = []
    for source, failures in rows:
        evidence = {
            "source": source,
            "failure_count": failures,
            "window_hours": window_hours,
        }
        matches.append(
            EvaluationMatch(
                title=f"Feed degraded: {source} ({failures} failures in {window_hours}h)",
                summary=(
                    f"Ingestion feed '{source}' has failed {failures} times "
                    f"in the last {window_hours} hours. Data may be incomplete."
                ),
                entity_type="feed",
                entity_id=source,
                severity=rule.severity,
                evidence=evidence,
                evidence_state={"failure_count": "present"},
            )
        )
    return matches


async def _eval_custom(
    session: AsyncSession, tenant_id: str, rule: AlertRule
) -> list[EvaluationMatch]:
    """Evaluate a safely-constrained custom condition.

    Supported conditions (``rule.condition`` keys):
    - ``metric``: one of "open_alert_count", "kev_exposure_count", "stale_agent_count"
    - ``operator``: "gte" | "gt" | "lte" | "lt" | "eq"
    - ``threshold``: numeric value

    No arbitrary code execution — only whitelisted metric queries are allowed.
    """
    metric = rule.condition.get("metric", "")
    operator = rule.condition.get("operator", "gte")
    threshold = rule.condition.get("threshold", 1)

    allowed_metrics = {
        "open_alert_count",
        "kev_exposure_count",
        "stale_agent_count",
    }
    if metric not in allowed_metrics:
        log.warning(
            "alert_eval.custom_metric_not_allowed",
            rule_id=rule.id,
            metric=metric,
        )
        return []

    # Resolve the metric value.
    value: int = 0
    if metric == "open_alert_count":
        value = (
            await session.scalar(
                select(func.count())
                .select_from(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.status == "open")
            )
        ) or 0
    elif metric == "kev_exposure_count":
        value = (
            await session.scalar(
                select(func.count())
                .select_from(AssetExposure)
                .join(Asset, Asset.id == AssetExposure.asset_id)
                .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
                .where(
                    Asset.tenant_id == tenant_id,
                    Vulnerability.is_kev.is_(True),
                    AssetExposure.resolved_at.is_(None),
                )
            )
        ) or 0
    elif metric == "stale_agent_count":
        value = (
            await session.scalar(
                select(func.count())
                .select_from(Agent)
                .where(
                    Agent.tenant_id == tenant_id,
                    Agent.status.in_([AgentStatus.STALE, AgentStatus.UNREACHABLE]),
                )
            )
        ) or 0

    op_map: dict[str, Any] = {
        "gte": lambda v, t: v >= t,
        "gt": lambda v, t: v > t,
        "lte": lambda v, t: v <= t,
        "lt": lambda v, t: v < t,
        "eq": lambda v, t: v == t,
    }
    check = op_map.get(operator)
    if check is None or not check(value, threshold):
        return []

    evidence = {
        "metric": metric,
        "operator": operator,
        "threshold": threshold,
        "actual_value": value,
    }
    return [
        EvaluationMatch(
            title=f"Custom rule triggered: {metric} {operator} {threshold} (actual: {value})",
            summary=(
                f"Custom alert rule fired: metric '{metric}' is {value}, "
                f"which satisfies the condition '{operator} {threshold}'."
            ),
            entity_type="platform",
            entity_id=tenant_id,
            severity=rule.severity,
            evidence=evidence,
            evidence_state={"actual_value": "present"},
        )
    ]


# ---------------------------------------------------------------------------
# Fingerprint and cooldown helpers
# ---------------------------------------------------------------------------


def _fingerprint(tenant_id: str, rule_id: str, entity_type: str | None, entity_id: str | None) -> str:
    raw = "|".join(
        (
            tenant_id,
            rule_id,
            entity_type or "",
            entity_id or "",
        )
    )
    return sha256(raw.encode()).hexdigest()


async def _within_cooldown(
    session: AsyncSession,
    tenant_id: str,
    fingerprint: str,
    cooldown_minutes: int,
) -> bool:
    """Return True if an alert with this fingerprint fired within the cooldown window."""
    cutoff = datetime.now(UTC) - timedelta(minutes=cooldown_minutes)
    existing = (
        await session.execute(
            select(Alert).where(
                Alert.tenant_id == tenant_id,
                Alert.fingerprint == fingerprint,
                Alert.last_triggered_at >= cutoff,
            )
        )
    ).scalar_one_or_none()
    return existing is not None


# ---------------------------------------------------------------------------
# Alert persistence with timeline event
# ---------------------------------------------------------------------------


async def _persist_alert(
    session: AsyncSession,
    tenant_id: str,
    rule: AlertRule,
    match: EvaluationMatch,
    fingerprint: str,
) -> Alert:
    """Insert or deduplicate-update an Alert and append a TimelineEvent."""
    from uuid import uuid4

    now = datetime.now(UTC)
    alert = Alert(
        id=str(uuid4()),
        tenant_id=tenant_id,
        rule_id=rule.id,
        fingerprint=fingerprint,
        title=match.title,
        summary=match.summary,
        severity=match.severity,
        status="open",
        entity_type=match.entity_type,
        entity_id=match.entity_id,
        evidence=match.evidence,
        payload={"evidence_state": match.evidence_state},
        first_triggered_at=now,
        last_triggered_at=now,
        occurrences=1,
    )

    try:
        async with session.begin_nested():
            session.add(alert)
            await session.flush()
    except IntegrityError:
        # Duplicate fingerprint — bump occurrence counter.
        alert = (
            await session.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.fingerprint == fingerprint)
                .with_for_update()
            )
        ).scalar_one()
        alert.occurrences += 1
        alert.last_triggered_at = now
        alert.evidence = match.evidence
        alert.payload = {"evidence_state": match.evidence_state}
        await session.flush()

    # Append timeline event — always, even on dedup.
    event = TimelineEvent(
        id=str(uuid4()),
        tenant_id=tenant_id,
        object_type="alert",
        object_id=alert.id,
        event_type="alert.triggered",
        actor=f"worker:alert_evaluation",
        data={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "trigger_type": rule.trigger_type,
            "severity": match.severity,
            "occurrences": alert.occurrences,
            "evidence": match.evidence,
        },
        event_at=now,
        created_at=now,
    )
    session.add(event)
    await session.flush()

    return alert


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

_EVALUATORS = {
    "kev_exposure": _eval_kev_exposure,
    "ioc_sighting": _eval_ioc_sighting,
    "agent_stale": _eval_agent_stale,
    "ransomware_relevance": _eval_ransomware_relevance,
    "feed_degraded": _eval_feed_degraded,
    "custom": _eval_custom,
}


class AlertEvaluationWorker:
    """Evaluates all enabled tenant alert rules against server-side DB facts.

    Safety contract
    ---------------
    * Reads only; never mutates infrastructure state.
    * Creates Alert rows and TimelineEvent entries only.
    * Never executes or schedules remediation actions.
    * All automation candidates require explicit human approval via the
      AutomationRun / approval workflow.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def evaluate_tenant(self, session: AsyncSession, tenant_id: str) -> int:
        """Evaluate all enabled rules for one tenant.  Returns alerts created/updated."""
        rules = (
            await session.execute(
                select(AlertRule).where(
                    AlertRule.tenant_id == tenant_id,
                    AlertRule.enabled.is_(True),
                )
            )
        ).scalars().all()

        total = 0
        for rule in rules:
            evaluator = _EVALUATORS.get(rule.trigger_type)
            if evaluator is None:
                log.warning(
                    "alert_eval.unknown_trigger_type",
                    rule_id=rule.id,
                    trigger_type=rule.trigger_type,
                )
                continue

            try:
                matches = await evaluator(session, tenant_id, rule)
            except Exception as exc:  # noqa: BLE001
                log.exception(
                    "alert_eval.evaluator_error",
                    rule_id=rule.id,
                    trigger_type=rule.trigger_type,
                    error=str(exc),
                )
                continue

            for match in matches:
                fp = _fingerprint(tenant_id, rule.id, match.entity_type, match.entity_id)
                if await _within_cooldown(session, tenant_id, fp, rule.cooldown_minutes):
                    log.debug(
                        "alert_eval.cooldown_skip",
                        rule_id=rule.id,
                        fingerprint=fp,
                        cooldown_minutes=rule.cooldown_minutes,
                    )
                    continue
                await _persist_alert(session, tenant_id, rule, match, fp)
                total += 1

        return total

    async def run_once(self) -> int:
        """One full evaluation pass over all tenants.  Returns total alerts fired."""
        from app.db.models import Tenant

        factory = get_session_factory()
        async with factory() as session:
            tenants = (await session.execute(select(Tenant).where(Tenant.is_active.is_(True)))).scalars().all()
            total = 0
            for tenant in tenants:
                try:
                    fired = await self.evaluate_tenant(session, tenant.id)
                    total += fired
                    await session.commit()
                except Exception as exc:  # noqa: BLE001
                    log.exception(
                        "alert_eval.tenant_error",
                        tenant_id=tenant.id,
                        error=str(exc),
                    )
                    await session.rollback()
            return total


async def main() -> None:
    settings = get_settings()
    worker = AlertEvaluationWorker(settings)
    while True:
        try:
            fired = await worker.run_once()
            log.info("alert_eval.cycle_complete", alerts_fired=fired)
        except Exception as exc:  # noqa: BLE001
            log.exception("alert_eval.cycle_error", error=str(exc))
        await asyncio.sleep(300)  # 5-minute evaluation cadence


if __name__ == "__main__":
    asyncio.run(main())
