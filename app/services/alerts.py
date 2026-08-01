"""Tenant-scoped alert rule evaluation worker."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Agent,
    AgentStatus,
    Alert,
    AlertEvaluationRun,
    AlertHistory,
    AlertRule,
    AlertTriggerType,
    Asset,
    AssetExposure,
    Indicator,
    RansomwareVictim,
    RunStatus,
    SourceRun,
    Vulnerability,
)


@dataclass(slots=True)
class RuleOutcome:
    rule_id: int
    status: str
    triggered: int = 0
    skipped: int = 0
    error: str | None = None


def _fingerprint(rule_id: int, payload: dict[str, Any]) -> str:
    raw = json.dumps({"rule_id": rule_id, "payload": payload}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "gt":
        return actual is not None and actual > expected
    if op == "gte":
        return actual is not None and actual >= expected
    if op == "lt":
        return actual is not None and actual < expected
    if op == "lte":
        return actual is not None and actual <= expected
    raise ValueError(f"unsupported operator: {op}")


def within_cooldown(
    *, last_triggered_at: datetime | None, cooldown_seconds: int, now: datetime
) -> bool:
    if last_triggered_at is None:
        return False
    cooldown_until = last_triggered_at + timedelta(seconds=max(0, cooldown_seconds))
    return now < cooldown_until


async def _evaluate_custom_condition(
    db: AsyncSession, tenant_id: str, condition: dict
) -> list[dict]:
    metric = condition.get("metric")
    op = condition.get("op")
    expected = condition.get("value")
    if not metric or not op:
        raise ValueError("custom condition requires metric and op")

    if metric == "open_kev_exposures":
        actual = await db.scalar(
            select(func.count(AssetExposure.id))
            .join(Asset, Asset.id == AssetExposure.asset_id)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(Asset.tenant_id == tenant_id, AssetExposure.resolved_at.is_(None))
            .where(Vulnerability.is_kev.is_(True))
        )
    elif metric == "stale_agents":
        actual = await db.scalar(
            select(func.count(Agent.id)).where(
                Agent.tenant_id == tenant_id,
                Agent.status == AgentStatus.STALE,
            )
        )
    else:
        raise ValueError(f"unsupported custom metric: {metric}")

    if _safe_compare(actual, op, expected):
        return [{"metric": metric, "actual": actual, "expected": expected, "op": op}]
    return []


async def _trigger_rows_for_rule(db: AsyncSession, rule: AlertRule) -> list[dict[str, Any]]:
    tenant_id = rule.tenant_id
    condition = rule.condition or {}

    if rule.trigger_type == AlertTriggerType.KEV_EXPOSURE:
        rows = (
            await db.execute(
                select(AssetExposure.id, AssetExposure.vulnerability_id, AssetExposure.asset_id)
                .join(Asset, Asset.id == AssetExposure.asset_id)
                .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
                .where(Asset.tenant_id == tenant_id, AssetExposure.resolved_at.is_(None))
                .where(Vulnerability.is_kev.is_(True))
            )
        ).all()
        return [
            {
                "type": "kev_exposure",
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "exposure_id": exposure_id,
                "source": "asset_exposures",
            }
            for exposure_id, vulnerability_id, asset_id in rows
        ]

    if rule.trigger_type == AlertTriggerType.IOC_SIGHTING:
        rows = (
            await db.execute(
                select(Indicator.id, Indicator.indicator_type, Indicator.value)
                .where(Indicator.verdict.in_(["malicious", "suspicious"]))
                .limit(1000)
            )
        ).all()
        return [
            {
                "type": "ioc_sighting",
                "indicator_id": indicator_id,
                "indicator_type": indicator_type,
                "value": value,
                "source": "indicators",
            }
            for indicator_id, indicator_type, value in rows
        ]

    if rule.trigger_type == AlertTriggerType.AGENT_STALE:
        rows = (
            await db.execute(
                select(Agent.id, Agent.last_heartbeat_at).where(
                    Agent.tenant_id == tenant_id,
                    Agent.status == AgentStatus.STALE,
                )
            )
        ).all()
        return [
            {
                "type": "agent_stale",
                "agent_id": agent_id,
                "last_heartbeat_at": last_heartbeat_at,
                "source": "agents",
            }
            for agent_id, last_heartbeat_at in rows
        ]

    if rule.trigger_type == AlertTriggerType.RANSOMWARE_RELEVANCE:
        since_days = int(condition.get("since_days", 30))
        cutoff = datetime.now(UTC) - timedelta(days=since_days)
        rows = (
            await db.execute(
                select(RansomwareVictim.id, RansomwareVictim.group_name, RansomwareVictim.domain)
                .where(RansomwareVictim.discovered_at >= cutoff)
                .limit(1000)
            )
        ).all()
        return [
            {
                "type": "ransomware_relevance",
                "victim_id": victim_id,
                "group": group,
                "domain": domain,
                "source": "ransomware_victims",
            }
            for victim_id, group, domain in rows
        ]

    if rule.trigger_type == AlertTriggerType.FEED_DEGRADED:
        rows = (
            await db.execute(
                select(SourceRun.source, SourceRun.status)
                .where(SourceRun.status.in_([RunStatus.FAILED, RunStatus.PARTIAL]))
                .limit(1000)
            )
        ).all()
        return [
            {
                "type": "feed_degraded",
                "source": source,
                "run_status": status.value if hasattr(status, "value") else str(status),
                "provenance": {"table": "source_runs", "source": source},
            }
            for source, status in rows
        ]

    if rule.trigger_type == AlertTriggerType.CUSTOM:
        return await _evaluate_custom_condition(db, tenant_id, condition)

    return []


async def _create_alert_dedup(db: AsyncSession, rule: AlertRule, fp: str, evidence: dict) -> bool:
    existing = (
        await db.execute(
            select(Alert.id).where(
                Alert.tenant_id == rule.tenant_id,
                Alert.rule_id == rule.id,
                Alert.fingerprint == fp,
                Alert.status == "open",
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False

    try:
        async with db.begin_nested():
            db.add(
                Alert(
                    tenant_id=rule.tenant_id,
                    rule_id=rule.id,
                    fingerprint=fp,
                    status="open",
                    title=f"{rule.trigger_type.value}: {rule.name}",
                    detail=evidence,
                )
            )
            await db.flush()
    except IntegrityError:
        return False
    return True


async def evaluate_alert_rules(
    db: AsyncSession,
    *,
    triggered_by: str,
    tenant_id: str | None = None,
    rule_id: int | None = None,
) -> AlertEvaluationRun:
    started = datetime.now(UTC)
    run = AlertEvaluationRun(
        tenant_id=tenant_id,
        triggered_by=triggered_by,
        status=RunStatus.RUNNING,
        started_at=started,
    )
    db.add(run)
    await db.flush()

    stmt = select(AlertRule).where(AlertRule.enabled.is_(True))
    if tenant_id:
        stmt = stmt.where(AlertRule.tenant_id == tenant_id)
    if rule_id:
        stmt = stmt.where(AlertRule.id == rule_id)

    rules = (await db.execute(stmt.order_by(AlertRule.tenant_id, AlertRule.id))).scalars().all()

    outcomes: list[RuleOutcome] = []
    triggered_total = 0
    failed_rules = 0

    for rule in rules:
        try:
            rows = await _trigger_rows_for_rule(db, rule)
            triggered = 0
            skipped = 0
            for row in rows:
                fp = _fingerprint(rule.id, row)
                history = (
                    await db.execute(
                        select(AlertHistory).where(
                            AlertHistory.tenant_id == rule.tenant_id,
                            AlertHistory.rule_id == rule.id,
                            AlertHistory.fingerprint == fp,
                        )
                    )
                ).scalar_one_or_none()

                now = datetime.now(UTC)
                if history is not None and within_cooldown(
                    last_triggered_at=history.last_triggered_at,
                    cooldown_seconds=rule.cooldown_seconds,
                    now=now,
                ):
                    skipped += 1
                    continue

                created = await _create_alert_dedup(db, rule, fp, row)
                if created:
                    triggered += 1
                    triggered_total += 1

                if history is None:
                    history = AlertHistory(
                        tenant_id=rule.tenant_id,
                        rule_id=rule.id,
                        fingerprint=fp,
                    )
                    db.add(history)

                history.state = "triggered" if created else "deduped"
                history.last_triggered_at = now
                history.last_error = None
                history.evidence = row

            outcomes.append(
                RuleOutcome(
                    rule_id=rule.id,
                    status="ok",
                    triggered=triggered,
                    skipped=skipped,
                )
            )
        except Exception as exc:  # noqa: BLE001
            failed_rules += 1
            outcomes.append(RuleOutcome(rule_id=rule.id, status="error", error=str(exc)))

            db.add(
                AlertHistory(
                    tenant_id=rule.tenant_id,
                    rule_id=rule.id,
                    fingerprint=_fingerprint(
                        rule.id,
                        {
                            "error": str(exc),
                            "at": datetime.now(UTC).isoformat(),
                        },
                    ),
                    state="error",
                    last_triggered_at=datetime.now(UTC),
                    last_error=str(exc),
                    evidence={"error": str(exc)},
                )
            )

    run.evaluated_rules = len(rules)
    run.triggered_alerts = triggered_total
    run.failed_rules = failed_rules
    run.finished_at = datetime.now(UTC)
    run.status = RunStatus.PARTIAL if failed_rules else RunStatus.SUCCESS
    run.detail = {
        "outcomes": [
            {
                "rule_id": o.rule_id,
                "status": o.status,
                "triggered": o.triggered,
                "skipped": o.skipped,
                "error": o.error,
            }
            for o in outcomes
        ]
    }
    await db.flush()
    return run
