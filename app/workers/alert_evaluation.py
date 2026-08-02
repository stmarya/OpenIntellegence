"""Bounded, tenant-safe alert rule evaluation with cooldown aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.alert_models import Alert, AlertRule, Sighting
from app.db.models import Agent, Asset, AssetExposure, RunStatus, SourceRun, Vulnerability
from app.services.alerting import alert_fingerprint

MAX_RULE_RESULTS = 100
SUPPORTED_TRIGGERS = frozenset({"ioc_sighting", "agent_stale", "kev_exposure", "ransomware_relevance", "feed_degraded"})


@dataclass(frozen=True)
class AlertCandidate:
    title: str
    summary: str
    severity: str
    entity_type: str | None
    entity_id: str | None
    payload: dict


class AlertEvaluationWorker:
    """Evaluates persisted rules without running arbitrary expressions."""

    async def evaluate(self, session: AsyncSession, now: datetime) -> int:
        rules = (await session.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))).scalars().all()
        emitted = 0
        for rule in rules:
            if rule.trigger_type not in SUPPORTED_TRIGGERS:
                continue
            for candidate in await self._candidates(session, rule, now):
                await self._aggregate(session, rule, candidate, now)
                emitted += 1
        return emitted

    async def _candidates(self, session: AsyncSession, rule: AlertRule, now: datetime) -> list[AlertCandidate]:
        if rule.trigger_type == "ioc_sighting":
            return await self._ioc_sightings(session, rule, now)
        if rule.trigger_type == "agent_stale":
            return await self._stale_agents(session, rule, now)
        if rule.trigger_type == "kev_exposure":
            return await self._kev_exposures(session, rule)
        if rule.trigger_type == "ransomware_relevance":
            return await self._ransomware_sightings(session, rule)
        return await self._feed_health(session, rule)

    async def _ioc_sightings(self, session: AsyncSession, rule: AlertRule, now: datetime) -> list[AlertCandidate]:
        minutes = max(1, min(int((rule.condition or {}).get("lookback_minutes", 60)), 10080))
        rows = (await session.execute(select(Sighting).where(Sighting.tenant_id == rule.tenant_id, Sighting.observed_at >= now - timedelta(minutes=minutes)).order_by(Sighting.observed_at.desc()).limit(MAX_RULE_RESULTS))).scalars().all()
        grouped: dict[tuple[str, str], list[Sighting]] = {}
        for row in rows:
            grouped.setdefault((row.entity_type, row.entity_id), []).append(row)
        minimum = max(1, min(int((rule.condition or {}).get("min_count", 1)), MAX_RULE_RESULTS))
        return [AlertCandidate(f"IOC sightings for {kind}:{value}", f"{len(items)} tenant sightings in {minutes} minutes.", rule.severity, kind, value, {"rule_type": rule.trigger_type, "matched_count": len(items), "truncated": len(rows) == MAX_RULE_RESULTS}) for (kind, value), items in grouped.items() if len(items) >= minimum]

    async def _stale_agents(self, session: AsyncSession, rule: AlertRule, now: datetime) -> list[AlertCandidate]:
        minutes = max(1, min(int((rule.condition or {}).get("stale_minutes", 15)), 43200))
        rows = (await session.execute(select(Agent).where(Agent.tenant_id == rule.tenant_id, or_(Agent.last_heartbeat_at.is_(None), Agent.last_heartbeat_at < now - timedelta(minutes=minutes))).limit(MAX_RULE_RESULTS))).scalars().all()
        return [AlertCandidate(f"Stale endpoint agent {row.id}", f"Heartbeat exceeds {minutes} minute threshold.", rule.severity, "agent", row.id, {"rule_type": rule.trigger_type, "stale_minutes": minutes, "truncated": len(rows) == MAX_RULE_RESULTS}) for row in rows]

    async def _kev_exposures(self, session: AsyncSession, rule: AlertRule) -> list[AlertCandidate]:
        rows = (await session.execute(select(AssetExposure, Asset, Vulnerability).join(Asset, Asset.id == AssetExposure.asset_id).join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id).where(Asset.tenant_id == rule.tenant_id, AssetExposure.resolved_at.is_(None), Vulnerability.is_kev.is_(True)).limit(MAX_RULE_RESULTS))).all()
        return [AlertCandidate(f"KEV exposure on {asset.hostname}", "Tenant asset has an unresolved known-exploited vulnerability.", rule.severity, "asset", asset.id, {"rule_type": rule.trigger_type, "truncated": len(rows) == MAX_RULE_RESULTS}) for _, asset, _ in rows]

    async def _ransomware_sightings(self, session: AsyncSession, rule: AlertRule) -> list[AlertCandidate]:
        rows = (await session.execute(select(Sighting).where(Sighting.tenant_id == rule.tenant_id).limit(MAX_RULE_RESULTS))).scalars().all()
        return [AlertCandidate(f"Ransomware-relevant sighting {row.entity_type}:{row.entity_id}", "A tenant sighting carries ransomware relevance.", rule.severity, row.entity_type, row.entity_id, {"rule_type": rule.trigger_type, "truncated": len(rows) == MAX_RULE_RESULTS}) for row in rows if isinstance(row.context, dict) and row.context.get("ransomware_relevant") is True]

    async def _feed_health(self, session: AsyncSession, rule: AlertRule) -> list[AlertCandidate]:
        # SourceRun is global. Deliberately expose only source + status, never id, timestamps, error text, or run counts.
        rows = (await session.execute(select(SourceRun.source, SourceRun.status).where(SourceRun.status.in_([RunStatus.FAILED, RunStatus.PARTIAL])).distinct().limit(MAX_RULE_RESULTS))).all()
        return [AlertCandidate(f"Intelligence source {source} is degraded", "A global source-health summary indicates degraded availability; no tenant data is asserted.", rule.severity, "source_health", str(source), {"rule_type": rule.trigger_type, "health_scope": "global", "source": str(source), "status": str(status)}) for source, status in rows]

    async def _aggregate(self, session: AsyncSession, rule: AlertRule, candidate: AlertCandidate, now: datetime) -> None:
        cutoff = now - timedelta(minutes=rule.cooldown_minutes)
        active = (await session.execute(select(Alert).where(Alert.tenant_id == rule.tenant_id, Alert.rule_id == rule.id, Alert.entity_type == candidate.entity_type, Alert.entity_id == candidate.entity_id, Alert.last_triggered_at >= cutoff).order_by(Alert.last_triggered_at.desc()).with_for_update())).scalars().first()
        if active is not None:
            active.occurrences += 1
            active.last_triggered_at = now
            active.payload = candidate.payload
            return
        fingerprint = alert_fingerprint(rule.tenant_id, rule_id=rule.id, entity_type=candidate.entity_type, entity_id=candidate.entity_id, severity=candidate.severity, bucket=now)
        item = Alert(tenant_id=rule.tenant_id, rule_id=rule.id, fingerprint=fingerprint, title=candidate.title, summary=candidate.summary, severity=candidate.severity, entity_type=candidate.entity_type, entity_id=candidate.entity_id, risk_score=None, payload=candidate.payload, first_triggered_at=now, last_triggered_at=now)
        try:
            async with session.begin_nested():
                session.add(item)
                await session.flush()
        except IntegrityError:
            existing = (await session.execute(select(Alert).where(Alert.tenant_id == rule.tenant_id, Alert.fingerprint == fingerprint).with_for_update())).scalar_one()
            existing.occurrences += 1
            existing.last_triggered_at = now
            existing.payload = candidate.payload
