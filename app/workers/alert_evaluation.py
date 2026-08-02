"""Tenant-scoped alert evaluation worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.alert_models import Alert, AlertRule, Sighting
from app.db.base import get_session_factory
from app.db.models import Agent, Asset, AssetExposure, RunStatus, SourceRun, Vulnerability
from app.services.alerting import alert_fingerprint

_SUPPORTED_RULES = {
    "ioc_sighting",
    "agent_stale",
    "kev_exposure",
    "ransomware_relevance",
    "feed_degraded",
}


@dataclass(frozen=True)
class Candidate:
    title: str
    summary: str
    severity: str
    entity_type: str | None
    entity_id: str | None
    risk_score: int | None
    payload: dict


@dataclass(frozen=True)
class EvaluationResult:
    rule_id: str
    trigger_type: str
    candidates: int
    skipped_reason: str | None = None


def _bounded_limit(raw: object, *, default: int, cap: int) -> int:
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        value = default
    return max(1, min(cap, value))


class AlertEvaluationWorker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.last_results: list[EvaluationResult] = []
        self.default_limit = 100
        self.max_limit = 500

    async def _load_rules(self, session: AsyncSession) -> list[AlertRule]:
        stmt = (
            select(AlertRule)
            .where(
                AlertRule.enabled.is_(True),
                AlertRule.trigger_type.in_([*_SUPPORTED_RULES, "custom"]),
            )
            .order_by(AlertRule.created_at.asc())
        )
        return (await session.execute(stmt)).scalars().all()

    async def _evaluate_ioc_sighting(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[Candidate]:
        condition = rule.condition or {}
        lookback = _bounded_limit(condition.get("lookback_minutes"), default=60, cap=10080)
        min_count = _bounded_limit(condition.get("min_count"), default=1, cap=1000)
        limit = _bounded_limit(
            condition.get("max_results"),
            default=self.default_limit,
            cap=self.max_limit,
        )
        since = now - timedelta(minutes=lookback)
        stmt = (
            select(Sighting)
            .where(Sighting.tenant_id == rule.tenant_id, Sighting.observed_at >= since)
            .order_by(Sighting.observed_at.desc())
            .limit(limit + 1)
        )
        rows = (await session.execute(stmt)).scalars().all()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]

        grouped: dict[tuple[str, str], list[Sighting]] = {}
        for row in rows:
            key = (row.entity_type, row.entity_id)
            grouped.setdefault(key, []).append(row)

        candidates: list[Candidate] = []
        for (entity_type, entity_id), matched in grouped.items():
            if len(matched) < min_count:
                continue
            candidates.append(
                Candidate(
                    title=f"IOC sightings for {entity_type}:{entity_id}",
                    summary=f"{len(matched)} sightings observed within {lookback} minutes.",
                    severity=rule.severity,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    risk_score=None,
                    payload={
                        "rule_id": rule.id,
                        "rule_type": rule.trigger_type,
                        "matched_factors": [
                            {
                                "factor": "sighting_count",
                                "value": len(matched),
                                "threshold": min_count,
                            }
                        ],
                        "source_record_ids": [row.id for row in matched],
                        "observed_timestamps": [row.observed_at.isoformat() for row in matched],
                        "provenance_references": [{"type": "table", "name": "sightings"}],
                        "evaluated_at": now.isoformat(),
                        "bounded_result": {"limit": limit, "truncated": truncated},
                    },
                )
            )
        return candidates

    async def _evaluate_agent_stale(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[Candidate]:
        condition = rule.condition or {}
        stale_minutes = _bounded_limit(condition.get("stale_minutes"), default=15, cap=43200)
        limit = _bounded_limit(
            condition.get("max_results"),
            default=self.default_limit,
            cap=self.max_limit,
        )
        cutoff = now - timedelta(minutes=stale_minutes)
        stmt = (
            select(Agent)
            .where(
                Agent.tenant_id == rule.tenant_id,
                or_(Agent.last_heartbeat_at.is_(None), Agent.last_heartbeat_at < cutoff),
            )
            .order_by(Agent.last_heartbeat_at.asc().nulls_first())
            .limit(limit + 1)
        )
        rows = (await session.execute(stmt)).scalars().all()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]

        return [
            Candidate(
                title=f"Stale endpoint agent {row.id}",
                summary=f"Agent heartbeat is stale beyond {stale_minutes} minutes.",
                severity=rule.severity,
                entity_type="agent",
                entity_id=row.id,
                risk_score=70,
                payload={
                    "rule_id": rule.id,
                    "rule_type": rule.trigger_type,
                    "matched_factors": [
                        {
                            "factor": "last_heartbeat_at",
                            "value": (
                                row.last_heartbeat_at.isoformat()
                                if row.last_heartbeat_at
                                else None
                            ),
                        },
                        {"factor": "stale_minutes", "value": stale_minutes},
                    ],
                    "source_record_ids": [row.id],
                    "observed_timestamps": (
                        [row.last_heartbeat_at.isoformat()] if row.last_heartbeat_at else []
                    ),
                    "provenance_references": [{"type": "table", "name": "agents"}],
                    "evaluated_at": now.isoformat(),
                    "bounded_result": {"limit": limit, "truncated": truncated},
                },
            )
            for row in rows
        ]

    async def _evaluate_kev_exposure(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[Candidate]:
        condition = rule.condition or {}
        limit = _bounded_limit(
            condition.get("max_results"),
            default=self.default_limit,
            cap=self.max_limit,
        )
        rows = (
            await session.execute(
                select(AssetExposure, Vulnerability, Asset)
                .join(Asset, Asset.id == AssetExposure.asset_id)
                .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
                .where(
                    Asset.tenant_id == rule.tenant_id,
                    AssetExposure.resolved_at.is_(None),
                    Vulnerability.is_kev.is_(True),
                )
                .order_by(
                    Vulnerability.cvss_score.desc().nulls_last(),
                    AssetExposure.detected_at.desc(),
                )
                .limit(limit + 1)
            )
        ).all()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]

        return [
            Candidate(
                title=f"KEV exposure on {asset.hostname}",
                summary=f"Unresolved KEV exposure {vuln.cve_id} detected on tenant asset.",
                severity=rule.severity,
                entity_type="asset",
                entity_id=asset.id,
                risk_score=None
                if vuln.cvss_score is None
                else max(1, min(100, int(vuln.cvss_score * 10))),
                payload={
                    "rule_id": rule.id,
                    "rule_type": rule.trigger_type,
                    "matched_factors": [
                        {"factor": "kev", "value": True},
                        {"factor": "cvss_score", "value": vuln.cvss_score},
                        {"factor": "exploit_maturity", "value": vuln.exploit_maturity.value},
                    ],
                    "source_record_ids": [exposure.id, vuln.id, asset.id],
                    "observed_timestamps": [exposure.detected_at.isoformat()],
                    "provenance_references": [
                        {"type": "table", "name": "asset_exposures"},
                        {"type": "table", "name": "vulnerabilities"},
                    ],
                    "evaluated_at": now.isoformat(),
                    "bounded_result": {"limit": limit, "truncated": truncated},
                },
            )
            for exposure, vuln, asset in rows
        ]

    async def _evaluate_ransomware_relevance(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[Candidate]:
        condition = rule.condition or {}
        lookback = _bounded_limit(condition.get("lookback_minutes"), default=10080, cap=43200)
        limit = _bounded_limit(
            condition.get("max_results"),
            default=self.default_limit,
            cap=self.max_limit,
        )
        since = now - timedelta(minutes=lookback)
        stmt = (
            select(Sighting)
            .where(Sighting.tenant_id == rule.tenant_id, Sighting.observed_at >= since)
            .order_by(Sighting.observed_at.desc())
            .limit(limit + 1)
        )
        rows = (await session.execute(stmt)).scalars().all()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]

        matches = [
            row
            for row in rows
            if isinstance(row.context, dict) and row.context.get("ransomware_relevant") is True
        ]
        return [
            Candidate(
                title=f"Ransomware-relevant sighting {row.entity_type}:{row.entity_id}",
                summary="Sighting context is marked ransomware-relevant.",
                severity=rule.severity,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                risk_score=80,
                payload={
                    "rule_id": rule.id,
                    "rule_type": rule.trigger_type,
                    "matched_factors": [
                        {"factor": "ransomware_relevant", "value": True},
                        {"factor": "source", "value": row.source},
                    ],
                    "source_record_ids": [row.id],
                    "observed_timestamps": [row.observed_at.isoformat()],
                    "provenance_references": [{"type": "table", "name": "sightings"}],
                    "evaluated_at": now.isoformat(),
                    "bounded_result": {"limit": limit, "truncated": truncated},
                },
            )
            for row in matches
        ]

    async def _evaluate_feed_degraded(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[Candidate]:
        condition = rule.condition or {}
        lookback = _bounded_limit(condition.get("lookback_minutes"), default=240, cap=10080)
        since = now - timedelta(minutes=lookback)
        rows = (
            await session.execute(
                select(SourceRun)
                .where(SourceRun.started_at >= since)
                .order_by(SourceRun.started_at.desc())
                .limit(self.max_limit)
            )
        ).scalars().all()
        degraded = [run for run in rows if run.status in {RunStatus.FAILED, RunStatus.PARTIAL}]
        if not degraded:
            return []
        return [
            Candidate(
                title="Threat-feed degradation detected",
                summary=f"{len(degraded)} feed run(s) are failed/partial in the lookback window.",
                severity=rule.severity,
                entity_type="feed",
                entity_id="degraded",
                risk_score=None,
                payload={
                    "rule_id": rule.id,
                    "rule_type": rule.trigger_type,
                    "matched_factors": [
                        {"factor": "degraded_runs", "value": len(degraded)},
                        {"factor": "lookback_minutes", "value": lookback},
                    ],
                    "source_record_ids": [run.id for run in degraded],
                    "observed_timestamps": [run.started_at.isoformat() for run in degraded],
                    "provenance_references": [{"type": "table", "name": "source_runs"}],
                    "evaluated_at": now.isoformat(),
                    "bounded_result": {"limit": self.max_limit, "truncated": False},
                },
            )
        ]

    async def _lock_existing_alert(
        self, session: AsyncSession, tenant_id: str, fingerprint: str
    ) -> Alert:
        return (
            await session.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.fingerprint == fingerprint)
                .with_for_update()
            )
        ).scalar_one()

    async def _insert_alert(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        rule_id: str,
        fingerprint: str,
        candidate: Candidate,
        now: datetime,
    ) -> Alert:
        item = Alert(
            tenant_id=tenant_id,
            rule_id=rule_id,
            fingerprint=fingerprint,
            title=candidate.title,
            summary=candidate.summary,
            severity=candidate.severity,
            entity_type=candidate.entity_type,
            entity_id=candidate.entity_id,
            risk_score=candidate.risk_score,
            payload=candidate.payload,
            first_triggered_at=now,
            last_triggered_at=now,
        )
        async with session.begin_nested():
            session.add(item)
            await session.flush()
        return item

    async def _apply_candidate(
        self, session: AsyncSession, rule: AlertRule, candidate: Candidate, now: datetime
    ) -> None:
        fingerprint = alert_fingerprint(
            rule.tenant_id,
            rule_id=rule.id,
            entity_type=candidate.entity_type,
            entity_id=candidate.entity_id,
            severity=candidate.severity,
            bucket=now,
        )
        try:
            await self._insert_alert(
                session,
                tenant_id=rule.tenant_id,
                rule_id=rule.id,
                fingerprint=fingerprint,
                candidate=candidate,
                now=now,
            )
            return
        except IntegrityError:
            pass

        existing = await self._lock_existing_alert(session, rule.tenant_id, fingerprint)
        existing.occurrences += 1
        existing.last_triggered_at = now
        existing.title = candidate.title
        existing.summary = candidate.summary
        existing.severity = candidate.severity
        existing.entity_type = candidate.entity_type
        existing.entity_id = candidate.entity_id
        existing.risk_score = candidate.risk_score
        existing.payload = candidate.payload
        await session.flush()

    async def _evaluate_rule(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> EvaluationResult:
        if rule.trigger_type == "custom":
            return EvaluationResult(
                rule_id=rule.id,
                trigger_type=rule.trigger_type,
                candidates=0,
                skipped_reason="custom rules are intentionally not executable by the worker",
            )

        if rule.trigger_type == "ioc_sighting":
            candidates = await self._evaluate_ioc_sighting(session, rule, now)
        elif rule.trigger_type == "agent_stale":
            candidates = await self._evaluate_agent_stale(session, rule, now)
        elif rule.trigger_type == "kev_exposure":
            candidates = await self._evaluate_kev_exposure(session, rule, now)
        elif rule.trigger_type == "ransomware_relevance":
            candidates = await self._evaluate_ransomware_relevance(session, rule, now)
        elif rule.trigger_type == "feed_degraded":
            candidates = await self._evaluate_feed_degraded(session, rule, now)
        else:
            return EvaluationResult(
                rule_id=rule.id,
                trigger_type=rule.trigger_type,
                candidates=0,
                skipped_reason="unsupported trigger type",
            )

        for candidate in candidates:
            await self._apply_candidate(session, rule, candidate, now)

        return EvaluationResult(
            rule_id=rule.id,
            trigger_type=rule.trigger_type,
            candidates=len(candidates),
        )

    async def run_once(self) -> int:
        now = datetime.now(UTC)
        results: list[EvaluationResult] = []
        factory = get_session_factory()
        async with factory() as session:
            for rule in await self._load_rules(session):
                results.append(await self._evaluate_rule(session, rule, now))
            await session.commit()
        self.last_results = results
        return sum(result.candidates for result in results)


async def main() -> None:
    worker = AlertEvaluationWorker(get_settings())
    while True:
        count = await worker.run_once()
        await asyncio.sleep(1 if count else 5)


if __name__ == "__main__":
    asyncio.run(main())
