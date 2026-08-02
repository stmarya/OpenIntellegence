"""Tenant-scoped alert-rule evaluator worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.alert_models import Alert, AlertRule, Sighting
from app.db.base import get_session_factory
from app.db.models import Agent, Asset, AssetExposure, Vulnerability

log = structlog.get_logger(__name__)

SUPPORTED_TRIGGER_TYPES = {
    "ioc_sighting",
    "agent_stale",
    "kev_exposure",
    "ransomware_relevance",
    "feed_degraded",
}


@dataclass(frozen=True)
class AlertCandidate:
    entity_type: str | None
    entity_id: str | None
    title: str
    summary: str | None
    severity: str
    risk_score: int | None
    observed_at: datetime
    matched_factors: dict[str, Any]
    evidence: list[dict[str, Any]]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class RuleEvaluation:
    candidates: list[AlertCandidate]
    skip_reason: str | None = None


class AlertEvaluationWorker:
    def __init__(
        self,
        settings: Settings,
        *,
        batch_size: int = 50,
    ) -> None:
        self.settings = settings
        self.batch_size = max(1, batch_size)

    async def claim_rules(self, session: AsyncSession, limit: int | None = None) -> list[AlertRule]:
        stmt = (
            select(AlertRule)
            .where(AlertRule.enabled.is_(True))
            .order_by(AlertRule.created_at)
            .limit(limit or self.batch_size)
            .with_for_update(skip_locked=True)
        )
        return (await session.execute(stmt)).scalars().all()

    async def run_once(self) -> dict[str, int]:
        counts = {"processed": 0, "created": 0, "aggregated": 0, "skipped": 0, "errors": 0}
        factory = get_session_factory()
        async with factory() as session:
            rules = await self.claim_rules(session)
            now = datetime.now(UTC)
            for rule in rules:
                counts["processed"] += 1
                if not rule.enabled:
                    counts["skipped"] += 1
                    log.info("alert.rule_skipped", rule_id=rule.id, reason="rule_disabled")
                    continue
                try:
                    evaluation = await self.evaluate_rule(session, rule, now)
                except Exception:
                    counts["errors"] += 1
                    log.exception(
                        "alert.rule_evaluation_failed",
                        tenant_id=rule.tenant_id,
                        rule_id=rule.id,
                        trigger_type=rule.trigger_type,
                    )
                    continue
                if evaluation.skip_reason:
                    counts["skipped"] += 1
                    log.info(
                        "alert.rule_skipped",
                        tenant_id=rule.tenant_id,
                        rule_id=rule.id,
                        trigger_type=rule.trigger_type,
                        reason=evaluation.skip_reason,
                    )
                    continue
                for candidate in evaluation.candidates:
                    status = await self.upsert_alert(session, rule, candidate, now)
                    counts[status] += 1

            await session.commit()

        log.info("alert.worker_run_complete", **counts)
        return counts

    async def evaluate_rule(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> RuleEvaluation:
        if rule.trigger_type == "custom":
            return RuleEvaluation([], skip_reason="unsupported_custom_trigger")
        if rule.trigger_type not in SUPPORTED_TRIGGER_TYPES:
            return RuleEvaluation([], skip_reason="unsupported_trigger_type")

        if rule.trigger_type == "ioc_sighting":
            return RuleEvaluation(await self.match_ioc_sighting(session, rule, now))
        if rule.trigger_type == "agent_stale":
            return RuleEvaluation(await self.match_agent_stale(session, rule, now))
        if rule.trigger_type == "kev_exposure":
            return RuleEvaluation(await self.match_kev_exposure(session, rule, now))
        if rule.trigger_type == "ransomware_relevance":
            return RuleEvaluation(await self.match_ransomware_relevance(session, rule, now))
        return await self.match_feed_degraded(session, rule, now)

    async def upsert_alert(
        self, session: AsyncSession, rule: AlertRule, candidate: AlertCandidate, now: datetime
    ) -> str:
        cooldown_start = now - timedelta(minutes=max(1, rule.cooldown_minutes))
        recent_stmt = (
            select(Alert)
            .where(
                Alert.tenant_id == rule.tenant_id,
                Alert.rule_id == rule.id,
                Alert.entity_type == candidate.entity_type,
                Alert.entity_id == candidate.entity_id,
                Alert.last_triggered_at >= cooldown_start,
            )
            .order_by(Alert.last_triggered_at.desc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        existing = (await session.execute(recent_stmt)).scalar_one_or_none()
        if existing is not None:
            existing.occurrences += 1
            existing.last_triggered_at = now
            existing.payload = self._alert_payload(rule, candidate, now)
            if candidate.risk_score is not None:
                existing.risk_score = max(existing.risk_score or 0, candidate.risk_score)
            return "aggregated"

        fingerprint = self._fingerprint(
            rule.tenant_id, rule.id, candidate, now, rule.cooldown_minutes
        )
        item = Alert(
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            fingerprint=fingerprint,
            title=candidate.title,
            summary=candidate.summary,
            severity=candidate.severity,
            entity_type=candidate.entity_type,
            entity_id=candidate.entity_id,
            risk_score=candidate.risk_score,
            payload=self._alert_payload(rule, candidate, now),
            first_triggered_at=now,
            last_triggered_at=now,
        )
        try:
            async with session.begin_nested():
                session.add(item)
                await session.flush()
            return "created"
        except IntegrityError:
            existing = (
                await session.execute(
                    select(Alert)
                    .where(Alert.tenant_id == rule.tenant_id, Alert.fingerprint == fingerprint)
                    .with_for_update()
                )
            ).scalar_one()
            existing.occurrences += 1
            existing.last_triggered_at = now
            existing.payload = self._alert_payload(rule, candidate, now)
            return "aggregated"

    async def fetch_ioc_sightings(
        self, session: AsyncSession, tenant_id: str, condition: dict[str, Any], now: datetime
    ) -> list[Sighting]:
        lookback = max(1, int(condition.get("lookback_minutes", 60)))
        limit = min(500, max(1, int(condition.get("limit", 100))))
        cutoff = now - timedelta(minutes=lookback)

        stmt = select(Sighting).where(
            Sighting.tenant_id == tenant_id, Sighting.observed_at >= cutoff
        )
        if entity_type := condition.get("entity_type"):
            stmt = stmt.where(Sighting.entity_type == str(entity_type))
        if source := condition.get("source"):
            stmt = stmt.where(Sighting.source == str(source))
        if (min_confidence := condition.get("min_confidence")) is not None:
            stmt = stmt.where(Sighting.confidence >= int(min_confidence))

        rows = (
            (await session.execute(stmt.order_by(Sighting.observed_at.desc()).limit(limit)))
            .scalars()
            .all()
        )
        return rows

    async def match_ioc_sighting(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[AlertCandidate]:
        sightings = await self.fetch_ioc_sightings(
            session, rule.tenant_id, rule.condition or {}, now
        )
        grouped: dict[tuple[str, str], list[Sighting]] = {}
        for sighting in sightings:
            grouped.setdefault((sighting.entity_type, sighting.entity_id), []).append(sighting)

        candidates: list[AlertCandidate] = []
        for (entity_type, entity_id), rows in grouped.items():
            latest = max(rows, key=lambda row: row.observed_at)
            candidates.append(
                AlertCandidate(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    title=f"IOC sighting detected: {entity_type}:{entity_id}",
                    summary=f"{len(rows)} matching sighting(s) for {entity_type}:{entity_id}.",
                    severity=rule.severity,
                    risk_score=None,
                    observed_at=latest.observed_at,
                    matched_factors={
                        "trigger_type": "ioc_sighting",
                        "match_count": len(rows),
                        "source": sorted({row.source for row in rows}),
                    },
                    evidence=[
                        {
                            "record_type": "sighting",
                            "record_id": row.id,
                            "observed_at": row.observed_at.isoformat(),
                            "source": row.source,
                        }
                        for row in rows
                    ],
                    provenance={
                        "sources": sorted({row.source for row in rows}),
                        "record_type": "sighting",
                    },
                )
            )
        return candidates

    async def fetch_stale_agents(
        self, session: AsyncSession, tenant_id: str, condition: dict[str, Any], now: datetime
    ) -> list[Agent]:
        stale_after_minutes = int(
            condition.get(
                "stale_after_minutes",
                (
                    self.settings.agent_heartbeat_interval_seconds
                    * self.settings.agent_stale_after_missed
                )
                // 60,
            )
        )
        stale_after_minutes = max(1, stale_after_minutes)
        cutoff = now - timedelta(minutes=stale_after_minutes)

        statuses = condition.get("statuses")
        status_values = [str(status) for status in statuses] if isinstance(statuses, list) else []
        stale_status = ["stale", "service_stopped", "unreachable", "cert_expired"]

        status_filter = status_values or stale_status
        stmt = select(Agent).where(
            Agent.tenant_id == tenant_id,
            or_(Agent.status.in_(status_filter), Agent.last_heartbeat_at <= cutoff),
        )
        return (
            (await session.execute(stmt.order_by(Agent.last_heartbeat_at.asc().nulls_first())))
            .scalars()
            .all()
        )

    async def match_agent_stale(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[AlertCandidate]:
        agents = await self.fetch_stale_agents(session, rule.tenant_id, rule.condition or {}, now)
        candidates: list[AlertCandidate] = []
        for agent in agents:
            observed_at = agent.last_heartbeat_at or agent.updated_at
            candidates.append(
                AlertCandidate(
                    entity_type="agent",
                    entity_id=agent.id,
                    title=f"Agent stale: {agent.id}",
                    summary=(
                        f"Agent status={agent.status} "
                        f"with last heartbeat {agent.last_heartbeat_at}."
                    ),
                    severity=rule.severity,
                    risk_score=None,
                    observed_at=observed_at,
                    matched_factors={"trigger_type": "agent_stale", "status": str(agent.status)},
                    evidence=[
                        {
                            "record_type": "agent",
                            "record_id": agent.id,
                            "observed_at": observed_at.isoformat(),
                            "status": str(agent.status),
                        }
                    ],
                    provenance={"sources": ["endpoint_agent"], "record_type": "agent"},
                )
            )
        return candidates

    async def fetch_kev_exposures(
        self, session: AsyncSession, tenant_id: str, condition: dict[str, Any]
    ) -> list[tuple[AssetExposure, Asset, Vulnerability]]:
        min_cvss = float(condition.get("min_cvss", 0.0))
        stmt = (
            select(AssetExposure, Asset, Vulnerability)
            .join(Asset, Asset.id == AssetExposure.asset_id)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(
                Asset.tenant_id == tenant_id,
                AssetExposure.resolved_at.is_(None),
                Vulnerability.is_kev.is_(True),
                or_(Vulnerability.cvss_score.is_(None), Vulnerability.cvss_score >= min_cvss),
            )
            .order_by(AssetExposure.detected_at.desc())
        )
        return [tuple(row) for row in (await session.execute(stmt)).all()]

    async def match_kev_exposure(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[AlertCandidate]:
        rows = await self.fetch_kev_exposures(session, rule.tenant_id, rule.condition or {})
        grouped: dict[str, list[tuple[AssetExposure, Asset, Vulnerability]]] = {}
        for exposure, asset, vuln in rows:
            grouped.setdefault(asset.id, []).append((exposure, asset, vuln))

        candidates: list[AlertCandidate] = []
        for asset_id, matches in grouped.items():
            newest = max(matches, key=lambda item: item[0].detected_at)
            known_scores = [item[2].cvss_score for item in matches if item[2].cvss_score is not None]
            max_cvss: float | None = max(known_scores) if known_scores else None
            candidates.append(
                AlertCandidate(
                    entity_type="asset",
                    entity_id=asset_id,
                    title=f"KEV exposure on asset {newest[1].hostname}",
                    summary=(
                        f"{len(matches)} KEV exposure(s) detected "
                        f"for asset {newest[1].hostname}."
                    ),
                    severity=rule.severity,
                    risk_score=min(100, int(max_cvss * 10)) if max_cvss is not None else None,
                    observed_at=newest[0].detected_at,
                    matched_factors={
                        "trigger_type": "kev_exposure",
                        "match_count": len(matches),
                        "highest_cvss": max_cvss,
                    },
                    evidence=[
                        {
                            "record_type": "asset_exposure",
                            "record_id": exposure.id,
                            "observed_at": exposure.detected_at.isoformat(),
                            "asset_id": asset.id,
                            "vulnerability_id": vuln.id,
                            "cve_id": vuln.cve_id,
                        }
                        for exposure, asset, vuln in matches
                    ],
                    provenance={
                        "sources": ["endpoint_agent", "cisa_kev", "nvd"],
                        "record_type": "asset_exposure",
                    },
                )
            )
        return candidates

    async def fetch_ransomware_sightings(
        self, session: AsyncSession, tenant_id: str, condition: dict[str, Any], now: datetime
    ) -> list[Sighting]:
        lookback_days = max(1, int(condition.get("lookback_days", 7)))
        entity_types = condition.get("entity_types")
        allowed_types = (
            [str(value) for value in entity_types]
            if isinstance(entity_types, list)
            else ["ransomware_victim"]
        )

        cutoff = now - timedelta(days=lookback_days)
        stmt = (
            select(Sighting)
            .where(
                Sighting.tenant_id == tenant_id,
                Sighting.entity_type.in_(allowed_types),
                Sighting.observed_at >= cutoff,
            )
            .order_by(Sighting.observed_at.desc())
        )
        return (await session.execute(stmt)).scalars().all()

    async def match_ransomware_relevance(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> list[AlertCandidate]:
        sightings = await self.fetch_ransomware_sightings(
            session, rule.tenant_id, rule.condition or {}, now
        )
        grouped: dict[tuple[str, str], list[Sighting]] = {}
        for sighting in sightings:
            grouped.setdefault((sighting.entity_type, sighting.entity_id), []).append(sighting)

        candidates: list[AlertCandidate] = []
        for (entity_type, entity_id), rows in grouped.items():
            latest = max(rows, key=lambda row: row.observed_at)
            candidates.append(
                AlertCandidate(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    title=f"Ransomware relevance: {entity_type}:{entity_id}",
                    summary=f"{len(rows)} ransomware-relevant sighting(s) observed.",
                    severity=rule.severity,
                    risk_score=None,
                    observed_at=latest.observed_at,
                    matched_factors={
                        "trigger_type": "ransomware_relevance",
                        "match_count": len(rows),
                    },
                    evidence=[
                        {
                            "record_type": "sighting",
                            "record_id": row.id,
                            "observed_at": row.observed_at.isoformat(),
                            "source": row.source,
                        }
                        for row in rows
                    ],
                    provenance={
                        "sources": sorted({row.source for row in rows}),
                        "record_type": "sighting",
                    },
                )
            )
        return candidates

    async def fetch_feed_window_data(
        self,
        session: AsyncSession,
        tenant_id: str,
        source: str,
        now: datetime,
        recent_minutes: int,
        baseline_hours: int,
    ) -> tuple[int, int, list[str], list[str]]:
        recent_cutoff = now - timedelta(minutes=recent_minutes)
        baseline_start = recent_cutoff - timedelta(hours=baseline_hours)

        recent_count_stmt = select(func.count(Sighting.id)).where(
            Sighting.tenant_id == tenant_id,
            Sighting.source == source,
            Sighting.observed_at >= recent_cutoff,
        )
        baseline_count_stmt = select(func.count(Sighting.id)).where(
            Sighting.tenant_id == tenant_id,
            Sighting.source == source,
            Sighting.observed_at >= baseline_start,
            Sighting.observed_at < recent_cutoff,
        )

        recent_ids_stmt = (
            select(Sighting.id)
            .where(
                Sighting.tenant_id == tenant_id,
                Sighting.source == source,
                Sighting.observed_at >= recent_cutoff,
            )
            .limit(20)
        )
        baseline_ids_stmt = (
            select(Sighting.id)
            .where(
                Sighting.tenant_id == tenant_id,
                Sighting.source == source,
                Sighting.observed_at >= baseline_start,
                Sighting.observed_at < recent_cutoff,
            )
            .limit(20)
        )

        recent_count = int((await session.execute(recent_count_stmt)).scalar() or 0)
        baseline_count = int((await session.execute(baseline_count_stmt)).scalar() or 0)
        recent_ids = [value for value in (await session.execute(recent_ids_stmt)).scalars().all()]
        baseline_ids = [
            value for value in (await session.execute(baseline_ids_stmt)).scalars().all()
        ]
        return recent_count, baseline_count, recent_ids, baseline_ids

    async def match_feed_degraded(
        self, session: AsyncSession, rule: AlertRule, now: datetime
    ) -> RuleEvaluation:
        source = str((rule.condition or {}).get("source") or "").strip()
        if not source:
            return RuleEvaluation([], skip_reason="feed_degraded_missing_source")

        recent_minutes = max(1, int((rule.condition or {}).get("recent_minutes", 60)))
        baseline_hours = max(1, int((rule.condition or {}).get("baseline_hours", 24)))
        min_baseline_events = max(1, int((rule.condition or {}).get("min_baseline_events", 1)))
        degradation_ratio = max(0.0, float((rule.condition or {}).get("degradation_ratio", 0.2)))

        recent_count, baseline_count, recent_ids, baseline_ids = await self.fetch_feed_window_data(
            session, rule.tenant_id, source, now, recent_minutes, baseline_hours
        )

        if baseline_count < min_baseline_events:
            return RuleEvaluation([])

        expected_recent = baseline_count * (recent_minutes / float(baseline_hours * 60))
        threshold = expected_recent * degradation_ratio
        if recent_count > threshold:
            return RuleEvaluation([])

        candidate = AlertCandidate(
            entity_type="feed",
            entity_id=source,
            title=f"Feed degraded: {source}",
            summary=(
                f"Recent events ({recent_count}) are below threshold {threshold:.2f} "
                f"for source {source}."
            ),
            severity=rule.severity,
            risk_score=None,
            observed_at=now,
            matched_factors={
                "trigger_type": "feed_degraded",
                "recent_count": recent_count,
                "baseline_count": baseline_count,
                "expected_recent": expected_recent,
                "threshold": threshold,
            },
            evidence=[
                {"record_type": "sighting", "record_id": value, "window": "recent"}
                for value in recent_ids
            ]
            + [
                {"record_type": "sighting", "record_id": value, "window": "baseline"}
                for value in baseline_ids
            ],
            provenance={"sources": [source], "record_type": "sighting"},
        )
        return RuleEvaluation([candidate])

    def _alert_payload(
        self, rule: AlertRule, candidate: AlertCandidate, now: datetime
    ) -> dict[str, Any]:
        payload = {
            "rule_id": rule.id,
            "trigger_type": rule.trigger_type,
            "matched_factors": candidate.matched_factors,
            "evidence": candidate.evidence,
            "observed_at": candidate.observed_at.isoformat(),
            "evaluated_at": now.isoformat(),
            "provenance": candidate.provenance,
        }
        if rule.auto_create_case:
            payload["case_candidate"] = {
                "requested": True,
                "state": "pending_approval",
                "reason": "auto_create_case_requested_by_rule",
            }
        return payload

    @staticmethod
    def _fingerprint(
        tenant_id: str,
        rule_id: str,
        candidate: AlertCandidate,
        now: datetime,
        cooldown_minutes: int,
    ) -> str:
        period_seconds = max(60, cooldown_minutes * 60)
        epoch_seconds = int(now.timestamp())
        bucket = epoch_seconds - (epoch_seconds % period_seconds)
        raw = "|".join(
            (
                tenant_id,
                rule_id,
                candidate.entity_type or "",
                candidate.entity_id or "",
                candidate.severity,
                str(bucket),
            )
        )
        return sha256(raw.encode()).hexdigest()


async def main() -> None:
    worker = AlertEvaluationWorker(get_settings())
    while True:
        result = await worker.run_once()
        await asyncio.sleep(2 if result["processed"] else 10)


if __name__ == "__main__":
    asyncio.run(main())
