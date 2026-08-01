"""Ingest pipeline: fetch -> normalise -> merge -> persist.

The pipeline is deliberately conservative about failure. A connector that
dies mid-run marks its :class:`SourceRun` as ``failed`` and leaves already
ingested records in place; a run where some records could not be normalised
is marked ``partial``. Both states are visible in the API so the dashboard
can say which feeds contributed to the numbers on screen.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.models import (
    Exploit,
    ExploitMaturity,
    Indicator,
    QuarantinedRecord,
    RansomwareVictim,
    RunStatus,
    SourceRun,
    Vulnerability,
)
from app.ingest.base import (
    Connector,
    ConnectorError,
    EntityKind,
    NormalizedRecord,
    Quarantine,
    build_http_client,
    registry,
)
from app.ingest.normalize import severity_from_cvss

log = structlog.get_logger(__name__)


@dataclass(slots=True)
class RunSummary:
    source: str
    run_id: str
    status: RunStatus
    fetched: int = 0
    ingested: int = 0
    quarantined: int = 0
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


def _merge_sources(existing: list[str] | None, source: str) -> list[str]:
    """Append a source without duplicating it, preserving order."""
    current = list(existing or [])
    if source not in current:
        current.append(source)
    return current


class IngestPipeline:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    async def run(
        self, connector_name: str, *, since: datetime | None = None
    ) -> RunSummary:
        connector_cls = registry.get(connector_name)
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC)

        run = SourceRun(
            id=run_id,
            source=connector_name,
            status=RunStatus.RUNNING,
            started_at=started,
        )
        self.session.add(run)
        await self.session.flush()

        summary = RunSummary(source=connector_name, run_id=run_id, status=RunStatus.RUNNING)

        async with build_http_client(self.settings) as client:
            connector: Connector = connector_cls(self.settings, client)

            if not connector.is_enabled:
                # Missing credentials is a configuration state, not a crash.
                summary.status = RunStatus.FAILED
                summary.error = f"{connector.label} is not configured"
                await self._finish(run, summary)
                return summary

            try:
                async for result in connector.fetch(since=since):
                    summary.fetched += 1
                    if isinstance(result, Quarantine):
                        summary.quarantined += 1
                        self.session.add(
                            QuarantinedRecord(
                                source=result.source,
                                source_run_id=run_id,
                                reason=result.reason,
                                raw_payload=result.raw,
                            )
                        )
                        continue

                    await self._persist(result, run_id)
                    summary.ingested += 1

            except ConnectorError as exc:
                summary.status = RunStatus.FAILED
                summary.error = str(exc)
                log.warning("connector_failed", source=connector_name, error=str(exc))
                await self._finish(run, summary)
                return summary

        summary.status = (
            RunStatus.PARTIAL if summary.quarantined else RunStatus.SUCCESS
        )
        await self._finish(run, summary)
        return summary

    async def _finish(self, run: SourceRun, summary: RunSummary) -> None:
        run.status = summary.status
        run.finished_at = datetime.now(UTC)
        run.records_fetched = summary.fetched
        run.records_ingested = summary.ingested
        run.records_quarantined = summary.quarantined
        run.error_message = summary.error
        await self.session.flush()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist(self, record: NormalizedRecord, run_id: str) -> None:
        match record.kind:
            case EntityKind.VULNERABILITY:
                await self._upsert_vulnerability(record)
            case EntityKind.EXPLOIT:
                await self._upsert_exploit(record, run_id)
            case EntityKind.RANSOMWARE_VICTIM:
                await self._upsert_victim(record, run_id)
            case EntityKind.INDICATOR:
                await self._upsert_indicator(record)
            case _:
                raise ValueError(f"unsupported record kind: {record.kind}")

    async def _upsert_vulnerability(self, record: NormalizedRecord) -> None:
        """Merge a CVE across feeds.

        Fields are merged rather than overwritten: NVD supplies the score,
        CISA KEV supplies vendor/product and the weaponised flag, OSV supplies
        package context. Whoever runs last must not erase the others.
        """
        payload = dict(record.payload)
        cve_id = payload["cve_id"]

        result = await self.session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
        vuln = result.scalar_one_or_none()

        if vuln is None:
            vuln = Vulnerability(cve_id=cve_id, first_seen=record.observed_at)
            self.session.add(vuln)

        for column in (
            "title", "description", "cvss_vector", "vendor", "product",
            "published_at", "last_modified_at", "kev_added_at", "kev_due_at",
        ):
            value = payload.get(column)
            # Never overwrite a known value with a missing one.
            if value is not None:
                setattr(vuln, column, value)

        score = payload.get("cvss_score")
        if score is not None:
            vuln.cvss_score = score
            vuln.severity = severity_from_cvss(score)

        if payload.get("is_kev"):
            vuln.is_kev = True

        if cpes := payload.get("cpe_uris"):
            merged = list(dict.fromkeys([*(vuln.cpe_uris or []), *cpes]))
            vuln.cpe_uris = merged

        # Exploit maturity only ever escalates.
        incoming = payload.get("exploit_maturity")
        if incoming:
            order = [e.value for e in ExploitMaturity]
            if order.index(incoming) > order.index(vuln.exploit_maturity):
                vuln.exploit_maturity = ExploitMaturity(incoming)

        vuln.sources = _merge_sources(vuln.sources, record.source)
        vuln.last_seen = record.observed_at or datetime.now(UTC)

    async def _upsert_exploit(self, record: NormalizedRecord, run_id: str) -> None:
        payload = dict(record.payload)
        external_id = payload["external_id"]

        result = await self.session.execute(
            select(Exploit).where(
                Exploit.source == record.source, Exploit.external_id == external_id
            )
        )
        exploit = result.scalar_one_or_none()
        if exploit is None:
            exploit = Exploit(source=record.source, external_id=external_id)
            self.session.add(exploit)

        exploit.title = payload.get("title") or exploit.title
        exploit.url = payload.get("url") or exploit.url
        exploit.author = payload.get("author") or exploit.author
        exploit.platform = payload.get("platform") or exploit.platform
        exploit.stars = payload.get("stars", exploit.stars)
        exploit.published_at = payload.get("published_at") or exploit.published_at
        exploit.confidence = payload.get("confidence", exploit.confidence)
        exploit.source_run_id = run_id

        # Link to the first CVE we already know about, and escalate its
        # maturity because a public exploit now exists.
        for cve_id in payload.get("cve_ids") or []:
            found = await self.session.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
            vuln = found.scalar_one_or_none()
            if vuln is None:
                continue

            exploit.vulnerability_id = vuln.id
            if vuln.exploit_maturity in (ExploitMaturity.UNKNOWN, ExploitMaturity.NONE):
                vuln.exploit_maturity = ExploitMaturity.POC
            break

    async def _upsert_victim(self, record: NormalizedRecord, run_id: str) -> None:
        payload = dict(record.payload)

        result = await self.session.execute(
            select(RansomwareVictim).where(
                RansomwareVictim.canonical_key == payload["canonical_key"],
                RansomwareVictim.group_name == payload["group_name"],
                RansomwareVictim.discovered_at == payload["discovered_at"],
            )
        )
        victim = result.scalar_one_or_none()

        if victim is None:
            victim = RansomwareVictim(
                canonical_key=payload["canonical_key"],
                group_name=payload["group_name"],
                discovered_at=payload["discovered_at"],
                display_name=payload["display_name"],
                source_run_id=run_id,
            )
            self.session.add(victim)

        for column in (
            "domain", "country", "sector", "website",
            "screenshot_url", "disclosure_status",
        ):
            if (value := payload.get(column)) is not None:
                setattr(victim, column, value)

        # Keep every spelling the feeds used — an analyst needs to see the
        # raw value to judge whether the merge was right.
        victim.raw_names = list(
            dict.fromkeys([*(victim.raw_names or []), *payload.get("raw_names", [])])
        )
        victim.needs_review = victim.needs_review or payload.get("needs_review", False)
        victim.sources = _merge_sources(victim.sources, record.source)

    async def _upsert_indicator(self, record: NormalizedRecord) -> None:
        payload = dict(record.payload)

        result = await self.session.execute(
            select(Indicator).where(
                Indicator.indicator_type == payload["indicator_type"],
                Indicator.value == payload["value"],
            )
        )
        indicator = result.scalar_one_or_none()
        if indicator is None:
            indicator = Indicator(
                indicator_type=payload["indicator_type"],
                value=payload["value"],
                first_seen=payload.get("first_seen"),
            )
            self.session.add(indicator)

        if (verdict := payload.get("verdict")) is not None:
            indicator.verdict = verdict
        if tags := payload.get("tags"):
            indicator.tags = list(dict.fromkeys([*(indicator.tags or []), *tags]))

        indicator.sources = _merge_sources(indicator.sources, record.source)
        indicator.last_seen = record.observed_at or datetime.now(UTC)
