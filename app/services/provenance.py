"""Provenance construction.

Every list endpoint states which feeds stand behind its numbers. The legacy
collectors merged records with no ``source`` field, so once four ransomware
feeds were combined nobody could say where a row came from or whether a
failing feed had quietly shrunk the totals. This module makes that visible.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import FeedStatus, Provenance
from app.db.models import RunStatus, SourceRun
from app.ingest.base import registry

#: Runs in these states mean the numbers on screen are incomplete.
_DEGRADED = {RunStatus.FAILED, RunStatus.PARTIAL}


async def latest_runs(
    db: AsyncSession, sources: Sequence[str] | None = None
) -> dict[str, SourceRun]:
    """Return the most recent run per source."""
    newest = (
        select(SourceRun.source, func.max(SourceRun.started_at).label("started_at"))
        .group_by(SourceRun.source)
        .subquery()
    )

    stmt = select(SourceRun).join(
        newest,
        (SourceRun.source == newest.c.source)
        & (SourceRun.started_at == newest.c.started_at),
    )
    if sources:
        stmt = stmt.where(SourceRun.source.in_(list(sources)))

    rows = (await db.execute(stmt)).scalars().all()
    return {run.source: run for run in rows}


async def build_provenance(
    db: AsyncSession, sources: Sequence[str] | None = None
) -> Provenance:
    """Describe the feeds behind a response.

    ``sources=None`` covers every registered connector.
    """
    wanted = list(sources) if sources else registry.names()
    runs = await latest_runs(db, wanted)

    included: list[str] = []
    degraded: list[str] = []

    for name in wanted:
        run = runs.get(name)
        if run is None:
            # Never run is not the same as failed, but it still means the
            # feed contributed nothing.
            degraded.append(name)
            continue
        if run.status in _DEGRADED:
            degraded.append(name)
        else:
            included.append(name)

    note = None
    if degraded:
        note = (
            "Partial data. These feeds did not contribute to this response: "
            + ", ".join(sorted(degraded))
            + "."
        )

    return Provenance(
        generated_at=datetime.now(UTC),
        sources_included=sorted(included),
        sources_degraded=sorted(degraded),
        is_partial=bool(degraded),
        note=note,
    )


async def feed_statuses(db: AsyncSession) -> list[FeedStatus]:
    """Per-connector health for the integrations page."""
    runs = await latest_runs(db)
    statuses: list[FeedStatus] = []

    for name in registry.names():
        connector_cls = registry.get(name)
        run = runs.get(name)

        if run is None:
            statuses.append(
                FeedStatus(source=name, label=connector_cls.label, status="never_run")
            )
            continue

        statuses.append(
            FeedStatus(
                source=name,
                label=connector_cls.label,
                status=run.status.value,
                last_run_at=run.finished_at or run.started_at,
                records_ingested=run.records_ingested,
                records_quarantined=run.records_quarantined,
                error_message=run.error_message,
            )
        )

    return statuses
