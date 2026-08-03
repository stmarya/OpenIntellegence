"""Threat intelligence endpoints: vulnerabilities, ransomware, actors, IOCs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.schemas import (
    IndicatorOut,
    ListResponse,
    Page,
    RansomwareVictimOut,
    ThreatActorOut,
    VulnerabilityDetail,
    VulnerabilityOut,
)
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.alert_models import Sighting
from app.db.models import (
    AssetExposure,
    Indicator,
    RansomwareVictim,
    ThreatActor,
    Vulnerability,
)
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
IocPrincipal = Annotated[Principal, Depends(require_scope(Scope.IOC))]


class SightingRef(BaseModel):
    """A sighting as referenced from an indicator detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    observed_at: datetime
    asset_id: str | None = None
    confidence: int | None = None


class ActorDetail(BaseModel):
    """Single threat actor with the victims that can be tied to its name."""

    actor: ThreatActorOut
    recent_victims: list[RansomwareVictimOut]
    victim_match_basis: str


class IndicatorDetail(BaseModel):
    """Single indicator with the tenant sightings that reference its value."""

    indicator: IndicatorOut
    sightings: list[SightingRef]
    sighting_match_basis: str
    enrichment_state: str


@router.get(
    "/vulnerabilities",
    response_model=ListResponse[VulnerabilityOut],
    summary="List vulnerabilities with asset context",
)
async def list_vulnerabilities(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    kev_only: bool = False,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    exploit_maturity: str | None = None,
    affected_only: Annotated[
        bool, Query(description="Only CVEs matching at least one asset in this tenant")
    ] = False,
) -> ListResponse[VulnerabilityOut]:
    """Return the remediation queue.

    Default ordering is by *affected asset count*, not CVSS. A 9.8 that
    touches nothing is less urgent than a 7.8 on 106 hosts, and sorting by
    score alone is how remediation queues end up ignored.
    """
    exposure_count = (
        select(
            AssetExposure.vulnerability_id.label("vuln_id"),
            func.count(AssetExposure.id).label("asset_count"),
        )
        .where(AssetExposure.resolved_at.is_(None))
        .group_by(AssetExposure.vulnerability_id)
        .subquery()
    )

    stmt = select(
        Vulnerability, func.coalesce(exposure_count.c.asset_count, 0).label("asset_count")
    ).outerjoin(exposure_count, exposure_count.c.vuln_id == Vulnerability.id)

    if kev_only:
        stmt = stmt.where(Vulnerability.is_kev.is_(True))
    if min_cvss is not None:
        # Rows with no score are excluded from a score filter rather than
        # treated as zero — unknown is not the same as low.
        stmt = stmt.where(Vulnerability.cvss_score >= min_cvss)
    if exploit_maturity:
        stmt = stmt.where(Vulnerability.exploit_maturity == exploit_maturity)
    if affected_only:
        stmt = stmt.where(func.coalesce(exposure_count.c.asset_count, 0) > 0)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    stmt = stmt.order_by(
        func.coalesce(exposure_count.c.asset_count, 0).desc(),
        Vulnerability.is_kev.desc(),
        Vulnerability.cvss_score.desc().nulls_last(),
    ).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).all()

    data = []
    for vuln, asset_count in rows:
        item = VulnerabilityOut.model_validate(vuln)
        item.affected_asset_count = int(asset_count)
        data.append(item)

    return ListResponse[VulnerabilityOut](
        data=data,
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=("nvd", "cisa_kev", "osv")),
    )


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=VulnerabilityDetail,
    summary="Vulnerability detail with public exploits",
)
async def get_vulnerability(
    cve_id: str, db: DbSession, principal: ReadPrincipal
) -> VulnerabilityDetail:
    result = await db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.exploits))
        .where(Vulnerability.cve_id == cve_id.upper())
    )
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{cve_id} is not in the dataset.")

    asset_count = await db.scalar(
        select(func.count(AssetExposure.id)).where(
            AssetExposure.vulnerability_id == vuln.id,
            AssetExposure.resolved_at.is_(None),
        )
    )

    detail = VulnerabilityDetail.model_validate(vuln)
    detail.affected_asset_count = int(asset_count or 0)
    return detail


@router.get(
    "/ransomware/victims",
    response_model=ListResponse[RansomwareVictimOut],
    summary="List ransomware leak-site victims",
)
async def list_victims(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    group: str | None = None,
    country: str | None = None,
    since: datetime | None = None,
    include_unreviewed: Annotated[
        bool, Query(description="Include rows whose victim name is not yet normalised")
    ] = True,
) -> ListResponse[RansomwareVictimOut]:
    """Victims are de-duplicated across the three leak-site feeds.

    The response keeps ``raw_names`` and ``needs_review`` so an analyst can
    audit every merge rather than trusting it blindly.
    """
    stmt = select(RansomwareVictim)
    if group:
        stmt = stmt.where(RansomwareVictim.group_name == group.lower())
    if country:
        stmt = stmt.where(RansomwareVictim.country == country)
    if since:
        stmt = stmt.where(RansomwareVictim.discovered_at >= since)
    if not include_unreviewed:
        stmt = stmt.where(RansomwareVictim.needs_review.is_(False))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    rows = (
        await db.execute(
            stmt.order_by(RansomwareVictim.discovered_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    unreviewed = await db.scalar(
        select(func.count(RansomwareVictim.id)).where(RansomwareVictim.needs_review.is_(True))
    )

    provenance = await build_provenance(
        db, sources=("ransomlook", "ransomware_live", "dls_monitor")
    )
    if unreviewed:
        provenance.note = (
            f"{unreviewed} victim names are not yet normalised "
            "(raw URLs or status prefixes) and are flagged with needs_review."
        )

    return ListResponse[RansomwareVictimOut](
        data=[RansomwareVictimOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=provenance,
    )


@router.get(
    "/ransomware/groups",
    summary="Leak-site groups aggregated from victim records",
)
async def list_ransomware_groups(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """Aggregate victims by leak-site group.

    This is a projection of victim rows, not a curated group registry. A
    group that has posted no victim in the ingested window is absent from
    this list, which is not evidence that the group is inactive.
    """
    grouped = (
        select(
            RansomwareVictim.group_name.label("group_name"),
            func.count(RansomwareVictim.id).label("victim_count"),
            func.max(RansomwareVictim.discovered_at).label("latest_victim_at"),
            func.min(RansomwareVictim.discovered_at).label("earliest_victim_at"),
            func.count(func.distinct(RansomwareVictim.country)).label("country_count"),
        )
        .group_by(RansomwareVictim.group_name)
        .subquery()
    )

    total = await db.scalar(select(func.count()).select_from(grouped)) or 0
    rows = (
        await db.execute(
            select(grouped)
            .order_by(grouped.c.victim_count.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()

    provenance = await build_provenance(
        db, sources=("ransomlook", "ransomware_live", "dls_monitor")
    )
    provenance.note = (
        "Groups are derived by aggregating ingested victim rows. Absence from "
        "this list means no victim was ingested for that group, not that the "
        "group is dormant."
    )

    return {
        "data": [
            {
                "group_name": row.group_name,
                "victim_count": int(row.victim_count or 0),
                "country_count": int(row.country_count or 0),
                "earliest_victim_at": row.earliest_victim_at,
                "latest_victim_at": row.latest_victim_at,
            }
            for row in rows
        ],
        "page": {
            "limit": limit,
            "offset": offset,
            "total": total,
            "has_more": offset + limit < total,
        },
        "provenance": provenance,
    }


@router.get(
    "/actors",
    response_model=ListResponse[ThreatActorOut],
    summary="List threat actors",
)
async def list_actors(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[ThreatActorOut]:
    stmt = select(ThreatActor)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    rows = (
        await db.execute(
            stmt.order_by(ThreatActor.victim_count.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    return ListResponse[ThreatActorOut](
        data=[ThreatActorOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=("ransomlook", "threat_actors")),
    )


@router.get(
    "/actors/{actor_id}",
    response_model=ActorDetail,
    summary="Threat actor detail",
)
async def get_actor(actor_id: str, db: DbSession, principal: ReadPrincipal) -> ActorDetail:
    """Return one actor and the leak-site victims tied to its name.

    The link between an actor record and a victim row is an alias match on
    the leak-site group name. That is a weaker claim than attribution, so
    the response states the basis rather than presenting the victims as an
    established finding.
    """
    actor = (
        await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat actor not found.")

    # ThreatActor stores canonical_name, display_name and aliases. An earlier
    # version resolved the match key with getattr(actor, "slug") or
    # getattr(actor, "name"), neither of which exists on the model, so the key
    # was always empty and every actor reported that it had no name to match
    # against. Leak-site group names are stored lowercased.
    alias_keys = {alias.lower() for alias in (actor.aliases or []) if alias}
    if actor.canonical_name:
        alias_keys.add(actor.canonical_name.lower())
    match_keys = sorted(alias_keys)

    victims: list[RansomwareVictim] = []
    if match_keys:
        victims = list(
            (
                await db.execute(
                    select(RansomwareVictim)
                    .where(RansomwareVictim.group_name.in_(match_keys))
                    .order_by(RansomwareVictim.discovered_at.desc())
                    .limit(50)
                )
            ).scalars().all()
        )
        basis = (
            "Victims are matched where the leak-site group name equals the "
            "actor's canonical name or one of its recorded aliases ("
            f"{', '.join(match_keys)}). A victim published under an alias that "
            "is not recorded here will not appear, and appearing here is an "
            "attacker claim rather than a confirmed breach."
        )
    else:
        basis = (
            "This actor record carries no canonical name or alias to match "
            "leak-site victims against, so no victim list is claimed for it."
        )

    return ActorDetail(
        actor=ThreatActorOut.model_validate(actor),
        recent_victims=[RansomwareVictimOut.model_validate(v) for v in victims],
        victim_match_basis=basis,
    )


@router.get(
    "/iocs",
    response_model=ListResponse[IndicatorOut],
    summary="List indicators of compromise",
)
async def list_iocs(
    db: DbSession,
    principal: IocPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    indicator_type: str | None = None,
    verdict: Annotated[
        str | None,
        Query(description="malicious | suspicious | clean | unenriched"),
    ] = None,
) -> ListResponse[IndicatorOut]:
    """Indicators, including those not yet enriched.

    ``verdict=unenriched`` selects rows with a NULL verdict. These are
    reported as their own category rather than folded into "clean", which
    would overstate confidence.
    """
    stmt = select(Indicator)
    if indicator_type:
        stmt = stmt.where(Indicator.indicator_type == indicator_type)
    if verdict == "unenriched":
        stmt = stmt.where(Indicator.verdict.is_(None))
    elif verdict:
        stmt = stmt.where(Indicator.verdict == verdict)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    rows = (
        await db.execute(
            stmt.order_by(Indicator.last_seen.desc().nulls_last()).limit(limit).offset(offset)
        )
    ).scalars().all()

    unenriched = await db.scalar(
        select(func.count(Indicator.id)).where(Indicator.verdict.is_(None))
    )

    provenance = await build_provenance(db, sources=("ransomwhere", "otx"))
    provenance.note = f"{unenriched or 0} indicators have not been enriched yet."

    return ListResponse[IndicatorOut](
        data=[IndicatorOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=provenance,
    )


@router.get(
    "/iocs/{indicator_id}",
    response_model=IndicatorDetail,
    summary="Indicator detail with tenant sightings",
)
async def get_indicator(
    indicator_id: str, db: DbSession, principal: IocPrincipal
) -> IndicatorDetail:
    """Return one indicator plus the sightings this tenant reported for it.

    An empty sighting list means this tenant reported none, which is not the
    same as the indicator being absent from the estate. Telemetry coverage is
    partial, and the response says so instead of implying an all-clear.
    """
    indicator = (
        await db.execute(select(Indicator).where(Indicator.id == indicator_id))
    ).scalar_one_or_none()
    if indicator is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Indicator not found.")

    value = getattr(indicator, "value", None)
    sightings: list[Sighting] = []
    if value:
        sightings = list(
            (
                await db.execute(
                    select(Sighting)
                    .where(
                        Sighting.tenant_id == principal.tenant_id,
                        Sighting.entity_id == value,
                    )
                    .order_by(Sighting.observed_at.desc())
                    .limit(100)
                )
            ).scalars().all()
        )

    return IndicatorDetail(
        indicator=IndicatorOut.model_validate(indicator),
        sightings=[SightingRef.model_validate(s) for s in sightings],
        sighting_match_basis=(
            "Sightings are matched on exact indicator value within this tenant. "
            "No sighting recorded here means none was reported, not that the "
            "indicator is absent from the estate."
        ),
        enrichment_state=(
            "enriched"
            if getattr(indicator, "verdict", None)
            else "not_enriched"
        ),
    )


@router.get("/stats/summary", summary="Dashboard KPI summary")
async def summary(db: DbSession, principal: ReadPrincipal) -> dict:
    """KPI counters for the executive dashboard.

    Every count that can legitimately be zero is returned as zero rather than
    omitted, so the UI can render an honest empty state instead of a gap.
    """
    severities = dict(
        (
            await db.execute(
                select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(
                    Vulnerability.severity
                )
            )
        ).all()
    )

    verdicts = dict(
        (
            await db.execute(
                select(Indicator.verdict, func.count(Indicator.id)).group_by(Indicator.verdict)
            )
        ).all()
    )

    return {
        "generated_at": datetime.now(UTC),
        "vulnerabilities": {
            "total": await db.scalar(select(func.count(Vulnerability.id))) or 0,
            "kev": await db.scalar(
                select(func.count(Vulnerability.id)).where(Vulnerability.is_kev.is_(True))
            ) or 0,
            "unscored": await db.scalar(
                select(func.count(Vulnerability.id)).where(Vulnerability.cvss_score.is_(None))
            ) or 0,
            "by_severity": {
                level: severities.get(level, 0)
                for level in ("critical", "high", "medium", "low", "none")
            },
        },
        "indicators": {
            "total": await db.scalar(select(func.count(Indicator.id))) or 0,
            "malicious": verdicts.get("malicious", 0),
            "suspicious": verdicts.get("suspicious", 0),
            "clean": verdicts.get("clean", 0),
            # Displayed as its own legend entry with a dashed swatch.
            "unenriched": verdicts.get(None, 0),
        },
        "ransomware": {
            "victims": await db.scalar(select(func.count(RansomwareVictim.id))) or 0,
            "needs_review": await db.scalar(
                select(func.count(RansomwareVictim.id)).where(
                    RansomwareVictim.needs_review.is_(True)
                )
            ) or 0,
            "groups": await db.scalar(
                select(func.count(func.distinct(RansomwareVictim.group_name)))
            ) or 0,
        },
        "provenance": await build_provenance(db, sources=None),
    }
