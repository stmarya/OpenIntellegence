"""Threat intelligence endpoints: vulnerabilities, ransomware, actors, IOCs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.schemas import (
    CorrelationRequest,
    CorrelationResponse,
    IndicatorOut,
    ListResponse,
    Page,
    RansomwareVictimOut,
    ThreatActorOut,
    VulnerabilityDetail,
    VulnerabilityOut,
)
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.models import (
    AssetExposure,
    Indicator,
    RansomwareVictim,
    ThreatActor,
    Vulnerability,
)
from app.services.correlation import correlate_entity
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
IocPrincipal = Annotated[Principal, Depends(require_scope(Scope.IOC))]


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


@router.post(
    "/correlation/evaluate",
    response_model=CorrelationResponse,
    summary="Evaluate entity correlation with server-resolved evidence",
)
async def evaluate_correlation(
    payload: CorrelationRequest,
    db: DbSession,
    principal: ReadPrincipal,
) -> CorrelationResponse:
    result = await correlate_entity(
        db,
        tenant_id=principal.tenant_id,
        primary_entity_type=payload.primary_entity_type,
        primary_entity_id=payload.primary_entity_id,
        caller_evidence=payload.caller_evidence,
    )
    return CorrelationResponse(score=result.score, evidence=result.evidence)
