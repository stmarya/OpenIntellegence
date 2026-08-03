"""Asset management and endpoint agent gateway endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from app.api.schemas import (
    AgentOut,
    AssetExposureResponse,
    AssetOut,
    EnrollmentRequest,
    EnrollmentResponse,
    ExposureItem,
    HeartbeatRequest,
    HeartbeatResponse,
    ListResponse,
    Page,
)
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.models import (
    Agent,
    AgentStatus,
    ApiKey,
    ApiKeyStatus,
    Asset,
    AssetExposure,
    AuditLog,
    InstalledSoftware,
    Vulnerability,
)
from app.services.agents import (
    apply_software_inventory,
    get_certificate_authority,
    recompute_exposure,
    resolve_agent_from_request,
)
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
EnrollPrincipal = Annotated[Principal, Depends(require_scope(Scope.ENROLL))]


@router.get("/assets", response_model=ListResponse[AssetOut], summary="List assets")
async def list_assets(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    criticality: str | None = None,
    os_family: str | None = None,
    exposed_only: bool = False,
) -> ListResponse[AssetOut]:
    exposure_count = (
        select(
            AssetExposure.asset_id.label("asset_id"),
            func.count(AssetExposure.id).label("cve_count"),
        )
        .where(AssetExposure.resolved_at.is_(None))
        .group_by(AssetExposure.asset_id)
        .subquery()
    )

    stmt = (
        select(Asset, func.coalesce(exposure_count.c.cve_count, 0).label("cve_count"))
        .outerjoin(exposure_count, exposure_count.c.asset_id == Asset.id)
        .where(Asset.tenant_id == principal.tenant_id)
    )

    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if os_family:
        stmt = stmt.where(Asset.os_family == os_family)
    if exposed_only:
        stmt = stmt.where(func.coalesce(exposure_count.c.cve_count, 0) > 0)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    rows = (
        await db.execute(
            stmt.order_by(
                func.coalesce(exposure_count.c.cve_count, 0).desc(), Asset.hostname
            )
            .limit(limit)
            .offset(offset)
        )
    ).all()

    data = []
    for asset, cve_count in rows:
        item = AssetOut.model_validate(asset)
        item.exposed_cve_count = int(cve_count)
        data.append(item)

    return ListResponse[AssetOut](
        data=data,
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=("endpoint_agent",)),
    )


@router.get(
    "/assets/{asset_id}/exposure",
    response_model=AssetExposureResponse,
    summary="CVE exposure for one asset",
)
async def asset_exposure(
    asset_id: str, db: DbSession, principal: ReadPrincipal
) -> AssetExposureResponse:
    """Which CVEs affect this asset, and how we decided that.

    ``matched_via`` records the join that produced each row (CPE match or
    vendor/product match) so a false positive can be traced to its rule
    instead of being argued about.
    """
    asset = (
        await db.execute(
            select(Asset).where(
                Asset.id == asset_id, Asset.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()

    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found.")

    rows = (
        await db.execute(
            select(AssetExposure, Vulnerability)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(
                AssetExposure.asset_id == asset_id,
                AssetExposure.resolved_at.is_(None),
            )
            .order_by(
                Vulnerability.is_kev.desc(),
                Vulnerability.cvss_score.desc().nulls_last(),
            )
        )
    ).all()

    now = datetime.now(UTC)
    exposures = [
        ExposureItem(
            cve_id=vuln.cve_id,
            cvss_score=vuln.cvss_score,
            severity=vuln.severity,
            is_kev=vuln.is_kev,
            exploit_maturity=vuln.exploit_maturity.value,
            matched_via=exposure.matched_via,
            detected_at=exposure.detected_at,
            sla_due_at=exposure.sla_due_at,
            sla_breached=bool(exposure.sla_due_at and exposure.sla_due_at < now),
        )
        for exposure, vuln in rows
    ]

    out = AssetOut.model_validate(asset)
    out.exposed_cve_count = len(exposures)

    return AssetExposureResponse(
        asset=out,
        exposures=exposures,
        provenance=await build_provenance(db, sources=("endpoint_agent", "nvd", "cisa_kev")),
    )


@router.get("/agents", response_model=ListResponse[AgentOut], summary="List endpoint agents")
async def list_agents(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    agent_status: str | None = None,
) -> ListResponse[AgentOut]:
    """Fleet view.

    Stale agents are reported as ``stale``, never dropped from the list. An
    endpoint that stopped reporting is the one you most need to see.
    """
    stmt = select(Agent).where(Agent.tenant_id == principal.tenant_id)
    if agent_status:
        stmt = stmt.where(Agent.status == agent_status)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(Agent.last_heartbeat_at.desc().nulls_first())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()

    return ListResponse[AgentOut](
        data=[AgentOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=("endpoint_agent",)),
    )


@router.post(
    "/agents/enroll",
    response_model=EnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll a new endpoint agent (single-use key)",
)
async def enroll_agent(
    payload: EnrollmentRequest,
    request: Request,
    db: DbSession,
    principal: EnrollPrincipal,
) -> EnrollmentResponse:
    """Exchange a single-use enrollment key for a client certificate.

    The enrollment key is revoked on success. A key that could enroll an
    unlimited number of endpoints would, once leaked from one installer,
    let anyone join the fleet.
    """
    settings = get_settings()
    ca = get_certificate_authority(settings)

    asset = (
        await db.execute(
            select(Asset).where(
                Asset.tenant_id == principal.tenant_id,
                Asset.hostname == payload.hostname,
            )
        )
    ).scalar_one_or_none()

    if asset is None:
        asset = Asset(
            tenant_id=principal.tenant_id,
            hostname=payload.hostname,
            asset_type="endpoint",
            os_family=payload.os_family,
            os_version=payload.os_version,
            mac_address=payload.mac_address,
        )
        db.add(asset)
        await db.flush()

    agent = Agent(
        tenant_id=principal.tenant_id,
        asset_id=asset.id,
        version=payload.agent_version,
        os_family=payload.os_family,
        status=AgentStatus.ACTIVE,
        enrolled_at=datetime.now(UTC),
    )
    db.add(agent)
    await db.flush()

    issued = ca.sign_csr(
        payload.csr_pem,
        agent_id=str(agent.id),
        tenant_id=str(principal.tenant_id),
        ttl_days=settings.agent_cert_ttl_days,
    )

    agent.cert_serial = issued.serial
    agent.cert_fingerprint = issued.fingerprint_sha256
    agent.cert_expires_at = issued.not_after

    # Burn the single-use enrollment key.
    enrollment_key = (
        await db.execute(select(ApiKey).where(ApiKey.id == principal.api_key_id))
    ).scalar_one_or_none()
    if enrollment_key is not None and enrollment_key.single_use:
        enrollment_key.status = ApiKeyStatus.REVOKED
        enrollment_key.revoked_at = datetime.now(UTC)
        enrollment_key.revoked_reason = f"consumed by agent enrollment {agent.id}"

    db.add(
        AuditLog(
            tenant_id=principal.tenant_id,
            actor=f"api_key:{principal.api_key_id}",
            action="agent.enroll",
            entity_type="agent",
            entity_id=str(agent.id),
            ip_address=request.client.host if request.client else None,
            details={
                "hostname": payload.hostname,
                "os_family": payload.os_family,
                "cert_serial": issued.serial,
            },
        )
    )

    return EnrollmentResponse(
        agent_id=str(agent.id),
        asset_id=str(asset.id),
        certificate_pem=issued.certificate_pem,
        ca_chain_pem=issued.ca_chain_pem,
        certificate_expires_at=issued.not_after,
        heartbeat_interval_seconds=settings.agent_heartbeat_interval_seconds,
    )


@router.post(
    "/agents/heartbeat",
    response_model=HeartbeatResponse,
    summary="Agent check-in and inventory push",
)
async def heartbeat(
    payload: HeartbeatRequest, request: Request, db: DbSession
) -> HeartbeatResponse:
    """Authenticated by client certificate, not by API key.

    Identity comes from the verified certificate presented at the TLS layer.
    A body-supplied agent id would be trivially spoofable.
    """
    settings = get_settings()
    agent = await resolve_agent_from_request(request, db, settings)

    now = datetime.now(UTC)
    agent.last_heartbeat_at = now
    agent.status = AgentStatus.ACTIVE
    agent.version = payload.agent_version

    if payload.software is not None:
        await apply_software_inventory(db, agent, payload.software)
        await recompute_exposure(db, agent.asset_id)

    if agent.asset_id and (payload.ip_address or payload.os_version):
        asset = await db.get(Asset, agent.asset_id)
        if asset is not None:
            asset.ip_address = payload.ip_address or asset.ip_address
            asset.os_version = payload.os_version or asset.os_version
            asset.last_seen_at = now

    renewal_due = bool(
        agent.cert_expires_at and agent.cert_expires_at - now < timedelta(days=14)
    )

    return HeartbeatResponse(
        acknowledged_at=now,
        next_heartbeat_seconds=settings.agent_heartbeat_interval_seconds,
        certificate_expires_at=agent.cert_expires_at,
        certificate_renewal_due=renewal_due,
    )


@router.get("/agents/{agent_id}", response_model=AgentOut, summary="One endpoint agent")
async def get_agent(agent_id: str, db: DbSession, principal: ReadPrincipal) -> AgentOut:
    """Read one agent fresh, rather than reusing a row from the fleet list.

    ``last_heartbeat_at`` is the field most likely to be consulted here, and it
    is the field where a stale copy does the most damage: it is the difference
    between an endpoint that checked in a minute ago and one that stopped
    reporting an hour ago. A heartbeat records last contact, not current
    health, so this endpoint deliberately returns the stored status rather than
    deriving a liveness verdict.
    """
    agent = (
        await db.execute(
            select(Agent).where(
                Agent.id == agent_id, Agent.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()

    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")

    return AgentOut.model_validate(agent)


@router.get("/agents/{agent_id}/software", summary="Installed software for an agent")
async def agent_software(
    agent_id: str, db: DbSession, principal: ReadPrincipal
) -> dict:
    agent = (
        await db.execute(
            select(Agent).where(
                Agent.id == agent_id, Agent.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found.")

    rows = (
        await db.execute(
            select(InstalledSoftware)
            .where(InstalledSoftware.asset_id == agent.asset_id)
            .order_by(InstalledSoftware.name)
        )
    ).scalars().all()

    return {
        "agent_id": agent_id,
        "asset_id": str(agent.asset_id) if agent.asset_id else None,
        "count": len(rows),
        # Software with no CPE cannot be matched to CVEs. Reporting the
        # figure stops the exposure count from looking authoritative when
        # part of the inventory is unmatchable.
        "unmatched_count": sum(1 for r in rows if not r.cpe_uri),
        "software": [
            {
                "name": r.name,
                "version": r.version,
                "vendor": r.vendor,
                "cpe_uri": r.cpe_uri,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            }
            for r in rows
        ],
    }
