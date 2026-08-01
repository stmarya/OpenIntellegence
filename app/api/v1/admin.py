"""API key management, feed health, and ingestion control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from app.api.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    FeedStatus,
    ListResponse,
    Page,
)
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.core.security import generate_key
from app.db.models import ApiKey, ApiKeyStatus, AuditLog, QuarantinedRecord, SourceRun
from app.ingest.base import registry
from app.ingest.pipeline import IngestPipeline
from app.services.provenance import feed_statuses

router = APIRouter()

KeyReader = Annotated[Principal, Depends(require_scope(Scope.APIKEY_READ))]
KeyWriter = Annotated[Principal, Depends(require_scope(Scope.APIKEY_WRITE))]
AdminPrincipal = Annotated[Principal, Depends(require_scope(Scope.ADMIN))]
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]

#: Scopes a caller may hand out. Anything else is rejected so a typo cannot
#: silently create a key that grants nothing, or one that grants too much.
GRANTABLE_SCOPES = {
    Scope.READ,
    Scope.WRITE,
    Scope.IOC,
    Scope.ENROLL,
    Scope.APIKEY_READ,
    Scope.APIKEY_WRITE,
    Scope.REPORT_WRITE,
}


@router.get("/api-keys", response_model=ListResponse[ApiKeyOut], summary="List API keys")
async def list_api_keys(
    db: DbSession,
    principal: KeyReader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    include_revoked: bool = True,
) -> ListResponse[ApiKeyOut]:
    """Revoked keys stay listed with their revocation reason.

    Deleting them would erase the audit trail of what once had access.
    """
    stmt = select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id)
    if not include_revoked:
        stmt = stmt.where(ApiKey.status != ApiKeyStatus.REVOKED)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(stmt.order_by(ApiKey.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()

    from app.services.provenance import build_provenance

    return ListResponse[ApiKeyOut](
        data=[ApiKeyOut.model_validate(r) for r in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=()),
    )


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key (secret shown once)",
)
async def create_api_key(
    payload: ApiKeyCreate, request: Request, db: DbSession, principal: KeyWriter
) -> ApiKeyCreated:
    """Mint a key and return its plaintext exactly once.

    Only the secret half is stored, Argon2id-hashed. We cannot show the key
    again later, and that is the point: a platform that can display your key
    on demand is a platform that is storing it recoverably.
    """
    unknown = sorted(set(payload.scopes) - GRANTABLE_SCOPES)
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": "Unknown scope requested.",
                "unknown": unknown,
                "grantable": sorted(GRANTABLE_SCOPES),
            },
        )

    # A caller cannot grant a scope it does not itself hold.
    escalation = sorted(s for s in payload.scopes if not principal.has(s))
    if escalation:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "message": "You cannot grant scopes you do not hold.",
                "missing": escalation,
                "granted": sorted(principal.scopes),
            },
        )

    generated = generate_key(agent=payload.agent_key)
    expires_at = (
        datetime.now(UTC) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )

    api_key = ApiKey(
        tenant_id=principal.tenant_id,
        name=payload.name,
        key_id=generated.key_id,
        secret_hash=generated.secret_hash,
        masked_key=generated.masked,
        prefix=generated.prefix,
        scopes=payload.scopes,
        rate_limit_per_hour=payload.rate_limit_per_hour,
        status=ApiKeyStatus.ACTIVE,
        expires_at=expires_at,
        single_use=payload.agent_key,
        created_by=str(principal.api_key_id),
    )
    db.add(api_key)
    await db.flush()

    db.add(
        AuditLog(
            tenant_id=principal.tenant_id,
            actor=f"api_key:{principal.api_key_id}",
            action="api_key.create",
            entity_type="api_key",
            entity_id=str(api_key.id),
            ip_address=request.client.host if request.client else None,
            # The raw key is never logged.
            details={"name": payload.name, "scopes": payload.scopes},
        )
    )

    out = ApiKeyCreated.model_validate(api_key)
    out.raw_key = generated.raw_key
    return out


@router.delete(
    "/api-keys/{key_id}",
    response_model=ApiKeyOut,
    summary="Revoke an API key",
)
async def revoke_api_key(
    key_id: str,
    request: Request,
    db: DbSession,
    principal: KeyWriter,
    reason: Annotated[str | None, Query(max_length=500)] = None,
) -> ApiKeyOut:
    api_key = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.id == key_id, ApiKey.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()

    if api_key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found.")

    if api_key.id == principal.api_key_id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "You cannot revoke the key you are currently authenticating with.",
        )

    api_key.status = ApiKeyStatus.REVOKED
    api_key.revoked_at = datetime.now(UTC)
    api_key.revoked_reason = reason or "revoked via API"

    db.add(
        AuditLog(
            tenant_id=principal.tenant_id,
            actor=f"api_key:{principal.api_key_id}",
            action="api_key.revoke",
            entity_type="api_key",
            entity_id=str(api_key.id),
            ip_address=request.client.host if request.client else None,
            details={"reason": api_key.revoked_reason},
        )
    )

    return ApiKeyOut.model_validate(api_key)


@router.get(
    "/feeds",
    response_model=list[FeedStatus],
    summary="Connector health for every registered feed",
)
async def feeds(db: DbSession, principal: ReadPrincipal) -> list[FeedStatus]:
    """Health of all connectors, including ones that have never run.

    A feed that is silently absent is indistinguishable from a feed with no
    data, so absence is reported explicitly as ``never_run``.
    """
    return await feed_statuses(db)


@router.get("/quarantine", summary="Records rejected during normalisation")
async def quarantine(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    source: str | None = None,
) -> dict:
    """Malformed records are kept, not dropped.

    The original collectors discarded anything they could not parse, which
    is why nobody noticed the CXSecurity date bug. Quarantined rows keep the
    raw payload so a parser fix can replay them.
    """
    stmt = select(QuarantinedRecord)
    if source:
        stmt = stmt.where(QuarantinedRecord.source == source)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(QuarantinedRecord.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    by_reason = dict(
        (
            await db.execute(
                select(QuarantinedRecord.reason, func.count(QuarantinedRecord.id)).group_by(
                    QuarantinedRecord.reason
                )
            )
        ).all()
    )

    return {
        "total": total,
        "by_reason": by_reason,
        "page": {"limit": limit, "offset": offset, "has_more": offset + limit < total},
        "records": [
            {
                "id": str(r.id),
                "source": r.source,
                "reason": r.reason,
                "raw_payload": r.raw_payload,
                "created_at": r.created_at,
            }
            for r in rows
        ],
    }


@router.post(
    "/ingest/{source}/run",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an ingestion run for one connector",
)
async def trigger_ingest(
    source: str,
    db: DbSession,
    principal: AdminPrincipal,
    since: datetime | None = None,
) -> dict:
    if source not in registry.names():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            {"message": f"Unknown connector '{source}'.", "available": registry.names()},
        )

    pipeline = IngestPipeline(db, get_settings())
    summary = await pipeline.run(source, since=since)

    return {
        "source": summary.source,
        "run_id": summary.run_id,
        "status": summary.status.value,
        "records_fetched": summary.fetched,
        "records_ingested": summary.ingested,
        "records_quarantined": summary.quarantined,
        "error": summary.error,
    }


@router.get("/runs", summary="Recent ingestion runs")
async def runs(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict:
    rows = (
        await db.execute(select(SourceRun).order_by(SourceRun.started_at.desc()).limit(limit))
    ).scalars().all()

    return {
        "runs": [
            {
                "id": str(r.id),
                "source": r.source,
                "status": r.status.value,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "records_fetched": r.records_fetched,
                "records_ingested": r.records_ingested,
                "records_quarantined": r.records_quarantined,
                "error_message": r.error_message,
            }
            for r in rows
        ]
    }
