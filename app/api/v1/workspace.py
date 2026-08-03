"""Workspace identity, access principals, roles, and tenant read surfaces."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from app.api.schemas import ListResponse, Page
from app.core.deps import CurrentPrincipal, DbSession, Principal, Scope, require_scope
from app.db.governance_models import IntelCollection
from app.db.models import ApiKey, ApiKeyStatus, Tenant
from app.db.platform_models import Role, User
from app.services.provenance import build_provenance
router = APIRouter(); ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]; KeyReader = Annotated[Principal, Depends(require_scope(Scope.APIKEY_READ))]
class ORM(BaseModel): model_config = ConfigDict(from_attributes=True)
SCOPE_CATALOGUE = {Scope.READ: "Read intelligence, assets, cases, and reporting surfaces.", Scope.WRITE: "Create and modify investigations, cases, alert rules, and sightings.", Scope.IOC: "Read indicator values and enrichment state.", Scope.ENROLL: "Enrol endpoint agents and submit heartbeats.", Scope.APIKEY_READ: "List masked API keys.", Scope.APIKEY_WRITE: "Mint and revoke bounded API keys.", Scope.REPORT_WRITE: "Request report generation.", Scope.ADMIN: "Administrative operations."}
class SessionOut(BaseModel):
    api_key_id: str; key_name: str; tenant_id: str; tenant_name: str | None; tenant_slug: str | None; scopes: list[str]; rate_limit_per_hour: int; subject_kind: str; note: str
class AccessPrincipalOut(ORM):
    id: str; name: str; masked_key: str; scopes: list = Field(default_factory=list); status: str; rate_limit_per_hour: int; created_by: str | None = None; created_at: datetime | None = None; expires_at: datetime | None = None; last_used_at: datetime | None = None; revoked_at: datetime | None = None; revoked_reason: str | None = None
class SharingGroupOut(ORM):
    id: str; name: str; description: str | None = None; purpose: str | None = None; owner: str | None = None; member_refs: list = Field(default_factory=list); last_curated_at: datetime | None = None
@router.get("/me", response_model=SessionOut)
async def whoami(db: DbSession, p: CurrentPrincipal) -> SessionOut:
    tenant = await db.get(Tenant, p.tenant_id); return SessionOut(api_key_id=str(p.api_key_id), key_name=p.name, tenant_id=str(p.tenant_id), tenant_name=tenant.name if tenant else None, tenant_slug=tenant.slug if tenant else None, scopes=sorted(p.scopes), rate_limit_per_hour=p.rate_limit_per_hour, subject_kind="api_key", note="This request is authenticated by a service API key. A user and role directory exists, but interactive OIDC sessions are not yet an authentication dependency.")
@router.get("/tenants/current")
async def current_tenant(db: DbSession, p: ReadPrincipal) -> dict:
    tenant = await db.get(Tenant, p.tenant_id)
    if not tenant: raise HTTPException(404, "Tenant not found.")
    active_keys = await db.scalar(select(func.count()).select_from(ApiKey).where(ApiKey.tenant_id == p.tenant_id, ApiKey.status != ApiKeyStatus.REVOKED)) or 0; users = await db.scalar(select(func.count()).select_from(User).where(User.tenant_id == p.tenant_id)) or 0; roles = await db.scalar(select(func.count()).select_from(Role).where(Role.tenant_id == p.tenant_id)) or 0
    return {"id": tenant.id, "slug": tenant.slug, "name": tenant.name, "is_active": tenant.is_active, "created_at": tenant.created_at, "active_api_key_count": active_keys, "user_count": users, "role_count": roles, "isolation": {"model": "row_scoped_by_tenant_id", "cross_tenant_sharing": "not_implemented"}, "generated_at": datetime.now(UTC)}
@router.get("/access/scopes")
async def access_scopes(db: DbSession, p: ReadPrincipal) -> dict:
    from app.api.v1.admin import GRANTABLE_SCOPES
    roles = (await db.execute(select(Role).where(Role.tenant_id == p.tenant_id).order_by(Role.name))).scalars().all(); return {"tenant_id": p.tenant_id, "scopes": [{"scope": s, "description": d, "grantable": s in GRANTABLE_SCOPES, "held_by_caller": p.has(s)} for s, d in SCOPE_CATALOGUE.items()], "roles": [{"id": x.id, "name": x.name, "scopes": x.scopes, "built_in": x.built_in} for x in roles], "authentication_note": "API keys remain the request principal until OIDC session verification is wired.", "generated_at": datetime.now(UTC)}
@router.get("/access/principals", response_model=ListResponse[AccessPrincipalOut])
async def access_principals(db: DbSession, p: KeyReader, limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0) -> ListResponse[AccessPrincipalOut]:
    stmt = select(ApiKey).where(ApiKey.tenant_id == p.tenant_id); total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows = (await db.execute(stmt.order_by(ApiKey.created_at.desc()).limit(limit).offset(offset))).scalars().all(); provenance = await build_provenance(db, sources=()); provenance.note = "API-key principals are listed here. Human users and role assignments are available from /users and /roles, but are not yet request-authentication principals."; return ListResponse(data=[AccessPrincipalOut.model_validate(x) for x in rows], page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total), provenance=provenance)
@router.get("/sharing-groups", response_model=ListResponse[SharingGroupOut])
async def sharing_groups(db: DbSession, p: ReadPrincipal, limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0) -> ListResponse[SharingGroupOut]:
    stmt = select(IntelCollection).where(IntelCollection.tenant_id == p.tenant_id, IntelCollection.is_shared.is_(True)); total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows = (await db.execute(stmt.order_by(IntelCollection.name).limit(limit).offset(offset))).scalars().all(); provenance = await build_provenance(db, sources=None); provenance.note = "Shared means tenant-internal. Cross-tenant publication remains unavailable."; return ListResponse(data=[SharingGroupOut.model_validate(x) for x in rows], page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total), provenance=provenance)
