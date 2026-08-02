"""Workspace identity, access principals, and tenant read surfaces.

What this module deliberately does not do
-----------------------------------------
There is no ``User`` table and no ``Role`` table in this platform. Callers
authenticate with an API key that carries a set of scopes, and that key *is*
the principal. Building a fake user directory here would make the console
look like a conventional IAM product while reporting nothing real, so these
endpoints describe the access model that exists and state plainly which one
does not.

The same applies to sharing groups. Collections can be marked shared, but
that sharing is tenant-internal; there is no cross-tenant sharing mechanism
to report, and an empty list here must not be read as "nothing is shared
externally" when the capability was never built.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from app.api.schemas import ListResponse, Page
from app.core.deps import CurrentPrincipal, DbSession, Principal, Scope, require_scope
from app.db.governance_models import IntelCollection
from app.db.models import ApiKey, ApiKeyStatus, Tenant
from app.services.provenance import build_provenance

router = APIRouter()

ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
KeyReader = Annotated[Principal, Depends(require_scope(Scope.APIKEY_READ))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


#: Human-readable meaning of every scope the platform enforces.
#:
#: ``admin`` is listed but is not grantable through the API key endpoint. It
#: is included so the console can explain a scope it may encounter on an
#: existing key rather than rendering it as an unknown string.
SCOPE_CATALOGUE: dict[str, str] = {
    Scope.READ: "Read intelligence, assets, cases, and reporting surfaces.",
    Scope.WRITE: "Create and modify investigations, cases, alert rules, and sightings.",
    Scope.IOC: "Read indicator values and their enrichment state.",
    Scope.ENROLL: "Enrol endpoint agents and submit heartbeats.",
    Scope.APIKEY_READ: "List API keys and their scopes in masked form.",
    Scope.APIKEY_WRITE: "Mint and revoke API keys, bounded by the scopes the caller holds.",
    Scope.REPORT_WRITE: "Request AI report generation.",
    Scope.ADMIN: "Trigger ingestion runs and administrative operations.",
}


class SessionOut(BaseModel):
    """The caller's own session, as authenticated on this request."""

    api_key_id: str
    key_name: str
    tenant_id: str
    tenant_name: str | None
    tenant_slug: str | None
    scopes: list[str]
    rate_limit_per_hour: int
    subject_kind: str
    note: str


class AccessPrincipalOut(ORM):
    """An API key viewed as a holder of access."""

    id: str
    name: str
    masked_key: str
    scopes: list = []
    status: str
    rate_limit_per_hour: int
    created_by: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class SharingGroupOut(ORM):
    id: str
    name: str
    description: str | None = None
    purpose: str | None = None
    owner: str | None = None
    member_refs: list = []
    last_curated_at: datetime | None = None


@router.get("/me", response_model=SessionOut, summary="The caller's own session")
async def whoami(db: DbSession, principal: CurrentPrincipal) -> SessionOut:
    """Describe the authenticated caller.

    This reports an API key, not a person. The platform cannot tell you who
    is holding the key, and saying so is more useful than printing a name
    that only identifies a credential.
    """
    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == principal.tenant_id))
    ).scalar_one_or_none()

    return SessionOut(
        api_key_id=str(principal.api_key_id),
        key_name=principal.name,
        tenant_id=str(principal.tenant_id),
        tenant_name=tenant.name if tenant else None,
        tenant_slug=tenant.slug if tenant else None,
        scopes=sorted(principal.scopes),
        rate_limit_per_hour=principal.rate_limit_per_hour,
        subject_kind="api_key",
        note=(
            "This session is authenticated by an API key, not by a user account. "
            "The platform has no user directory, so the key name is a label chosen "
            "at creation time and does not identify who is currently holding it."
        ),
    )


@router.get("/tenants/current", summary="The tenant this session is scoped to")
async def current_tenant(db: DbSession, principal: ReadPrincipal) -> dict:
    """Return the tenant record backing this session.

    Only the caller's own tenant is returned. There is no endpoint that lists
    every tenant, because no session in this platform is authorised across
    tenant boundaries.
    """
    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == principal.tenant_id))
    ).scalar_one_or_none()

    if tenant is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "The tenant referenced by this API key no longer exists.",
        )

    active_keys = await db.scalar(
        select(func.count())
        .select_from(ApiKey)
        .where(
            ApiKey.tenant_id == principal.tenant_id,
            ApiKey.status != ApiKeyStatus.REVOKED,
        )
    )

    return {
        "id": str(tenant.id),
        "slug": tenant.slug,
        "name": tenant.name,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at,
        "active_principal_count": active_keys or 0,
        "isolation": {
            "model": "row_scoped_by_tenant_id",
            "cross_tenant_sharing": "not_implemented",
            "detail": (
                "Tenant-scoped tables are filtered by tenant_id on every query. "
                "No mechanism exists for sharing records between tenants, so this "
                "tenant cannot publish to or read from another one."
            ),
        },
        "generated_at": datetime.now(UTC),
    }


@router.get(
    "/access/scopes",
    summary="The scope catalogue this platform enforces",
)
async def access_scopes(principal: ReadPrincipal) -> dict:
    """Return every scope, its meaning, and whether it can be granted.

    Roles do not exist as stored objects. A principal's authority is exactly
    the set of scopes on its key, so the scope list is the whole permission
    model rather than a summary of one.
    """
    from app.api.v1.admin import GRANTABLE_SCOPES

    return {
        "tenant_id": str(principal.tenant_id),
        "scopes": [
            {
                "scope": scope,
                "description": description,
                "grantable": scope in GRANTABLE_SCOPES,
                "held_by_caller": principal.has(scope),
            }
            for scope, description in SCOPE_CATALOGUE.items()
        ],
        "role_model": {
            "named_roles": "not_implemented",
            "detail": (
                "Authority is carried directly on each API key as a scope set. "
                "There are no named roles to assign, and no role can be edited "
                "to change what an existing key may do."
            ),
        },
        "generated_at": datetime.now(UTC),
    }


@router.get(
    "/access/principals",
    response_model=ListResponse[AccessPrincipalOut],
    summary="Everything that holds access to this tenant",
)
async def access_principals(
    db: DbSession,
    principal: KeyReader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[AccessPrincipalOut]:
    """List the access principals of this tenant.

    Revoked keys are included. A roster that hides them answers "who has
    access now" but destroys the answer to "who had access last month",
    which is the question that matters after an incident.
    """
    stmt = select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(ApiKey.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    provenance = await build_provenance(db, sources=())
    provenance.note = (
        "These are API key principals, not user accounts. The platform has no "
        "user directory, so this roster cannot tell you which people hold these "
        "credentials."
    )

    return ListResponse[AccessPrincipalOut](
        data=[AccessPrincipalOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=provenance,
    )


@router.get(
    "/sharing-groups",
    response_model=ListResponse[SharingGroupOut],
    summary="Collections shared within this tenant",
)
async def sharing_groups(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[SharingGroupOut]:
    """Return collections flagged as shared.

    Sharing here means visible to the whole tenant. It does not mean shared
    with another tenant, another organisation, or any external community,
    none of which this platform can currently do.
    """
    stmt = select(IntelCollection).where(
        IntelCollection.tenant_id == principal.tenant_id,
        IntelCollection.is_shared.is_(True),
    )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await db.execute(
            stmt.order_by(IntelCollection.name.asc()).limit(limit).offset(offset)
        )
    ).scalars().all()

    provenance = await build_provenance(db, sources=None)
    provenance.note = (
        "Shared means visible to every principal in this tenant. No cross-tenant "
        "or external sharing group exists, so an empty list means nothing has been "
        "shared internally, not that external sharing is switched off."
    )

    return ListResponse[SharingGroupOut](
        data=[SharingGroupOut.model_validate(row) for row in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=provenance,
    )
