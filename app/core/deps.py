"""FastAPI dependencies: authentication, scope enforcement, rate limiting."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.config import Settings, get_settings
from app.core.ratelimit import InMemoryRateLimiter, RateLimiter
from app.db.base import get_db
from app.db.models import ApiKey, ApiKeyStatus


class Scope:
    """Canonical scope strings.

    Scopes are named after the resource and verb so a forbidden response can
    tell the caller exactly what is missing — ``apikey.read`` rather than a
    bare 403.
    """

    READ = "read"
    WRITE = "write"
    IOC = "ioc"
    ENROLL = "enroll"
    APIKEY_READ = "apikey.read"
    APIKEY_WRITE = "apikey.write"
    REPORT_WRITE = "report.write"
    ADMIN = "admin"


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    api_key_id: str
    tenant_id: str
    name: str
    scopes: frozenset[str]
    rate_limit_per_hour: int

    def has(self, scope: str) -> bool:
        return Scope.ADMIN in self.scopes or scope in self.scopes


_limiter: RateLimiter | InMemoryRateLimiter | None = None


def set_rate_limiter(limiter: RateLimiter | InMemoryRateLimiter) -> None:
    global _limiter
    _limiter = limiter


def get_rate_limiter() -> RateLimiter | InMemoryRateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = InMemoryRateLimiter()
    return _limiter


_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing API key.",
    headers={"WWW-Authenticate": 'Bearer realm="openintelligence"'},
)


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


async def get_principal(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    """Authenticate the caller and enforce their rate limit.

    Every failure path returns the same 401 with the same timing profile as
    far as is practical, so the endpoint cannot be used to enumerate valid
    key ids.
    """
    raw = _extract_key(authorization, x_api_key)
    if not raw:
        raise _UNAUTHORIZED

    parts = security.parse_key(raw)
    if parts is None:
        raise _UNAUTHORIZED

    result = await db.execute(select(ApiKey).where(ApiKey.key_id == parts.key_id))
    key = result.scalar_one_or_none()
    if key is None:
        # Still pay the Argon2 cost so a missing key and a wrong secret take
        # comparable time.
        security.verify_secret(parts.secret, security.hash_secret("decoy"))
        raise _UNAUTHORIZED

    if not security.verify_secret(parts.secret, key.secret_hash):
        raise _UNAUTHORIZED

    now = datetime.now(UTC)
    if key.status == ApiKeyStatus.REVOKED or key.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This API key has been revoked.")
    if key.expires_at is not None and key.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This API key has expired.")

    limiter = get_rate_limiter()
    verdict = await limiter.check(f"apikey:{key.key_id}", key.rate_limit_per_hour)
    response.headers.update(verdict.headers())
    if not verdict.allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Rate limit of {verdict.limit}/hour exceeded.",
            headers=verdict.headers(),
        )

    key.last_used_at = now
    request.state.tenant_id = key.tenant_id

    return Principal(
        api_key_id=key.id,
        tenant_id=key.tenant_id,
        name=key.name,
        scopes=frozenset(key.scopes or []),
        rate_limit_per_hour=key.rate_limit_per_hour,
    )


def require_scope(*scopes: str) -> Callable[[Principal], Principal]:
    """Dependency factory enforcing that the caller holds every given scope.

    The 403 body names the missing scope and the caller's current scopes.
    This mirrors the UI contract, where a locked portlet says *"requires
    `apikey.read`, your role is Analyst"* rather than just greying out.
    """

    async def dependency(
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> Principal:
        missing = [s for s in scopes if not principal.has(s)]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Insufficient scope for this endpoint.",
                    "required": list(scopes),
                    "missing": missing,
                    "granted": sorted(principal.scopes),
                },
            )
        return principal

    return dependency


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
DbSession = Annotated[AsyncSession, Depends(get_db)]
