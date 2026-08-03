"""Create the first tenant and privileged API key without hardcoded credentials.

The raw key is printed once to stdout. Re-running for a tenant that already has
keys fails closed; operators must use the authenticated API for later keys.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from uuid import uuid4

from sqlalchemy import func, select

from app.core.deps import Scope
from app.core.security import generate_key
from app.db.base import get_session_factory
from app.db.models import ApiKey, ApiKeyStatus, Tenant

BOOTSTRAP_SCOPES = [
    Scope.READ,
    Scope.WRITE,
    Scope.IOC,
    Scope.ENROLL,
    Scope.APIKEY_READ,
    Scope.APIKEY_WRITE,
    Scope.REPORT_WRITE,
    Scope.ADMIN,
]


async def bootstrap(slug: str, name: str, key_name: str) -> str:
    """Create the tenant when absent and mint its first one-time-displayed key."""
    factory = get_session_factory()
    async with factory() as session:
        tenant = (
            await session.execute(select(Tenant).where(Tenant.slug == slug))
        ).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(id=str(uuid4()), slug=slug, name=name, is_active=True)
            session.add(tenant)
            await session.flush()
        existing = await session.scalar(
            select(func.count())
            .select_from(ApiKey)
            .where(ApiKey.tenant_id == tenant.id)
        )
        if existing:
            raise RuntimeError(
                "Tenant already has an API key; bootstrap refuses to mint another."
            )
        generated = generate_key()
        session.add(
            ApiKey(
                id=str(uuid4()),
                tenant_id=tenant.id,
                name=key_name,
                key_id=generated.key_id,
                prefix=generated.prefix,
                secret_hash=generated.secret_hash,
                masked_key=generated.masked,
                scopes=BOOTSTRAP_SCOPES,
                rate_limit_per_hour=1000,
                status=ApiKeyStatus.ACTIVE,
                single_use=False,
                created_by="system:bootstrap",
            )
        )
        await session.commit()
        return generated.raw_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap one OpenIntelligence tenant")
    parser.add_argument("--slug", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--key-name", default="Initial administrator")
    args = parser.parse_args()
    try:
        raw = asyncio.run(bootstrap(args.slug, args.name, args.key_name))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    print("Store this key now; it will never be shown again:")
    print(raw)


if __name__ == "__main__":
    main()
