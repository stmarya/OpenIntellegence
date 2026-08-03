"""Seed an explicitly labelled synthetic CTI graph for development testing.

This command never creates a tenant and refuses to run in production. Every edge
is marked synthetic_test_only so test evidence cannot be mistaken for telemetry.
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from app.core.config import get_settings
from app.db.base import get_session_factory
from app.db.models import Tenant
from app.db.platform_models import EntityRelationship

FIXTURE_KIND = "synthetic_test_only"
SEED_ACTOR = "system:synthetic_graph_seed"

SYNTHETIC_RELATIONSHIPS = (
    (
        "campaign",
        "synthetic-campaign-night-glass",
        "attributed_to",
        "threat_actor",
        "synthetic-actor-orchid",
        "Synthetic Night Glass campaign",
        "Synthetic Orchid actor",
        0.78,
    ),
    (
        "threat_actor",
        "synthetic-actor-orchid",
        "uses",
        "malware",
        "synthetic-malware-emberdrop",
        "Synthetic Orchid actor",
        "Synthetic EmberDrop malware",
        0.91,
    ),
    (
        "malware",
        "synthetic-malware-emberdrop",
        "communicates_with",
        "indicator",
        "synthetic-c2.example.invalid",
        "Synthetic EmberDrop malware",
        "synthetic-c2.example.invalid",
        0.88,
    ),
    (
        "indicator",
        "synthetic-c2.example.invalid",
        "observed_on",
        "asset",
        "synthetic-asset-workstation-07",
        "synthetic-c2.example.invalid",
        "Synthetic workstation 07",
        0.72,
    ),
    (
        "asset",
        "synthetic-asset-workstation-07",
        "affected_by",
        "vulnerability",
        "CVE-2099-0001",
        "Synthetic workstation 07",
        "CVE-2099-0001 (synthetic)",
        0.96,
    ),
    (
        "vulnerability",
        "CVE-2099-0001",
        "exploited_by",
        "malware",
        "synthetic-malware-emberdrop",
        "CVE-2099-0001 (synthetic)",
        "Synthetic EmberDrop malware",
        0.84,
    ),
    (
        "campaign",
        "synthetic-campaign-night-glass",
        "targets",
        "sector",
        "synthetic-sector-manufacturing",
        "Synthetic Night Glass campaign",
        "Synthetic manufacturing sector",
        0.69,
    ),
    (
        "investigation",
        "synthetic-investigation-001",
        "investigates",
        "campaign",
        "synthetic-campaign-night-glass",
        "Synthetic investigation 001",
        "Synthetic Night Glass campaign",
        1.0,
    ),
    (
        "detection_rule",
        "synthetic-rule-emberdrop-network",
        "detects",
        "malware",
        "synthetic-malware-emberdrop",
        "Synthetic EmberDrop network rule",
        "Synthetic EmberDrop malware",
        0.8,
    ),
)


async def seed(tenant_slug: str) -> tuple[int, int]:
    """Insert missing synthetic edges and return (created, existing)."""
    settings = get_settings()
    if settings.is_production:
        raise RuntimeError("Synthetic graph fixtures are forbidden in production.")

    factory = get_session_factory()
    async with factory() as session:
        tenant = (
            await session.execute(select(Tenant).where(Tenant.slug == tenant_slug))
        ).scalar_one_or_none()
        if tenant is None:
            raise RuntimeError(
                f"Tenant {tenant_slug!r} does not exist; bootstrap it before seeding fixtures."
            )

        created = 0
        existing = 0
        for (
            source_type,
            source_id,
            relationship_type,
            target_type,
            target_id,
            source_label,
            target_label,
            confidence,
        ) in SYNTHETIC_RELATIONSHIPS:
            found = await session.scalar(
                select(EntityRelationship.id).where(
                    EntityRelationship.tenant_id == tenant.id,
                    EntityRelationship.source_type == source_type,
                    EntityRelationship.source_id == source_id,
                    EntityRelationship.relationship_type == relationship_type,
                    EntityRelationship.target_type == target_type,
                    EntityRelationship.target_id == target_id,
                )
            )
            if found is not None:
                existing += 1
                continue
            session.add(
                EntityRelationship(
                    tenant_id=tenant.id,
                    source_type=source_type,
                    source_id=source_id,
                    relationship_type=relationship_type,
                    target_type=target_type,
                    target_id=target_id,
                    confidence=confidence,
                    evidence={
                        "fixture_kind": FIXTURE_KIND,
                        "note": "Synthetic graph evidence for development testing; not tenant telemetry.",
                        "source_label": source_label,
                        "target_label": target_label,
                    },
                    sources=["synthetic_graph_fixture"],
                    created_by=SEED_ACTOR,
                )
            )
            created += 1

        await session.commit()
        return created, existing


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed a labelled synthetic CTI relationship graph for development"
    )
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument(
        "--confirm-synthetic",
        action="store_true",
        help="Acknowledge that fixture rows are test-only and not tenant telemetry",
    )
    args = parser.parse_args()
    if not args.confirm_synthetic:
        parser.error("--confirm-synthetic is required")
    try:
        created, existing = asyncio.run(seed(args.tenant_slug))
    except RuntimeError as exc:
        parser.error(str(exc))
    print(
        f"Synthetic graph ready: {created} relationship(s) created, "
        f"{existing} already present."
    )
    print("Test seed: campaign / synthetic-campaign-night-glass")


if __name__ == "__main__":
    main()
