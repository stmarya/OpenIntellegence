"""Agent identity, software inventory, and CVE exposure matching."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_gateway.mtls import AgentCertificateAuthority, CertificateAuthorityError
from app.api.schemas import SoftwareItem
from app.core.config import Settings
from app.db.models import (
    Agent,
    AgentStatus,
    Asset,
    AssetExposure,
    InstalledSoftware,
    Vulnerability,
)

#: Remediation windows by severity, in days. Mirrors the CISA KEV posture:
#: a known-exploited flaw gets a fortnight regardless of its score.
SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 90,
}
KEV_SLA_DAYS = 14

# Settings is a pydantic model and therefore unhashable, so this cannot be
# memoised by cache key. A module-level singleton gives the same
# once-per-process construction without needing one.
_certificate_authority: AgentCertificateAuthority | None = None


def get_certificate_authority(settings: Settings) -> AgentCertificateAuthority:
    """Return the process-wide agent certificate authority."""
    global _certificate_authority
    if _certificate_authority is not None:
        return _certificate_authority
    try:
        _certificate_authority = AgentCertificateAuthority.from_settings(settings)
    except CertificateAuthorityError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Agent certificate authority is not configured: {exc}",
        ) from exc
    return _certificate_authority


async def resolve_agent_from_request(
    request: Request, db: AsyncSession, settings: Settings
) -> Agent:
    """Identify the calling agent from its verified client certificate.

    The reverse proxy terminates mTLS and forwards the verified certificate
    in ``X-Client-Cert``. We re-read the identity from the certificate rather
    than trusting any header that merely *claims* an agent id.
    """
    raw_cert = request.headers.get("x-client-cert")
    if not raw_cert:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Client certificate required. Agents must authenticate with mTLS.",
        )

    # nginx forwards the PEM percent-encoded on a single line.
    cert_pem = unquote(raw_cert).replace("\t", "\n")

    ca = get_certificate_authority(settings)
    try:
        agent_id, tenant_id = ca.parse_client_certificate(cert_pem)
    except (CertificateAuthorityError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, f"Invalid client certificate: {exc}"
        ) from exc

    agent = (
        await db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()

    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown agent.")

    if agent.status == AgentStatus.REVOKED:
        # A revoked agent may still hold a syntactically valid certificate
        # until it expires; revocation is enforced here, not only by CRL.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "This agent has been revoked. Re-enroll it to restore reporting.",
        )

    if agent.cert_expires_at and agent.cert_expires_at < datetime.now(UTC):
        agent.status = AgentStatus.CERT_EXPIRED
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Agent certificate has expired. Renew it before reporting.",
        )

    return agent


async def apply_software_inventory(
    db: AsyncSession, agent: Agent, software: Sequence[SoftwareItem]
) -> None:
    """Reconcile the reported inventory against what we already store.

    Rows are updated in place and unseen rows are marked removed rather than
    deleted: knowing that a vulnerable package *was* present until last
    Tuesday matters during an incident.
    """
    if agent.asset_id is None:
        return

    now = datetime.now(UTC)

    existing_rows = (
        await db.execute(
            select(InstalledSoftware).where(InstalledSoftware.asset_id == agent.asset_id)
        )
    ).scalars().all()
    existing = {(row.name, row.version): row for row in existing_rows}

    reported_keys: set[tuple[str, str | None]] = set()

    for item in software:
        key = (item.name, item.version)
        reported_keys.add(key)

        if (row := existing.get(key)) is not None:
            row.last_seen = now
            row.removed_at = None
            row.cpe_uri = item.cpe_uri or row.cpe_uri
            continue

        db.add(
            InstalledSoftware(
                asset_id=agent.asset_id,
                name=item.name,
                version=item.version,
                vendor=item.vendor,
                cpe_uri=item.cpe_uri,
                first_seen=now,
                last_seen=now,
            )
        )

    for key, row in existing.items():
        if key not in reported_keys and row.removed_at is None:
            row.removed_at = now

    await db.flush()


def _sla_due(severity: str | None, is_kev: bool, detected_at: datetime) -> datetime | None:
    if is_kev:
        return detected_at + timedelta(days=KEV_SLA_DAYS)
    if severity and severity in SLA_DAYS:
        return detected_at + timedelta(days=SLA_DAYS[severity])
    # No score means no defensible deadline. Leaving this NULL is more
    # honest than inventing one.
    return None


async def recompute_exposure(db: AsyncSession, asset_id: str | None) -> int:
    """Match installed software against known CVEs.

    Two rules, both recorded in ``matched_via``:

    * ``cpe`` — the software's CPE URI appears in the CVE's CPE list. Precise.
    * ``vendor_product`` — CISA KEV vendor and product match the software
      name. Broader, and the only rule available for KEV entries, which
      carry no CPE data.

    Exposures that no longer match are resolved rather than deleted so the
    remediation history survives.
    """
    if asset_id is None:
        return 0

    asset = await db.get(Asset, asset_id)
    if asset is None:
        return 0

    now = datetime.now(UTC)

    software = (
        await db.execute(
            select(InstalledSoftware).where(
                InstalledSoftware.asset_id == asset_id,
                InstalledSoftware.removed_at.is_(None),
            )
        )
    ).scalars().all()

    cpe_index = {row.cpe_uri: row for row in software if row.cpe_uri}
    name_index = {row.name.lower(): row for row in software}

    existing_rows = (
        await db.execute(
            select(AssetExposure).where(
                AssetExposure.asset_id == asset_id, AssetExposure.resolved_at.is_(None)
            )
        )
    ).scalars().all()
    existing = {row.vulnerability_id: row for row in existing_rows}

    matched: set[str] = set()
    vulnerabilities = (await db.execute(select(Vulnerability))).scalars().all()

    for vuln in vulnerabilities:
        match_rule: str | None = None
        evidence: str | None = None

        for cpe in vuln.cpe_uris or []:
            if cpe in cpe_index:
                match_rule, evidence = "cpe", cpe
                break

        if match_rule is None and vuln.product:
            product = vuln.product.lower()
            for name, row in name_index.items():
                if product in name or name in product:
                    match_rule = "vendor_product"
                    evidence = f"{vuln.vendor or '?'} / {vuln.product} ~ {row.name}"
                    break

        if match_rule is None:
            continue

        matched.add(vuln.id)
        if vuln.id in existing:
            continue

        db.add(
            AssetExposure(
                asset_id=asset_id,
                vulnerability_id=vuln.id,
                matched_via=match_rule,
                match_evidence=evidence,
                detected_at=now,
                sla_due_at=_sla_due(vuln.severity, vuln.is_kev, now),
            )
        )

    for vuln_id, row in existing.items():
        if vuln_id not in matched:
            row.resolved_at = now

    await db.flush()
    return len(matched)


async def mark_stale_agents(db: AsyncSession, settings: Settings) -> int:
    """Flag agents that have missed too many heartbeats.

    Called by a scheduled job. Silence is a finding, so it is written to the
    record instead of being inferred at read time.
    """
    cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.agent_heartbeat_interval_seconds * settings.agent_stale_after_missed
    )

    rows = (
        await db.execute(
            select(Agent).where(
                Agent.status == AgentStatus.ACTIVE,
                Agent.last_heartbeat_at.is_not(None),
                Agent.last_heartbeat_at < cutoff,
            )
        )
    ).scalars().all()

    for agent in rows:
        agent.status = AgentStatus.STALE

    await db.flush()
    return len(rows)
