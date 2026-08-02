"""Shared alerting primitives used by the API and evaluation worker."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256


def alert_fingerprint(
    tenant_id: str,
    *,
    rule_id: str | None,
    entity_type: str | None,
    entity_id: str | None,
    severity: str,
    bucket: datetime,
) -> str:
    """Return the canonical hourly fingerprint for one alert occurrence.

    The hourly bucket deduplicates same-hour events. A cooldown that spans an
    hour boundary must be handled by a locked, rule/entity lookup in the
    evaluation worker; callers must not use a changed fingerprint as a reason
    to create a duplicate alert.
    """
    raw = "|".join(
        (
            tenant_id,
            rule_id or "manual",
            entity_type or "",
            entity_id or "",
            severity,
            bucket.strftime("%Y%m%d%H"),
        )
    )
    return sha256(raw.encode("utf-8")).hexdigest()
