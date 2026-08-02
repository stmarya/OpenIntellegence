"""Alerting helpers shared by API and workers."""

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
    """Return a deterministic SHA-256 fingerprint for an alert occurrence.

    The bucket parameter is deliberately limited to the current UTC hour. A
    caller enforcing a rule cooldown must additionally lock and aggregate a
    matching rule/entity alert over the configured cooldown interval, so a
    bucket transition cannot create a duplicate alert.
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
    return sha256(raw.encode()).hexdigest()
