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

    The bucket parameter is truncated to the current UTC hour so that
    multiple occurrences within the same hour share the same fingerprint.
    Cross-hour cooldown aggregation is handled separately by the worker's
    cooldown lookup, which queries existing alerts by rule/entity within
    ``cooldown_minutes`` regardless of bucket boundary.
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
