"""Connector capability registry — safe metadata only.

This module derives capability metadata from application configuration.
It never returns URLs, tokens, or any other secret values; those stay inside
SecretStr fields and are never serialised by this layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.core.config import Settings

#: Delivery-adapter actions backed by an outbound connector.
DELIVERY_ACTIONS: frozenset[str] = frozenset(
    {"slack.notify", "jira.issue.create", "siem.push"}
)

#: Internal actions served by future workers; advertised as planned/unavailable
#: until the worker implementation exists. These are never delivered via the
#: connector delivery worker.
INTERNAL_ACTIONS: frozenset[str] = frozenset(
    {"case.create", "report.generate", "endpoint.command.request"}
)

#: Complete set of actions accepted anywhere in the platform.
ALL_ACTIONS: frozenset[str] = DELIVERY_ACTIONS | INTERNAL_ACTIONS

ConfigState = Literal["configured", "not_configured", "planned"]


@dataclass(frozen=True)
class CapabilityEntry:
    """Safe, public metadata for a single action/connector capability."""

    action: str
    connector_type: str
    enabled: bool
    config_state: ConfigState
    config_reason: str


def build_capability_registry(settings: Settings) -> list[CapabilityEntry]:
    """Return capability metadata derived solely from configuration.

    Secrets are never included in the returned entries.  Callers may safely
    serialise and return this list to authenticated tenants.
    """
    entries: list[CapabilityEntry] = []

    # --- slack.notify ---------------------------------------------------
    if settings.slack_webhook_url:
        entries.append(
            CapabilityEntry(
                action="slack.notify",
                connector_type="slack",
                enabled=True,
                config_state="configured",
                config_reason="Webhook URL is set.",
            )
        )
    else:
        entries.append(
            CapabilityEntry(
                action="slack.notify",
                connector_type="slack",
                enabled=False,
                config_state="not_configured",
                config_reason="SLACK_WEBHOOK_URL is not set.",
            )
        )

    # --- jira.issue.create ----------------------------------------------
    jira_ok = bool(
        settings.jira_base_url and settings.jira_email and settings.jira_api_token
    )
    if jira_ok:
        entries.append(
            CapabilityEntry(
                action="jira.issue.create",
                connector_type="jira",
                enabled=True,
                config_state="configured",
                config_reason="Base URL, email, and API token are set.",
            )
        )
    else:
        missing = [
            name
            for name, value in (
                ("JIRA_BASE_URL", settings.jira_base_url),
                ("JIRA_EMAIL", settings.jira_email),
                ("JIRA_API_TOKEN", settings.jira_api_token),
            )
            if not value
        ]
        entries.append(
            CapabilityEntry(
                action="jira.issue.create",
                connector_type="jira",
                enabled=False,
                config_state="not_configured",
                config_reason=f"Missing: {', '.join(missing)}.",
            )
        )

    # --- siem.push ------------------------------------------------------
    if settings.siem_webhook_url:
        entries.append(
            CapabilityEntry(
                action="siem.push",
                connector_type="siem_webhook",
                enabled=True,
                config_state="configured",
                config_reason="Webhook URL is set.",
            )
        )
    else:
        entries.append(
            CapabilityEntry(
                action="siem.push",
                connector_type="siem_webhook",
                enabled=False,
                config_state="not_configured",
                config_reason="SIEM_WEBHOOK_URL is not set.",
            )
        )

    # --- Internal / planned actions -------------------------------------
    for action, reason in (
        ("case.create", "Worker implementation is planned; no delivery adapter required."),
        (
            "report.generate",
            "Worker implementation is planned; no delivery adapter required.",
        ),
        (
            "endpoint.command.request",
            "Worker implementation is planned; requires dual approval; "
            "no automatic replay permitted.",
        ),
    ):
        entries.append(
            CapabilityEntry(
                action=action,
                connector_type="internal",
                enabled=False,
                config_state="planned",
                config_reason=reason,
            )
        )

    return entries


def enabled_delivery_actions(settings: Settings) -> frozenset[str]:
    """Return the set of delivery-adapter actions that have a configured connector."""
    return frozenset(
        entry.action
        for entry in build_capability_registry(settings)
        if entry.connector_type != "internal" and entry.enabled
    )


def all_enabled_actions(settings: Settings) -> frozenset[str]:
    """Return the set of all actions that are currently enabled.

    This includes delivery-adapter actions with a configured connector.
    Internal/planned actions are never included until their workers are
    integrated and the capability entry is updated to ``enabled=True``.
    """
    return frozenset(
        entry.action for entry in build_capability_registry(settings) if entry.enabled
    )


def connector_health(settings: Settings) -> list[dict]:
    """Derive per-connector health from configuration and state.

    No network probes are issued; health is inferred from whether all required
    configuration values are present.  Future active probing (e.g., a
    lightweight ping against each endpoint) is planned but not yet implemented.

    Returns a list of dicts safe for API serialisation.
    """
    entries = build_capability_registry(settings)
    result = []
    for entry in entries:
        if entry.connector_type == "internal":
            # Internal actions do not have a delivery connector; skip.
            continue
        result.append(
            {
                "action": entry.action,
                "connector_type": entry.connector_type,
                "status": "healthy" if entry.enabled else "degraded",
                "config_state": entry.config_state,
                "config_reason": entry.config_reason,
                "active_probe": "planned",
            }
        )
    return result
