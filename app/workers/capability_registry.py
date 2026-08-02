"""Connector capability registry.

Tracks which action adapters are currently enabled, combining external
connectors (Slack, Jira, SIEM) with internal handlers.
Playbook creation and dispatch MUST validate against this registry so
unavailable actions are rejected immediately rather than queued silently.

External connectors are enabled only when their credentials are present in
the environment.  The internal actions ``case.create`` and
``report.generate`` are always enabled.  ``endpoint.command.request`` is
internal but requires ``COMMAND_SIGNING_KEY`` to be configured — it is
registered as *disabled* at module load time and re-registered as *enabled*
by ``sync_external_connectors`` when the key is present.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ActionKind = Literal["internal", "external"]


@dataclass(frozen=True)
class ActionCapability:
    action: str
    kind: ActionKind
    enabled: bool
    description: str = ""


class CapabilityRegistry:
    """Registry of known and enabled action adapters.

    Call ``register`` during startup for every adapter (external connectors
    from the delivery registry, internal handlers unconditionally).  Query
    ``is_enabled`` at playbook-create and dispatch time to produce a
    deterministic rejection rather than a silent dead-letter.
    """

    def __init__(self) -> None:
        self._capabilities: dict[str, ActionCapability] = {}

    def register(self, cap: ActionCapability) -> None:
        self._capabilities[cap.action] = cap

    def is_enabled(self, action: str) -> bool:
        cap = self._capabilities.get(action)
        return cap is not None and cap.enabled

    def enabled_actions(self) -> set[str]:
        return {k for k, v in self._capabilities.items() if v.enabled}

    def all_capabilities(self) -> list[ActionCapability]:
        return sorted(self._capabilities.values(), key=lambda c: c.action)

    def validate_actions(self, actions: list[str]) -> list[str]:
        """Return the subset of *actions* that are unknown or disabled."""
        enabled = self.enabled_actions()
        return [a for a in actions if a not in enabled]


# ---------------------------------------------------------------------------
# Process-wide singleton — imported everywhere by name.
# ---------------------------------------------------------------------------

capability_registry = CapabilityRegistry()

# case.create and report.generate are unconditionally available.
# endpoint.command.request starts disabled; sync_external_connectors
# promotes it to enabled once COMMAND_SIGNING_KEY is confirmed present.
_INTERNAL_ACTIONS: dict[str, str] = {
    "case.create": "Create a new investigation case via the domain service.",
    "report.generate": "Generate a threat-intelligence report via the AI service.",
    "endpoint.command.request": (
        "Submit a signed, expiring, allowlisted command request to an enrolled"
        " endpoint agent.  Requires dual approval and a configured"
        " COMMAND_SIGNING_KEY."
    ),
}

_ALWAYS_ENABLED_INTERNAL: frozenset[str] = frozenset({"case.create", "report.generate"})

for _action, _desc in _INTERNAL_ACTIONS.items():
    capability_registry.register(
        ActionCapability(
            action=_action,
            kind="internal",
            enabled=_action in _ALWAYS_ENABLED_INTERNAL,
            description=_desc,
        )
    )


def sync_external_connectors(connectors: dict) -> None:
    """Update external-connector and signing-key-dependent action enablement.

    *connectors* is the **complete** connector map returned by
    ``app.workers.connector_delivery.build_all_connectors()``, which
    includes both external connectors and the internal action handlers.
    It must be called *after* all handlers have been added to the map so
    that ``endpoint.command.request`` is correctly marked enabled when
    ``COMMAND_SIGNING_KEY`` is configured.
    """
    _external_actions: dict[str, str] = {
        "slack.notify": "Post a message to a Slack channel via webhook.",
        "jira.issue.create": "Create a Jira issue via the REST API.",
        "siem.push": "Push an event to a SIEM webhook endpoint.",
    }
    for action, description in _external_actions.items():
        capability_registry.register(
            ActionCapability(
                action=action,
                kind="external",
                enabled=action in connectors,
                description=description,
            )
        )

    # endpoint.command.request is internal but requires COMMAND_SIGNING_KEY.
    # Re-register with the actual enabled state based on the built connectors.
    capability_registry.register(
        ActionCapability(
            action="endpoint.command.request",
            kind="internal",
            enabled="endpoint.command.request" in connectors,
            description=_INTERNAL_ACTIONS["endpoint.command.request"],
        )
    )
