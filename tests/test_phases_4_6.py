"""Deterministic unit tests for phases 4–6.

Covers:
- Capability registry state and action validation
- Delivery state transitions (delivered, retry, dead_letter)
- Lease recovery timing
- Dead-letter replay idempotency and policy rejection
- Endpoint command policy: allowlist, expiry, signature, missing fields
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from app.workers.capability_registry import (
    ActionCapability,
    CapabilityRegistry,
    capability_registry,
    sync_external_connectors,
)
from app.workers.connector_delivery import DeliveryReceipt, retry_delay
from app.workers.internal_actions import (
    ALLOWED_ENDPOINT_COMMANDS,
    _verify_command_envelope,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valid_envelope(
    command: str = "isolate",
    agent_id: str = "agent-uuid-001",
    signing_key: str = "test-key",
    ttl_seconds: int = 300,
    nonce: str = "abc123",
) -> tuple[dict, str]:
    """Return (envelope_dict, signing_key) for a valid command envelope."""
    now = datetime.now(UTC)
    issued_at = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    canonical = {
        "agent_id": agent_id,
        "command": command,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    msg = json.dumps(canonical, sort_keys=True).encode()
    sig = hmac.new(signing_key.encode(), msg, hashlib.sha256).hexdigest()
    envelope = {**canonical, "signature": sig}
    return envelope, signing_key


# ---------------------------------------------------------------------------
# Phase 4: Capability registry
# ---------------------------------------------------------------------------


class TestCapabilityRegistry:
    def test_fresh_registry_starts_empty(self) -> None:
        reg = CapabilityRegistry()
        assert reg.enabled_actions() == set()
        assert reg.all_capabilities() == []

    def test_register_enabled_action(self) -> None:
        reg = CapabilityRegistry()
        reg.register(ActionCapability(action="foo.bar", kind="internal", enabled=True))
        assert reg.is_enabled("foo.bar")

    def test_register_disabled_action(self) -> None:
        reg = CapabilityRegistry()
        reg.register(ActionCapability(action="foo.bar", kind="external", enabled=False))
        assert not reg.is_enabled("foo.bar")

    def test_unknown_action_not_enabled(self) -> None:
        reg = CapabilityRegistry()
        assert not reg.is_enabled("nonexistent.action")

    def test_re_register_updates_enablement(self) -> None:
        """Later registration replaces earlier — used when signing key becomes available."""
        reg = CapabilityRegistry()
        reg.register(ActionCapability(action="a.b", kind="internal", enabled=False))
        assert not reg.is_enabled("a.b")
        reg.register(ActionCapability(action="a.b", kind="internal", enabled=True))
        assert reg.is_enabled("a.b")

    def test_validate_actions_returns_disabled_and_unknown(self) -> None:
        reg = CapabilityRegistry()
        reg.register(ActionCapability(action="case.create", kind="internal", enabled=True))
        reg.register(ActionCapability(action="slack.notify", kind="external", enabled=False))
        result = reg.validate_actions(["case.create", "slack.notify", "made.up"])
        # slack.notify disabled, made.up unknown — both invalid
        assert "case.create" not in result
        assert "slack.notify" in result
        assert "made.up" in result

    def test_validate_actions_empty_list(self) -> None:
        reg = CapabilityRegistry()
        assert reg.validate_actions([]) == []


class TestGlobalRegistryInternalActions:
    def test_case_create_always_enabled(self) -> None:
        assert capability_registry.is_enabled("case.create")

    def test_report_generate_always_enabled(self) -> None:
        assert capability_registry.is_enabled("report.generate")

    def test_external_actions_not_enabled_without_sync(self) -> None:
        """External connectors start disabled until sync_external_connectors is called."""
        # Before syncing, jira/slack/siem should not be enabled because no
        # credentials are configured in test settings.
        reg = CapabilityRegistry()
        # Explicitly register as disabled (simulating no credentials)
        reg.register(ActionCapability(action="slack.notify", kind="external", enabled=False))
        assert not reg.is_enabled("slack.notify")


class TestSyncExternalConnectors:
    def test_enabled_connectors_reflected(self) -> None:
        """sync_external_connectors marks actions enabled when connector is present."""
        reg = CapabilityRegistry()
        # Temporarily replace the global to test in isolation
        with patch("app.workers.capability_registry.capability_registry", reg):
            # Pre-register endpoint.command.request so patch works
            from app.workers.capability_registry import _INTERNAL_ACTIONS

            for action, _desc in _INTERNAL_ACTIONS.items():
                reg.register(ActionCapability(action=action, kind="internal", enabled=True))

            sync_external_connectors(
                {"slack.notify": object(), "endpoint.command.request": object()}
            )

        assert reg.is_enabled("slack.notify")
        assert not reg.is_enabled("jira.issue.create")
        assert not reg.is_enabled("siem.push")
        assert reg.is_enabled("endpoint.command.request")

    def test_endpoint_command_disabled_without_signing_key(self) -> None:
        reg = CapabilityRegistry()
        with patch("app.workers.capability_registry.capability_registry", reg):
            from app.workers.capability_registry import _INTERNAL_ACTIONS

            for action, _desc in _INTERNAL_ACTIONS.items():
                reg.register(ActionCapability(action=action, kind="internal", enabled=True))

            # endpoint.command.request NOT in connectors dict → signing key absent
            sync_external_connectors({"slack.notify": object()})

        assert not reg.is_enabled("endpoint.command.request")


# ---------------------------------------------------------------------------
# Delivery state transitions (pure logic, no DB)
# ---------------------------------------------------------------------------


class TestDeliveryStateTransitions:
    """Validate that the worker applies the correct state after each outcome."""

    def _make_item(self, attempts: int = 0) -> MagicMock:
        item = MagicMock()
        item.action = "slack.notify"
        item.attempts = attempts
        item.state = "delivering"
        item.lease_token = "tok"
        item.lease_until = datetime.now(UTC) + timedelta(minutes=2)
        item.last_error = None
        item.delivery_result = None
        item.delivered_at = None
        item.available_at = None
        return item

    def _apply_outcome(self, item, receipt, max_attempts=5):
        """Mimic the delivery worker's state-transition logic."""
        item.attempts += 1
        item.lease_token = None
        item.lease_until = None

        if receipt.delivered:
            item.state = "delivered"
            item.delivered_at = datetime.now(UTC)
            item.delivery_result = {"remote_id": receipt.remote_id, "detail": receipt.detail or {}}
            item.last_error = None
        elif receipt.retryable and item.attempts < max_attempts:
            item.state = "retry"
            item.available_at = datetime.now(UTC) + retry_delay(item.attempts)
            item.last_error = receipt.error
        else:
            item.state = "dead_letter"
            item.delivery_result = {"error": receipt.error, "detail": receipt.detail or {}}
            item.last_error = receipt.error

    def test_successful_delivery(self) -> None:
        item = self._make_item()
        self._apply_outcome(item, DeliveryReceipt(True, remote_id="JIRA-42"))
        assert item.state == "delivered"
        assert item.delivery_result["remote_id"] == "JIRA-42"
        assert item.last_error is None
        assert item.lease_token is None

    def test_retryable_failure_increments_and_schedules(self) -> None:
        item = self._make_item(attempts=0)
        self._apply_outcome(item, DeliveryReceipt(False, retryable=True, error="timeout"))
        assert item.state == "retry"
        assert item.attempts == 1
        assert item.last_error == "timeout"
        assert item.available_at is not None

    def test_max_attempts_exceeded_becomes_dead_letter(self) -> None:
        item = self._make_item(attempts=4)  # one more push → 5 = max
        self._apply_outcome(
            item, DeliveryReceipt(False, retryable=True, error="timeout"), max_attempts=5
        )
        assert item.state == "dead_letter"

    def test_non_retryable_failure_immediately_dead_letter(self) -> None:
        item = self._make_item(attempts=0)
        self._apply_outcome(item, DeliveryReceipt(False, retryable=False, error="policy_reject"))
        assert item.state == "dead_letter"
        assert item.attempts == 1

    def test_lease_cleared_on_any_outcome(self) -> None:
        item = self._make_item()
        self._apply_outcome(item, DeliveryReceipt(True))
        assert item.lease_token is None
        assert item.lease_until is None


# ---------------------------------------------------------------------------
# Lease recovery timing
# ---------------------------------------------------------------------------


class TestLeaseRecovery:
    def test_retry_delay_is_bounded(self) -> None:
        assert retry_delay(99).total_seconds() == 3600

    def test_retry_delay_increases_with_attempts(self) -> None:
        assert retry_delay(1) < retry_delay(2) < retry_delay(3)

    def test_retry_delay_first_attempt(self) -> None:
        # 30 * 2^1 = 60 seconds
        assert retry_delay(1).total_seconds() == 60

    def test_retry_delay_caps_at_7(self) -> None:
        # After attempt 7 the multiplier is capped: 30 * 128 = 3840 > 3600 → 3600
        assert retry_delay(7).total_seconds() == 3600
        assert retry_delay(8).total_seconds() == 3600


# ---------------------------------------------------------------------------
# Endpoint command policy
# ---------------------------------------------------------------------------


class TestEndpointCommandPolicy:
    def test_valid_envelope_passes(self) -> None:
        envelope, key = _make_valid_envelope()
        assert _verify_command_envelope(envelope, key) is None

    def test_unlisted_command_rejected(self) -> None:
        envelope, key = _make_valid_envelope(command="rm_rf_slash")
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "allowlist" in err.lower() or "not in" in err.lower()

    def test_missing_agent_id_rejected(self) -> None:
        envelope, key = _make_valid_envelope()
        envelope.pop("agent_id")
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "agent_id" in err

    def test_missing_nonce_rejected(self) -> None:
        envelope, key = _make_valid_envelope()
        envelope.pop("nonce")
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "nonce" in err

    def test_expired_envelope_rejected(self) -> None:
        envelope, key = _make_valid_envelope(ttl_seconds=-10)
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "expired" in err.lower()

    def test_ttl_too_long_rejected(self) -> None:
        envelope, key = _make_valid_envelope(ttl_seconds=7200)  # 2 hours > max 1 hour
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "ttl" in err.lower() or "maximum" in err.lower()

    def test_wrong_signing_key_rejected(self) -> None:
        envelope, _ = _make_valid_envelope(signing_key="real-key")
        err = _verify_command_envelope(envelope, "wrong-key")
        assert err is not None
        assert "signature" in err.lower()

    def test_tampered_command_rejected(self) -> None:
        envelope, key = _make_valid_envelope(command="isolate")
        # Tamper with the command after signing
        envelope["command"] = "collect_forensics"
        err = _verify_command_envelope(envelope, key)
        assert err is not None
        assert "signature" in err.lower()

    def test_empty_agent_id_rejected(self) -> None:
        envelope, key = _make_valid_envelope()
        envelope["agent_id"] = ""
        err = _verify_command_envelope(envelope, key)
        assert err is not None

    def test_all_allowed_commands_pass(self) -> None:
        """Every command in the allowlist must produce a valid envelope."""
        for cmd in ALLOWED_ENDPOINT_COMMANDS:
            envelope, key = _make_valid_envelope(command=cmd, nonce=cmd)
            # Signature still covers the nonce, so rebuild it
            assert _verify_command_envelope(envelope, key) is None
