"""Tests for the signed endpoint command envelope.

These cover the cryptography and the policy, not a delivery path — no
delivery path exists. The point of landing them now is that the signing
primitive is exercised before anything is able to act on its verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.endpoint_command_envelope import (
    MAX_TTL_SECONDS,
    build_envelope,
    sign_envelope,
    verify_envelope,
)
from app.services.endpoint_intents import ALLOWED_INTENTS

KEY = "unit-test-signing-key"


def make(**overrides) -> dict:
    envelope = build_envelope(
        agent_id="3f1b1d5e-0000-4000-8000-000000000001",
        intent_type="isolate_network",
        nonce="nonce-001",
        signing_key=KEY,
    )
    envelope.update(overrides)
    return envelope


class TestValidEnvelopes:
    def test_freshly_built_envelope_verifies(self) -> None:
        assert verify_envelope(make(), KEY) is None

    @pytest.mark.parametrize("intent", sorted(ALLOWED_INTENTS))
    def test_every_allowlisted_intent_verifies(self, intent: str) -> None:
        envelope = build_envelope(
            agent_id="agent-uuid",
            intent_type=intent,
            nonce=f"nonce-{intent}",
            signing_key=KEY,
        )
        assert verify_envelope(envelope, KEY) is None

    def test_signature_excludes_itself(self) -> None:
        """Re-signing a signed envelope must reproduce the same digest."""
        envelope = make()
        assert sign_envelope(envelope, KEY) == envelope["signature"]

    def test_key_order_does_not_change_the_signature(self) -> None:
        envelope = make()
        reordered = dict(reversed(list(envelope.items())))
        assert verify_envelope(reordered, KEY) is None


class TestAllowlist:
    def test_unlisted_intent_is_rejected(self) -> None:
        envelope = build_envelope(
            agent_id="agent-uuid",
            intent_type="run_arbitrary_shell",
            nonce="n",
            signing_key=KEY,
        )
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "allowlisted" in error

    def test_allowlist_is_checked_even_when_the_signature_is_valid(self) -> None:
        """A correctly signed envelope is still refused if the intent is not allowed.

        Signing authority is not the same as authorisation. Holding the key
        must not let a caller widen the set of things an agent will do.
        """
        envelope = build_envelope(
            agent_id="agent-uuid", intent_type="format_disk", nonce="n", signing_key=KEY
        )
        assert sign_envelope(envelope, KEY) == envelope["signature"]
        assert verify_envelope(envelope, KEY) is not None


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field", ["agent_id", "nonce", "issued_at", "expires_at", "signature"]
    )
    def test_missing_field_is_rejected(self, field: str) -> None:
        envelope = make()
        del envelope[field]
        assert verify_envelope(envelope, KEY) is not None

    @pytest.mark.parametrize("field", ["agent_id", "nonce"])
    def test_empty_field_is_rejected(self, field: str) -> None:
        assert verify_envelope(make(**{field: ""}), KEY) is not None

    def test_hostname_shaped_agent_id_is_still_accepted_but_uuid_is_the_contract(
        self,
    ) -> None:
        """The verifier cannot tell a UUID from a hostname; the caller must.

        Documented explicitly so this is understood as an accepted limitation
        rather than assumed to be enforced here.
        """
        envelope = build_envelope(
            agent_id="workstation-04.corp.local",
            intent_type="isolate_network",
            nonce="n",
            signing_key=KEY,
        )
        assert verify_envelope(envelope, KEY) is None


class TestExpiry:
    def test_expired_envelope_is_rejected(self) -> None:
        envelope = build_envelope(
            agent_id="agent-uuid",
            intent_type="isolate_network",
            nonce="n",
            signing_key=KEY,
            issued_at=datetime.now(UTC) - timedelta(hours=2),
            ttl_seconds=60,
        )
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "expired" in error.lower()

    def test_ttl_beyond_the_cap_is_rejected(self) -> None:
        envelope = build_envelope(
            agent_id="agent-uuid",
            intent_type="isolate_network",
            nonce="n",
            signing_key=KEY,
            ttl_seconds=MAX_TTL_SECONDS + 1,
        )
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "maximum" in error.lower()

    def test_ttl_exactly_at_the_cap_is_accepted(self) -> None:
        envelope = build_envelope(
            agent_id="agent-uuid",
            intent_type="isolate_network",
            nonce="n",
            signing_key=KEY,
            ttl_seconds=MAX_TTL_SECONDS,
        )
        assert verify_envelope(envelope, KEY) is None

    def test_expiry_before_issue_is_rejected(self) -> None:
        envelope = make()
        envelope["expires_at"] = envelope["issued_at"]
        envelope["signature"] = sign_envelope(envelope, KEY)
        assert verify_envelope(envelope, KEY) is not None

    def test_verification_is_evaluated_at_the_supplied_moment(self) -> None:
        envelope = make()
        later = datetime.now(UTC) + timedelta(days=1)
        assert verify_envelope(envelope, KEY) is None
        assert verify_envelope(envelope, KEY, now=later) is not None

    def test_unparseable_timestamps_are_rejected(self) -> None:
        envelope = make(issued_at="last Tuesday")
        assert verify_envelope(envelope, KEY) is not None


class TestSignature:
    def test_wrong_key_is_rejected(self) -> None:
        error = verify_envelope(make(), "a-different-key")
        assert error is not None
        assert "signature" in error.lower()

    def test_tampered_intent_is_rejected(self) -> None:
        """Swapping one allowlisted intent for another must break the signature."""
        envelope = make()
        envelope["intent_type"] = "collect_inventory"
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "signature" in error.lower()

    def test_tampered_agent_id_is_rejected(self) -> None:
        """Redirecting a signed command at another machine must fail."""
        envelope = make(agent_id="some-other-agent")
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "signature" in error.lower()

    def test_extended_expiry_is_rejected(self) -> None:
        """An attacker must not be able to lengthen the replay window."""
        envelope = make()
        envelope["expires_at"] = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
        error = verify_envelope(envelope, KEY)
        assert error is not None
        assert "signature" in error.lower()

    def test_replayed_nonce_is_not_detected_here(self) -> None:
        """Replay detection does not exist yet; this records that honestly.

        The nonce is signed so a future delivery layer can persist and reject
        duplicates. Until that store exists, the same envelope verifies twice
        and a short TTL is the only control.
        """
        envelope = make()
        assert verify_envelope(envelope, KEY) is None
        assert verify_envelope(envelope, KEY) is None
