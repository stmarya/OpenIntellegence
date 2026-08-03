"""Signed, expiring envelope for endpoint command requests.

This module is pure: it performs no I/O, touches no database, and opens no
socket. It answers exactly one question — *is this command envelope
authentic, unexpired, and allowlisted?*

Nothing calls it yet.
---------------------
There is still no endpoint command delivery path in this platform.
``GET /settings`` reports ``endpoint_command_delivery: "not_implemented"``
and that remains accurate. This module is the signing primitive that a
future delivery layer will need; it is landed on its own, with tests, so
that the cryptography is reviewed and exercised before any code is able to
act on its verdict.

Relationship to the intent control plane
----------------------------------------
``app.services.endpoint_intents`` decides *whether a human-approved intent
is authorised* (allowlist, expiry, two distinct approvers, requester may not
self-approve). This module decides *whether a specific envelope on the wire
is genuine*. They are separate concerns and both must pass.

The allowlist is imported from ``endpoint_intents`` rather than redefined.
An earlier draft of this code carried its own, different command list; two
allowlists for one decision is a policy bug waiting to happen.

Design notes
------------
* **Device identity is the agent UUID**, taken from the mTLS certificate
  subject — never a hostname. Hostnames are reused after re-imaging, so a
  command signed for a hostname can land on a different machine.
* **TTL is hard-capped** at ``MAX_TTL_SECONDS`` regardless of what the
  envelope claims. A signed envelope is a bearer credential; a long-lived
  one is a replay window.
* **Every failure is terminal, never retryable.** An envelope is immutable,
  so a bad signature or an elapsed expiry cannot become valid by waiting.
  Retrying would only burn the attempt budget and delay the audit record.
* **The signature does not cover itself.** Only the business fields are
  signed, serialised with sorted keys so field ordering cannot be used to
  produce a forgery.

This module does not implement replay *detection*. The ``nonce`` field is
signed so that a future delivery layer can persist seen nonces and reject
duplicates, but no such store exists yet. A short TTL is currently the only
replay control, and that is a mitigation, not a defence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

from app.services.endpoint_intents import ALLOWED_INTENTS

# An envelope is rejected beyond this age even if it claims a longer life.
MAX_TTL_SECONDS = 3600

# Fields covered by the signature. Sorted on serialisation, and deliberately
# excluding "signature" itself.
SIGNED_FIELDS = ("agent_id", "expires_at", "intent_type", "issued_at", "nonce")


def canonical_message(envelope: dict) -> bytes:
    """Return the exact byte string that is signed for *envelope*.

    Keys are sorted and separators are fixed so that two structurally
    identical envelopes always produce byte-identical input.
    """
    payload = {field: envelope.get(field) for field in SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_envelope(envelope: dict, signing_key: str) -> str:
    """Return the HMAC-SHA256 hex digest for *envelope*."""
    return hmac.new(
        signing_key.encode(), canonical_message(envelope), hashlib.sha256
    ).hexdigest()


def build_envelope(
    *,
    agent_id: str,
    intent_type: str,
    nonce: str,
    signing_key: str,
    issued_at: datetime | None = None,
    ttl_seconds: int = 300,
) -> dict:
    """Construct a signed envelope.

    No validation is performed here beyond signing. Call :func:`verify_envelope`
    to check the result; building and verifying are kept separate so the
    verifier can be tested against envelopes this function would refuse to
    produce.
    """
    issued = issued_at or datetime.now(UTC)
    expires = issued + timedelta(seconds=ttl_seconds)
    envelope = {
        "agent_id": agent_id,
        "intent_type": intent_type,
        "nonce": nonce,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }
    envelope["signature"] = sign_envelope(envelope, signing_key)
    return envelope


def _as_aware(value: datetime) -> datetime:
    """Treat a naive timestamp as UTC rather than rejecting it.

    A naive timestamp is ambiguous, but reading it as local time would make
    verification depend on the server's timezone.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def verify_envelope(
    envelope: dict, signing_key: str, *, now: datetime | None = None
) -> str | None:
    """Validate *envelope*.

    Returns ``None`` when the envelope is authentic, unexpired, and carries an
    allowlisted intent. Otherwise returns a human-readable rejection reason
    suitable for an audit record.

    Every rejection is terminal. The caller must not retry.
    """
    intent_type = envelope.get("intent_type")
    if not isinstance(intent_type, str) or intent_type not in ALLOWED_INTENTS:
        allowed = ", ".join(sorted(ALLOWED_INTENTS))
        return f"Intent {intent_type!r} is not allowlisted ({allowed})."

    agent_id = envelope.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        return "Envelope is missing 'agent_id' (the mTLS device UUID)."

    nonce = envelope.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return "Envelope is missing 'nonce'."

    issued_raw = envelope.get("issued_at")
    expires_raw = envelope.get("expires_at")
    signature = envelope.get("signature")
    if not issued_raw or not expires_raw or not signature:
        return "Envelope is missing 'issued_at', 'expires_at', or 'signature'."

    try:
        issued_at = _as_aware(datetime.fromisoformat(issued_raw))
        expires_at = _as_aware(datetime.fromisoformat(expires_raw))
    except (TypeError, ValueError):
        return "Envelope timestamps are not valid ISO-8601."

    if expires_at <= issued_at:
        return "Envelope expires before it was issued."

    ttl = (expires_at - issued_at).total_seconds()
    if ttl > MAX_TTL_SECONDS:
        return f"Envelope TTL of {ttl:.0f}s exceeds the {MAX_TTL_SECONDS}s maximum."

    moment = _as_aware(now or datetime.now(UTC))
    if moment > expires_at:
        return f"Envelope expired at {expires_at.isoformat()}."

    expected = sign_envelope(envelope, signing_key)
    if not hmac.compare_digest(expected, signature):
        return "Envelope signature verification failed."

    return None
