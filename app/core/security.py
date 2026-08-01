"""API key generation, hashing and verification.

Design notes
------------
A raw key looks like ``ngs_live_<22-char-id><32-char-secret>``.

The *id* segment is stored in plaintext and indexed, so verifying a key is a
single primary-key lookup followed by one Argon2 verification. Hashing the
whole key and scanning the table would be O(n) Argon2 calls per request,
which is a denial-of-service vector.

Only the Argon2id hash of the *secret* segment is persisted. The full key is
shown exactly once, at creation time.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.config import get_settings

_ID_BYTES = 16  # -> 22 chars base64url, unpadded
_SECRET_BYTES = 24  # -> 32 chars base64url, unpadded

_ID_LEN = 22
_SECRET_LEN = 32


def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(
        time_cost=s.argon2_time_cost,
        memory_cost=s.argon2_memory_cost,
        parallelism=s.argon2_parallelism,
    )


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    """Result of minting a new API key."""

    key_id: str
    """Public, indexed identifier. Safe to log and display."""

    secret_hash: str
    """Argon2id hash of the secret half. Safe to persist."""

    raw_key: str
    """Full key. Shown to the user once and never stored."""

    prefix: str

    @property
    def masked(self) -> str:
        """Display form, e.g. ``ngs_live_7f3a\u2026c21b``."""
        return f"{self.prefix}{self.key_id[:4]}\u2026{self.key_id[-4:]}"


@dataclass(frozen=True, slots=True)
class KeyParts:
    prefix: str
    key_id: str
    secret: str


def generate_key(*, agent: bool = False) -> GeneratedKey:
    """Mint a new API key.

    ``agent=True`` produces an enrollment key (``ngs_agnt_``) used once by an
    endpoint agent to obtain its mTLS client certificate.
    """
    s = get_settings()
    prefix = s.api_key_prefix_agent if agent else s.api_key_prefix_platform

    key_id = secrets.token_urlsafe(_ID_BYTES)[:_ID_LEN]
    secret = secrets.token_urlsafe(_SECRET_BYTES)[:_SECRET_LEN]

    return GeneratedKey(
        key_id=key_id,
        secret_hash=_hasher().hash(secret),
        raw_key=f"{prefix}{key_id}{secret}",
        prefix=prefix,
    )


def parse_key(raw: str) -> KeyParts | None:
    """Split a presented key into its parts, or return ``None`` if malformed.

    This never raises: a malformed key is an authentication failure, not a
    server error.
    """
    s = get_settings()
    for prefix in (s.api_key_prefix_platform, s.api_key_prefix_agent):
        if not raw.startswith(prefix):
            continue
        body = raw[len(prefix) :]
        if len(body) != _ID_LEN + _SECRET_LEN:
            return None
        return KeyParts(prefix=prefix, key_id=body[:_ID_LEN], secret=body[_ID_LEN:])
    return None


def verify_secret(secret: str, secret_hash: str) -> bool:
    """Verify a presented secret against a stored Argon2id hash."""
    try:
        return _hasher().verify(secret_hash, secret)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(secret_hash: str) -> bool:
    """True when Argon2 parameters have been raised since the hash was made."""
    try:
        return _hasher().check_needs_rehash(secret_hash)
    except InvalidHashError:
        return False


def hash_secret(secret: str) -> str:
    return _hasher().hash(secret)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
