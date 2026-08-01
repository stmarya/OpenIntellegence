"""Tests for API key minting, verification, and rate limiting."""

from __future__ import annotations

import pytest

from app.core.deps import Principal, Scope
from app.core.ratelimit import InMemoryRateLimiter
from app.core.security import (
    constant_time_equals,
    generate_key,
    hash_secret,
    parse_key,
    verify_secret,
)


class TestKeyGeneration:
    def test_platform_key_shape(self) -> None:
        key = generate_key()
        assert key.raw_key.startswith("ngs_live_")
        assert key.prefix == "ngs_live_"

    def test_agent_key_shape(self) -> None:
        key = generate_key(agent=True)
        assert key.raw_key.startswith("ngs_agnt_")

    def test_secret_is_hashed_not_stored(self) -> None:
        """The stored hash must not contain the plaintext."""
        key = generate_key()
        secret = key.raw_key[len(key.prefix) + 22 :]
        assert secret not in key.secret_hash
        assert key.secret_hash.startswith("$argon2")

    def test_key_id_is_recoverable_from_raw_key(self) -> None:
        """Verification must be one indexed lookup, not a scan.

        If the id could not be read from the key, every request would have to
        Argon2-verify against every stored key, which is a denial-of-service
        vector against ourselves.
        """
        key = generate_key()
        parts = parse_key(key.raw_key)
        assert parts is not None
        assert parts.key_id == key.key_id

    def test_keys_are_unique(self) -> None:
        ids = {generate_key().key_id for _ in range(50)}
        assert len(ids) == 50

    def test_masked_form_hides_the_secret(self) -> None:
        key = generate_key()
        assert "\u2026" in key.masked
        secret = key.raw_key[len(key.prefix) + 22 :]
        assert secret not in key.masked


class TestKeyParsing:
    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "garbage",
            "ngs_live_",
            "ngs_live_tooshort",
            "wrong_prefix_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Bearer ngs_live_x",
        ],
    )
    def test_malformed_keys_return_none_never_raise(self, raw) -> None:
        """A malformed key is a 401, not a 500."""
        assert parse_key(raw) is None


class TestVerification:
    def test_correct_secret_verifies(self) -> None:
        key = generate_key()
        parts = parse_key(key.raw_key)
        assert parts is not None
        assert verify_secret(parts.secret, key.secret_hash) is True

    def test_wrong_secret_rejected(self) -> None:
        key = generate_key()
        other = generate_key()
        other_parts = parse_key(other.raw_key)
        assert other_parts is not None
        assert verify_secret(other_parts.secret, key.secret_hash) is False

    def test_same_secret_hashes_differently_each_time(self) -> None:
        """Argon2 salts per hash, so identical secrets must not collide."""
        assert hash_secret("identical") != hash_secret("identical")

    def test_constant_time_compare(self) -> None:
        assert constant_time_equals("abc", "abc") is True
        assert constant_time_equals("abc", "abd") is False


class TestScopes:
    def _principal(self, *scopes: str) -> Principal:
        return Principal(
            api_key_id="key-1",
            tenant_id="tenant-1",
            name="test-key",
            scopes=set(scopes),
            rate_limit_per_hour=1000,
        )

    def test_held_scope_allowed(self) -> None:
        assert self._principal(Scope.READ).has(Scope.READ)

    def test_missing_scope_denied(self) -> None:
        assert not self._principal(Scope.READ).has(Scope.APIKEY_WRITE)

    def test_admin_implies_everything(self) -> None:
        admin = self._principal(Scope.ADMIN)
        assert admin.has(Scope.READ)
        assert admin.has(Scope.APIKEY_WRITE)
        assert admin.has(Scope.ENROLL)

    def test_read_does_not_imply_write(self) -> None:
        assert not self._principal(Scope.READ).has(Scope.WRITE)


class TestRateLimiting:
    async def test_allows_up_to_the_limit(self) -> None:
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            result = await limiter.check("key-1", limit=5)
            assert result.allowed is True

    async def test_blocks_past_the_limit(self) -> None:
        limiter = InMemoryRateLimiter()
        for _ in range(3):
            await limiter.check("key-1", limit=3)
        result = await limiter.check("key-1", limit=3)
        assert result.allowed is False
        assert result.remaining == 0

    async def test_limits_are_isolated_per_key(self) -> None:
        """One noisy tenant must not exhaust another tenant's budget."""
        limiter = InMemoryRateLimiter()
        for _ in range(3):
            await limiter.check("key-1", limit=3)
        result = await limiter.check("key-2", limit=3)
        assert result.allowed is True

    async def test_headers_are_well_formed(self) -> None:
        limiter = InMemoryRateLimiter()
        result = await limiter.check("key-1", limit=10)
        headers = result.headers()
        assert headers["X-RateLimit-Limit"] == "10"
        assert headers["X-RateLimit-Remaining"] == "9"
        assert "X-RateLimit-Reset" in headers

    async def test_retry_after_present_only_when_blocked(self) -> None:
        limiter = InMemoryRateLimiter()
        allowed = await limiter.check("key-1", limit=1)
        assert "Retry-After" not in allowed.headers()

        blocked = await limiter.check("key-1", limit=1)
        assert blocked.allowed is False
        assert "Retry-After" in blocked.headers()
