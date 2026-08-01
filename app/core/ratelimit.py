"""Redis-backed sliding-window rate limiter.

A fixed-window counter lets a caller send 2x their quota across a window
boundary. This uses a sorted set per key so the window genuinely slides.

The whole check is a single Lua script, which makes it atomic — otherwise
concurrent requests race between the count and the insert and the limit
leaks under exactly the load it is meant to protect against.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from redis.asyncio import Redis

_SLIDING_WINDOW_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local used = redis.call('ZCARD', key)

if used >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local reset = window
  if oldest[2] then
    reset = math.ceil((tonumber(oldest[2]) + window) - now)
  end
  return {0, used, reset}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window)
return {1, used + 1, window}
"""


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    limit: int
    used: int
    reset_seconds: int

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def headers(self) -> dict[str, str]:
        """Standard rate-limit response headers."""
        out = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset_seconds),
        }
        if not self.allowed:
            out["Retry-After"] = str(self.reset_seconds)
        return out


class RateLimiter:
    def __init__(self, redis: Redis, *, window_seconds: int = 3600) -> None:
        self._redis = redis
        self._window = window_seconds
        self._script = redis.register_script(_SLIDING_WINDOW_LUA)

    async def check(self, identity: str, limit: int) -> RateLimitResult:
        now = time.time()
        # Monotonic-ish unique member so identical timestamps do not collide.
        member = f"{now:.6f}:{time.perf_counter_ns()}"

        allowed, used, reset = await self._script(
            keys=[f"ratelimit:{identity}"],
            args=[now, self._window, limit, member],
        )
        return RateLimitResult(
            allowed=bool(allowed),
            limit=limit,
            used=int(used),
            reset_seconds=int(reset),
        )


class InMemoryRateLimiter:
    """Dependency-free limiter for tests and single-process development.

    Not safe across workers — never use it in production.
    """

    def __init__(self, *, window_seconds: int = 3600) -> None:
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}

    async def check(self, identity: str, limit: int) -> RateLimitResult:
        now = time.time()
        cutoff = now - self._window
        hits = [t for t in self._hits.get(identity, []) if t > cutoff]

        if len(hits) >= limit:
            reset = int(hits[0] + self._window - now) + 1
            self._hits[identity] = hits
            return RateLimitResult(False, limit, len(hits), max(1, reset))

        hits.append(now)
        self._hits[identity] = hits
        return RateLimitResult(True, limit, len(hits), self._window)
