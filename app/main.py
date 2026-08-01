"""FastAPI application entrypoint."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.deps import set_rate_limiter
from app.core.ratelimit import InMemoryRateLimiter, RateLimiter
from app.db.base import get_engine

log = structlog.get_logger(__name__)

DESCRIPTION = """
OpenIntelligence is a cyber threat intelligence platform: it ingests public
and commercial feeds, correlates them against your own endpoint inventory,
and exposes the result over a versioned REST API.

**Authentication.** Send your key in `X-API-Key`, or as `Authorization:
Bearer <key>`. Keys are scoped; a 403 response names the scope you are
missing. Endpoint agents authenticate with mutual TLS instead of a key.

**Rate limits.** Every response carries `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset`. A 429 also carries
`Retry-After`.

**Provenance.** List responses include a `provenance` block naming which
feeds contributed and which were degraded. If a feed failed, the figures are
incomplete and the response says so rather than quietly under-reporting.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()

    try:
        redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis.ping()
        set_rate_limiter(RateLimiter(redis))
        log.info("rate_limiter_ready", backend="redis")
    except Exception as exc:  # noqa: BLE001 - startup must not hard-fail here
        if settings.is_production:
            # In production an unavailable limiter means unmetered access.
            # Refusing to boot is safer than serving without limits.
            raise
        redis = None
        set_rate_limiter(InMemoryRateLimiter())
        log.warning("rate_limiter_degraded", backend="in-memory", error=str(exc))

    # Register connectors so the registry is populated before any request.
    import app.ingest.connectors  # noqa: F401

    yield

    if redis is not None:
        await redis.aclose()
    await get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="OpenIntelligence CTI API",
        description=DESCRIPTION,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "X-Request-Duration-Ms",
        ],
    )

    @app.middleware("http")
    async def timing(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-Duration-Ms"] = f"{elapsed_ms:.1f}"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Field-level detail, so a client can fix the call without guessing.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_failed",
                "message": "The request body or query parameters are invalid.",
                "fields": [
                    {
                        "location": ".".join(str(p) for p in err["loc"]),
                        "problem": err["msg"],
                    }
                    for err in exc.errors()
                ],
            },
        )

    app.include_router(api_router, prefix="/api/v1")

    @app.get("/health", tags=["Operations"], summary="Liveness probe")
    async def health() -> dict:
        return {"status": "ok", "version": app.version}

    @app.get("/health/ready", tags=["Operations"], summary="Readiness probe")
    async def ready() -> JSONResponse:
        """Reports dependency health individually.

        A single boolean would hide which dependency is down, which is the
        only thing an operator actually needs to know.
        """
        checks: dict[str, str] = {}

        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["database"] = f"error: {exc}"

        try:
            redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
            await redis.ping()
            await redis.aclose()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"error: {exc}"

        healthy = all(v == "ok" for v in checks.values())
        return JSONResponse(
            status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "ready" if healthy else "degraded", "checks": checks},
        )

    return app


app = create_app()
