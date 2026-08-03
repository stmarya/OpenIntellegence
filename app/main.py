"""FastAPI application entrypoint."""
from __future__ import annotations
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from secrets import token_hex
import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI,Request,status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
import app.db.registry  # noqa: F401
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.deps import set_rate_limiter
from app.core.ratelimit import InMemoryRateLimiter,RateLimiter
from app.db.base import get_engine
from app.observability import metrics_response,observe
log=structlog.get_logger(__name__)
DESCRIPTION="""OpenIntelligence ingests cyber-threat intelligence, correlates it with endpoint inventory, and exposes a tenant-scoped REST API. API clients use scoped keys; endpoint agents use mTLS. List responses disclose provenance and degraded sources."""
@asynccontextmanager
async def lifespan(app:FastAPI)->AsyncIterator[None]:
 settings=get_settings();redis=None
 try:
  redis=aioredis.from_url(settings.redis_url,decode_responses=True);await redis.ping();set_rate_limiter(RateLimiter(redis));log.info("rate_limiter_ready",backend="redis")
 except Exception as exc:
  if settings.is_production:raise
  set_rate_limiter(InMemoryRateLimiter());log.warning("rate_limiter_degraded",backend="in-memory",error_type=type(exc).__name__)
 import app.ingest.connectors  # noqa: F401
 yield
 if redis is not None:await redis.aclose()
 await get_engine().dispose()
def create_app()->FastAPI:
 settings=get_settings();app=FastAPI(title="OpenIntelligence CTI API",description=DESCRIPTION,version="0.2.0",lifespan=lifespan,docs_url="/docs",redoc_url="/redoc",openapi_url="/openapi.json")
 app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origins,allow_credentials=True,allow_methods=["*"],allow_headers=["*"],expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset","Retry-After","X-Request-Duration-Ms","X-Request-ID"])
 @app.middleware("http")
 async def telemetry(request:Request,call_next):
  started=time.perf_counter();request_id=request.headers.get("X-Request-ID") or token_hex(16)
  try:response=await call_next(request)
  except Exception:
   route=getattr(request.scope.get("route"),"path","unmatched");observe(request.method,route,500,time.perf_counter()-started);log.exception("request_failed",request_id=request_id,route=route);raise
  elapsed=time.perf_counter()-started;route=getattr(request.scope.get("route"),"path","unmatched");observe(request.method,route,response.status_code,elapsed);response.headers["X-Request-Duration-Ms"]=f"{elapsed*1000:.1f}";response.headers["X-Request-ID"]=request_id;return response
 @app.exception_handler(RequestValidationError)
 async def validation_handler(request:Request,exc:RequestValidationError):
  return JSONResponse(status_code=422,content={"error":"validation_failed","message":"The request body or query parameters are invalid.","fields":[{"location":".".join(str(p) for p in err["loc"]),"problem":err["msg"]} for err in exc.errors()]})
 app.include_router(api_router,prefix="/api/v1")
 @app.get("/health",tags=["Operations"])
 async def health()->dict:return {"status":"ok","version":app.version}
 @app.get("/health/ready",tags=["Operations"])
 async def ready()->JSONResponse:
  checks={}
  try:
   async with get_engine().connect() as conn:await conn.execute(text("SELECT 1"))
   checks["database"]="ok"
  except Exception:checks["database"]="error"
  try:
   redis=aioredis.from_url(get_settings().redis_url,decode_responses=True);await redis.ping();await redis.aclose();checks["redis"]="ok"
  except Exception:checks["redis"]="error"
  healthy=all(v=="ok" for v in checks.values());return JSONResponse(status_code=200 if healthy else 503,content={"status":"ready" if healthy else "degraded","checks":checks})
 @app.get("/metrics",include_in_schema=False)
 async def metrics():return metrics_response()
 return app
app=create_app()
