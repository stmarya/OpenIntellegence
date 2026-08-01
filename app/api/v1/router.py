"""Aggregates every v1 route under a single router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import admin, ai, alerting, assets, intel

api_router = APIRouter()

api_router.include_router(intel.router, tags=["Threat Intelligence"])
api_router.include_router(alerting.router, tags=["Alerts & Sightings"])
api_router.include_router(assets.router, tags=["Assets & Agents"])
api_router.include_router(admin.router, tags=["Administration"])
api_router.include_router(ai.router, tags=["AI"])
