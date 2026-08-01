"""Aggregates every v1 route under a single router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    admin,
    ai,
    alerting,
    assets,
    connectors,
    correlations,
    discovery,
    domains,
    entity_details,
    intel,
    orchestration,
    workflows,
)

api_router = APIRouter()

api_router.include_router(intel.router, tags=["Threat Intelligence"])
api_router.include_router(discovery.router, tags=["Discovery & Search"])
api_router.include_router(entity_details.router, tags=["Entity Details"])
api_router.include_router(domains.router, tags=["Domains"])
api_router.include_router(workflows.router, tags=["Workflows"])
api_router.include_router(alerting.router, tags=["Alerting"])
api_router.include_router(correlations.router, tags=["Correlations"])
api_router.include_router(orchestration.router, tags=["Orchestration"])
api_router.include_router(connectors.router, tags=["Connectors"])
api_router.include_router(assets.router, tags=["Assets & Agents"])
api_router.include_router(admin.router, tags=["Administration"])
api_router.include_router(ai.router, tags=["AI"])
