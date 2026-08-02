"""Aggregates every v1 route under a single router."""
from __future__ import annotations
from fastapi import APIRouter
from app.api.v1 import admin,ai,alerting,assets,automation_health,automation_replay,correlations,discovery,domains,endpoint_intents,entity_details,intel,orchestration,workflows
api_router=APIRouter()
for module,tags in [(intel,["Threat Intelligence"]),(discovery,["Discovery & Search"]),(entity_details,["Entity Details"]),(domains,["Domains"]),(workflows,["Workflows"]),(alerting,["Alerting"]),(correlations,["Correlations"]),(orchestration,["Orchestration"]),(automation_health,["Automation Health"]),(automation_replay,["Automation Replay"]),(endpoint_intents,["Endpoint Intent Control"]),(assets,["Assets & Agents"]),(admin,["Administration"]),(ai,["AI"])]: api_router.include_router(module.router,tags=tags)
