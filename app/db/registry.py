"""Explicit ORM model registration."""

from __future__ import annotations

from app.db import (
    alert_models,
    correlation_models,
    domain_models,
    endpoint_intent_models,
    governance_models,
    models,
    orchestration_models,
    platform_models,
    workflow_models,
)
from app.db.base import Base

__all__ = ["Base"]

# Imports above intentionally register every model with Base.metadata.
_REGISTERED_MODEL_MODULES = (
    alert_models,
    correlation_models,
    domain_models,
    endpoint_intent_models,
    governance_models,
    models,
    orchestration_models,
    platform_models,
    workflow_models,
)
