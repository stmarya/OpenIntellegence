"""Explicit ORM model registration."""
from __future__ import annotations
from app.db import alert_models, correlation_models, domain_models, endpoint_intent_models, models, orchestration_models, workflow_models  # noqa: F401
from app.db.base import Base  # noqa: F401
__all__=["Base"]
