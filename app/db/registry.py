"""Explicit ORM model registration.

Import this module anywhere that needs ``Base.metadata`` to reflect all
tables — specifically ``alembic/env.py`` for Alembic autogenerate and
``app/main.py`` for the FastAPI application factory.

Keeping all model imports here (instead of inside ``app.db.base``) breaks
the circular dependency that made ``app.db.models → app.db.base →
app.db.models`` partially-initialised.
"""

from __future__ import annotations

from app.db import (  # noqa: F401
    alert_models,
    correlation_models,
    domain_models,
    models,
    orchestration_models,
    workflow_models,
)
from app.db.base import Base  # noqa: F401

__all__ = ["Base"]
