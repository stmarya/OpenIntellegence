"""Explicit ORM model registration.

Import this module (or ``app.db.registry``) anywhere that needs
``Base.metadata`` to reflect all tables — in particular ``alembic/env.py``
and the FastAPI application factory.  Keeping registration here instead of
inside ``app.db.base`` breaks the circular import that made
``app.db.models → app.db.base → app.db.models`` partially-initialised.
"""

from __future__ import annotations

from app.db.base import Base  # noqa: F401
from app.db import (  # noqa: F401
    alert_models,
    correlation_models,
    domain_models,
    models,
    orchestration_models,
    workflow_models,
)

__all__ = ["Base"]
