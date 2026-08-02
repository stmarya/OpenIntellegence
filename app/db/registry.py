"""Explicit ORM model registration for metadata initialization."""

from __future__ import annotations

from importlib import import_module

_MODEL_MODULES = (
    "app.db.models",
    "app.db.alert_models",
    "app.db.workflow_models",
    "app.db.correlation_models",
    "app.db.orchestration_models",
    "app.db.domain_models",
)


def register_models() -> None:
    """Import every ORM module so Base.metadata is fully populated."""
    for module in _MODEL_MODULES:
        import_module(module)
