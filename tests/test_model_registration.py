"""Checks explicit ORM registration behavior."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(code: str) -> str:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_base_import_does_not_eagerly_register_all_models() -> None:
    count = _run("from app.db.base import Base; print(len(Base.metadata.tables))")
    assert count == "0"


def test_explicit_register_models_populates_metadata() -> None:
    count = _run(
        "from app.db.base import Base; from app.db.registry import register_models; "
        "register_models(); print(len(Base.metadata.tables))"
    )
    assert int(count) > 10
