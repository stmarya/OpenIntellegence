"""Alembic lineage checks for the canonical single-head chain."""

from __future__ import annotations

from pathlib import Path

from alembic.script import ScriptDirectory

EXPECTED_CHAIN = ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008"]


def test_alembic_has_single_head() -> None:
    scripts = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "alembic"))
    assert scripts.get_heads() == ["0008"]


def test_expected_revisions_exist() -> None:
    scripts = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "alembic"))
    revisions = {rev.revision for rev in scripts.walk_revisions(base="0001", head="0008")}
    for revision in EXPECTED_CHAIN:
        assert revision in revisions
