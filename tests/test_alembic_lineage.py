"""Alembic lineage checks for the canonical single-head chain."""

from __future__ import annotations

from pathlib import Path

from alembic.script import ScriptDirectory

# Stable revisions that must always be present in the chain.  The head revision
# is intentionally not hardcoded here: concurrent feature branches may each
# introduce a new head, and the exact final head is only known after all branches
# are integrated and a linear migration sequence is assembled.
STABLE_CHAIN = ["0001", "0002", "0003", "0004", "0005", "0006", "0007"]


def test_alembic_has_single_head() -> None:
    """There must be exactly one migration head at all times."""
    scripts = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "alembic"))
    heads = scripts.get_heads()
    assert len(heads) == 1, f"Expected a single migration head, found: {heads}"


def test_expected_revisions_exist() -> None:
    """Every revision in the stable baseline chain must be reachable from 0001."""
    scripts = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "alembic"))
    head = scripts.get_heads()[0]
    revisions = {rev.revision for rev in scripts.walk_revisions(base="0001", head=head)}
    for revision in STABLE_CHAIN:
        assert revision in revisions, f"Revision {revision!r} is missing from the migration chain"
