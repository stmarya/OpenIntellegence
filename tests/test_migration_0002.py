"""Regression checks for 0002 upgrade idempotency from 0001 schema state."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _migration():
    module_name = "migration_0002_campaign_malware_domains"
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "0002_campaign_malware_domains.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeOp:
    def __init__(self) -> None:
        self.added_columns: list[tuple[str, str]] = []
        self.created_unique: list[tuple[str, str]] = []

    def add_column(self, table_name, column):  # noqa: ANN001
        self.added_columns.append((table_name, column.name))

    def create_unique_constraint(self, name, table_name, _cols):  # noqa: ANN001
        self.created_unique.append((table_name, name))

    def __getattr__(self, _name):
        def _noop(*_args, **_kwargs):  # noqa: ANN001
            return None

        return _noop


def test_has_column_returns_false_in_offline_mode_without_calling_get_bind(monkeypatch) -> None:
    """_has_column must not call op.get_bind() when as_sql is True (offline mode)."""
    migration = _migration()

    class _OfflineContext:
        as_sql = True

    class _OfflineOp:
        def get_context(self):
            return _OfflineContext()

        def get_bind(self):
            raise RuntimeError("get_bind() must not be called in offline mode")

    monkeypatch.setattr(migration, "op", _OfflineOp())
    assert migration._has_column("installed_software", "first_seen") is False
    assert migration._has_column("asset_exposures", "match_evidence") is False


def test_has_unique_constraint_returns_false_in_offline_mode_without_calling_get_bind(
    monkeypatch,
) -> None:
    """_has_unique_constraint must not call op.get_bind() in offline mode."""
    migration = _migration()

    class _OfflineContext:
        as_sql = True

    class _OfflineOp:
        def get_context(self):
            return _OfflineContext()

        def get_bind(self):
            raise RuntimeError("get_bind() must not be called in offline mode")

    monkeypatch.setattr(migration, "op", _OfflineOp())
    assert migration._has_unique_constraint("installed_software", "uq_software_asset_name_version") is False
    assert migration._has_unique_constraint("asset_exposures", "uq_exposure_asset_vuln") is False


def test_upgrade_skips_columns_and_constraints_already_present(monkeypatch) -> None:
    migration = _migration()
    fake_op = _FakeOp()
    existing_columns = {
        ("installed_software", "first_seen"),
        ("installed_software", "last_seen"),
        ("installed_software", "removed_at"),
        ("asset_exposures", "match_evidence"),
    }
    existing_constraints = {
        ("installed_software", "uq_software_asset_name_version"),
        ("asset_exposures", "uq_exposure_asset_vuln"),
    }

    monkeypatch.setattr(migration, "op", fake_op)
    monkeypatch.setattr(
        migration, "_has_column", lambda table, column: (table, column) in existing_columns
    )
    monkeypatch.setattr(
        migration,
        "_has_unique_constraint",
        lambda table, name: (table, name) in existing_constraints,
    )
    migration.upgrade()

    assert ("installed_software", "first_seen") not in fake_op.added_columns
    assert ("installed_software", "last_seen") not in fake_op.added_columns
    assert ("installed_software", "removed_at") not in fake_op.added_columns
    assert ("asset_exposures", "match_evidence") not in fake_op.added_columns
    assert ("installed_software", "uq_software_asset_name_version") not in fake_op.created_unique
    assert ("asset_exposures", "uq_exposure_asset_vuln") not in fake_op.created_unique


def test_upgrade_adds_columns_and_constraints_when_missing(monkeypatch) -> None:
    migration = _migration()
    fake_op = _FakeOp()

    monkeypatch.setattr(migration, "op", fake_op)
    monkeypatch.setattr(migration, "_has_column", lambda _table, _column: False)
    monkeypatch.setattr(migration, "_has_unique_constraint", lambda _table, _name: False)
    migration.upgrade()

    assert ("installed_software", "first_seen") in fake_op.added_columns
    assert ("installed_software", "last_seen") in fake_op.added_columns
    assert ("installed_software", "removed_at") in fake_op.added_columns
    assert ("asset_exposures", "match_evidence") in fake_op.added_columns
    assert ("installed_software", "uq_software_asset_name_version") in fake_op.created_unique
    assert ("asset_exposures", "uq_exposure_asset_vuln") in fake_op.created_unique
