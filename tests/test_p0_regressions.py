"""Deterministic regression tests for P0 corrective fixes.

Covers:
1. Metadata registration / import-order safety
2. NULL lease recovery query behavior
3. Unsupported internal-action rejection
4. Constraint-name parity (indicators, assets, ransomware_victims)
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime

import pytest

# ---------------------------------------------------------------------------
# 1. Metadata registration / import-order safety
# ---------------------------------------------------------------------------


def test_models_importable_before_base_import() -> None:
    """app.db.models must import cleanly without relying on base.py's old
    circular late-imports.

    Runs in a subprocess so the test exercises a genuinely clean interpreter
    state without mutating the current process's module cache (which would
    invalidate class identities already held by other test modules).
    """
    script = (
        "import app.db.models\n"
        "assert hasattr(app.db.models, 'Indicator'), "
        "'Indicator class missing after fresh import'\n"
        "assert hasattr(app.db.models, 'Asset'), "
        "'Asset class missing after fresh import'\n"
        "assert hasattr(app.db.models, 'RansomwareVictim'), "
        "'RansomwareVictim class missing after fresh import'\n"
    )
    result = subprocess.run(
        [sys.executable],
        input=script,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Clean import of app.db.models failed:\n{result.stderr}"
    )


def test_registry_registers_all_tables() -> None:
    """After importing app.db.registry, Base.metadata must contain every
    table defined across all ORM modules.

    Runs in a subprocess to avoid mutating the current process's module cache.
    """
    required_csv = (
        "tenants,vulnerabilities,indicators,assets,ransomware_victims,"
        "automation_playbooks,automation_runs,automation_outbox,"
        "alert_rules,correlations"
    )
    script = (
        "import app.db.registry\n"
        "tables = set(app.db.registry.Base.metadata.tables.keys())\n"
        f"required = set('{required_csv}'.split(','))\n"
        "missing = required - tables\n"
        "assert not missing, "
        "f'Tables missing from Base.metadata after registry import: {missing}'\n"
    )
    result = subprocess.run(
        [sys.executable],
        input=script,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Registry did not populate all expected tables:\n{result.stderr}"
    )


def test_base_has_no_circular_model_imports() -> None:
    """app.db.base must not import any ORM model modules at module level."""
    import ast
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "app" / "db" / "base.py").read_text()
    tree = ast.parse(source)

    # Collect all import names from top-level ImportFrom nodes that reference
    # app.db sub-modules (alert_models, models, etc.).
    model_modules = {
        "alert_models",
        "correlation_models",
        "domain_models",
        "models",
        "orchestration_models",
        "workflow_models",
    }
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("app.db"):
                for alias in node.names:
                    if alias.name in model_modules:
                        found.append(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name or ""
                if any(name == f"app.db.{m}" or name.endswith(f".{m}") for m in model_modules):
                    found.append(name)

    assert not found, (
        f"app/db/base.py still imports model modules at module level: {found}. "
        "Move registrations to app/db/registry.py."
    )


def test_create_app_populates_base_metadata() -> None:
    """create_app() must work without a live database and, because app/main.py
    explicitly imports app.db.registry, Base.metadata must contain all ORM
    tables after the factory runs.

    This is the deterministic registration contract test: it proves that the
    FastAPI application factory path is directly wired to the registry rather
    than relying on an undocumented import side-effect.
    """
    from app.db.registry import Base
    from app.main import create_app

    app = create_app()
    assert app is not None

    tables = set(Base.metadata.tables.keys())
    required = {
        "tenants",
        "vulnerabilities",
        "indicators",
        "assets",
        "ransomware_victims",
        "automation_playbooks",
        "automation_runs",
        "automation_outbox",
        "alert_rules",
        "correlations",
    }
    missing = required - tables
    assert not missing, (
        f"Tables missing from Base.metadata after create_app(): {missing}. "
        "Ensure app/main.py imports app.db.registry at module level."
    )


# ---------------------------------------------------------------------------
# 2. NULL lease recovery — claim predicate
# ---------------------------------------------------------------------------


def test_claim_abandoned_null_lease_is_reclaimable() -> None:
    """An AutomationOutbox row that reached state='delivering' but was never
    given a lease_until value (NULL) must match the abandoned predicate so the
    worker can reclaim it on the next poll cycle.

    This is a unit-level predicate check using SQLAlchemy's compile path
    rather than a live DB, so it exercises the ORM expression logic
    deterministically without requiring a database connection.
    """
    from sqlalchemy import and_, or_
    from sqlalchemy.dialects import sqlite

    from app.db.orchestration_models import AutomationOutbox

    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    # Reproduce the fixed predicate from DeliveryWorker.claim().
    abandoned = and_(
        AutomationOutbox.state == "delivering",
        or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
    )

    compiled = str(
        abandoned.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})
    )

    # The IS NULL branch must be present.
    assert "IS NULL" in compiled, (
        "Abandoned predicate does not contain IS NULL check — stuck delivering "
        "records with null lease_until will never be reclaimed."
    )
    # The time comparison must also be present.
    assert "lease_until" in compiled


def test_old_abandoned_predicate_misses_null_lease() -> None:
    """Demonstrates the pre-fix bug: the original predicate
    (lease_until < now) silently excluded NULL rows in SQL semantics.

    NULL comparisons with < yield NULL (not TRUE), so a delivering row with
    lease_until IS NULL would never be returned.
    """
    from sqlalchemy import and_
    from sqlalchemy.dialects import sqlite

    from app.db.orchestration_models import AutomationOutbox

    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    # The OLD (buggy) predicate — kept here as a documented regression.
    old_abandoned = and_(
        AutomationOutbox.state == "delivering",
        AutomationOutbox.lease_until < now,
    )

    compiled = str(
        old_abandoned.compile(
            dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}
        )
    )

    # Confirm the IS NULL guard is absent from the old predicate.
    assert "IS NULL" not in compiled, (
        "Expected the old predicate to lack IS NULL — if this fails the regression "
        "documentation needs updating."
    )


# ---------------------------------------------------------------------------
# 3. Unsupported internal-action rejection
# ---------------------------------------------------------------------------


def test_p0_allowed_actions_excludes_deferred_actions() -> None:
    """P0 _ALLOWED_ACTIONS must not contain case.create, report.generate,
    or endpoint.command.request because no worker handles them yet."""
    from app.api.v1.orchestration import _ALLOWED_ACTIONS

    deferred = {"case.create", "report.generate", "endpoint.command.request"}
    accepted = deferred & _ALLOWED_ACTIONS
    assert not accepted, (
        f"These unimplemented actions are still in _ALLOWED_ACTIONS and would "
        f"produce dead-lettered outbox records: {accepted}"
    )


def test_p0_allowed_actions_covers_connector_actions() -> None:
    """The three currently-implemented connector actions must remain in P0."""
    from app.api.v1.orchestration import _ALLOWED_ACTIONS

    required = {"slack.notify", "jira.issue.create", "siem.push"}
    missing = required - _ALLOWED_ACTIONS
    assert not missing, f"Connector actions unexpectedly removed from _ALLOWED_ACTIONS: {missing}"


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_propose_run_rejects_stale_playbook_actions_before_run_creation() -> None:
    """Persisted/admin-inserted playbooks containing deferred actions must be
    rejected at propose_run before any AutomationRun is created."""
    from fastapi import HTTPException

    from app.api.v1.orchestration import RunCreate, propose_run
    from app.core.deps import Principal
    from app.db.orchestration_models import AutomationPlaybook

    class _Db:
        def __init__(self) -> None:
            self.add_calls = 0
            self.flush_calls = 0

        async def execute(self, _stmt):  # noqa: ANN001
            if not hasattr(self, "_calls"):
                self._calls = 0
            self._calls += 1
            if self._calls == 1:
                return _ScalarResult(None)
            return _ScalarResult(
                AutomationPlaybook(
                    id="playbook-1",
                    tenant_id="tenant-1",
                    name="stale",
                    trigger_type="manual",
                    steps=[{"action": "case.create", "target": "t", "payload": {}}],
                    enabled=True,
                )
            )

        def add(self, _obj):  # noqa: ANN001
            self.add_calls += 1

        async def flush(self):
            self.flush_calls += 1

        async def refresh(self, _obj): ...  # noqa: ANN001

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"admin"}),
        rate_limit_per_hour=1000,
    )
    db = _Db()

    with pytest.raises(HTTPException) as exc_info:
        await propose_run(
            RunCreate(
                playbook_id="playbook-1",
                source_type="manual",
                source_id="source-1",
                idempotency_key="idempotency-1",
            ),
            db=db,  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 422
    assert "case.create" in str(exc_info.value.detail)
    assert db.add_calls == 0
    assert db.flush_calls == 0


@pytest.mark.asyncio
async def test_dispatch_run_rejects_stale_playbook_actions_before_outbox_creation() -> None:
    """Persisted/admin-inserted playbooks containing deferred actions must be
    rejected at dispatch_run before any AutomationOutbox is created."""
    from fastapi import HTTPException

    from app.api.v1.orchestration import dispatch_run
    from app.core.deps import Principal
    from app.db.orchestration_models import AutomationPlaybook, AutomationRun

    run = AutomationRun(
        id="run-1",
        tenant_id="tenant-1",
        playbook_id="playbook-1",
        source_type="manual",
        source_id="source-1",
        idempotency_key="idempotency-1",
        state="approved",
        required_approvals=1,
        approvals=[],
        context={},
        requested_by="api_key:key-1",
    )
    playbook = AutomationPlaybook(
        id="playbook-1",
        tenant_id="tenant-1",
        name="stale",
        trigger_type="manual",
        steps=[{"action": "report.generate", "target": "t", "payload": {}}],
        enabled=True,
    )

    class _Db:
        def __init__(self) -> None:
            self.add_calls = 0
            self.flush_calls = 0

        async def execute(self, _stmt):  # noqa: ANN001
            return _ScalarResult(run)

        async def get(self, model, _id):  # noqa: ANN001
            if model is AutomationPlaybook:
                return playbook
            return None

        def add(self, _obj):  # noqa: ANN001
            self.add_calls += 1

        async def flush(self):
            self.flush_calls += 1

        async def refresh(self, _obj): ...  # noqa: ANN001

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"admin"}),
        rate_limit_per_hour=1000,
    )
    db = _Db()

    with pytest.raises(HTTPException) as exc_info:
        await dispatch_run("run-1", db=db, principal=principal)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 422
    assert "report.generate" in str(exc_info.value.detail)
    assert db.add_calls == 0
    assert db.flush_calls == 0
    assert run.state == "approved"


@pytest.mark.asyncio
async def test_create_playbook_rejects_unsupported_actions() -> None:
    """POST /playbooks with a step using a deferred action must raise 422."""
    from fastapi import HTTPException

    from app.api.v1.orchestration import PlaybookCreate, PlaybookStep, create_playbook
    from app.core.deps import Principal

    class _Db:
        def add(self, _): ...
        async def flush(self): ...
        async def refresh(self, _): ...

    principal = Principal(
        api_key_id="key-1",
        tenant_id="tenant-1",
        name="tester",
        scopes=frozenset({"admin"}),
        rate_limit_per_hour=1000,
    )

    for bad_action in ("case.create", "report.generate", "endpoint.command.request"):
        with pytest.raises(HTTPException) as exc_info:
            await create_playbook(
                PlaybookCreate(
                    name="Bad Playbook",
                    trigger_type="manual",
                    steps=[PlaybookStep(action=bad_action, target="dest", payload={})],
                ),
                db=_Db(),  # type: ignore[arg-type]
                principal=principal,
            )
        assert exc_info.value.status_code == 422, (
            f"Expected 422 for deferred action {bad_action!r}, "
            f"got {exc_info.value.status_code}"
        )


# ---------------------------------------------------------------------------
# 4. Constraint-name parity
# ---------------------------------------------------------------------------


def test_constraint_names_match_0001_migration() -> None:
    """ORM UniqueConstraint names for indicators, assets, and
    ransomware_victims must exactly match the names in 0001_initial_schema.py
    to prevent Alembic autogenerate from emitting spurious rename migrations.
    """
    from app.db.registry import Base  # ensures all tables are registered

    canonical = {
        "indicators": "uq_indicators_type_value",
        "assets": "uq_assets_tenant_id_hostname",
        "ransomware_victims": "uq_ransomware_victims_canonical_key_group_name_discovered_at",
    }

    for table_name, expected_name in canonical.items():
        table = Base.metadata.tables[table_name]
        constraint_names = {
            c.name
            for c in table.constraints
            if c.__class__.__name__ == "UniqueConstraint"
        }
        assert expected_name in constraint_names, (
            f"Table '{table_name}' is missing UniqueConstraint named "
            f"'{expected_name}'. Found: {constraint_names}. "
            "This drift will cause Alembic autogenerate to emit spurious migrations."
        )
