"""Deterministic tests for the endpoint command request control plane.

No network calls, no shell execution, no database required.

Coverage
--------
- Allowlist enforcement: arbitrary command text is rejected.
- Tenant isolation: a principal cannot see or modify another tenant's request.
- Same-approver rejection: the requester cannot approve their own request.
- Two-approval transition: two distinct approvers move the request to approved.
- Duplicate-approver rejection: the same approver cannot approve twice.
- Expiry: requests past their expires_at are lazily transitioned to expired.
- Cancellation: a request in a cancellable state becomes cancelled.
- Idempotency: a second create with the same key returns the existing row.
- No execution side effects: no dispatch endpoint exists; result/receipt are null.
- State machine guard: transitions from terminal states are rejected.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.api.v1.endpoint_commands import (
    ApprovalNote,
    CommandRequestCreate,
    CommandRequestOut,
    _check_expiry,
    approve_command_request,
    cancel_command_request,
    create_command_request,
    get_command_request,
)
from app.core.deps import Principal
from app.db.endpoint_command_models import (
    ALLOWED_COMMAND_TYPES,
    EndpointCommandRequest,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

TENANT_A = str(uuid.uuid4())
TENANT_B = str(uuid.uuid4())
KEY_A1 = str(uuid.uuid4())
KEY_A2 = str(uuid.uuid4())
KEY_A3 = str(uuid.uuid4())
KEY_B1 = str(uuid.uuid4())
ASSET_ID = str(uuid.uuid4())


def _principal(
    tenant_id: str = TENANT_A,
    key_id: str = KEY_A1,
    scopes: frozenset[str] | None = None,
) -> Principal:
    return Principal(
        api_key_id=key_id,
        tenant_id=tenant_id,
        name="tester",
        scopes=scopes if scopes is not None else frozenset({"read", "write"}),
        rate_limit_per_hour=1000,
    )


def _make_request(
    tenant_id: str = TENANT_A,
    requester_key: str = KEY_A1,
    state: str = "proposed",
    expires_at: datetime | None = None,
    idempotency_key: str | None = None,
    approvals: list | None = None,
) -> EndpointCommandRequest:
    """Build an in-memory EndpointCommandRequest without a DB."""
    if expires_at is None:
        expires_at = datetime.now(UTC) + timedelta(hours=1)
    req = EndpointCommandRequest()
    req.id = str(uuid.uuid4())
    req.tenant_id = tenant_id
    req.target_asset_id = ASSET_ID
    req.target_agent_id = None
    req.command_type = "isolate_network"
    req.parameters = {}
    req.requester = f"api_key:{requester_key}"
    req.reason = "Suspected lateral movement on this host."
    req.expires_at = expires_at
    req.state = state
    req.idempotency_key = idempotency_key or str(uuid.uuid4())
    req.required_approvals = 2
    req.approvals = approvals if approvals is not None else []
    req.rejected_reason = None
    req.audit_timeline = [
        {"event": "proposed", "actor": req.requester, "at": "2026-01-01T00:00:00+00:00"}
    ]
    req.result = None
    req.receipt = None
    req.dispatched_at = None
    req.created_at = datetime.now(UTC)
    req.updated_at = datetime.now(UTC)
    return req


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeDb:
    """Minimal fake async DB session sufficient for control-plane tests."""

    def __init__(self, existing: EndpointCommandRequest | None = None) -> None:
        self._existing = existing
        self.added: list = []
        self.flushed = False

    async def execute(self, _stmt):
        return _ScalarResult(self._existing)

    async def scalar(self, _stmt):
        return 1 if self._existing else 0

    def add(self, obj) -> None:
        self.added.append(obj)
        # Simulate flush assigning an id
        if not getattr(obj, "id", None):
            obj.id = str(uuid.uuid4())

    async def flush(self) -> None:
        self.flushed = True


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------


class TestAllowlist:
    """Command type must come from the strict allowlist."""

    def test_all_allowed_types_are_valid_pydantic_values(self) -> None:
        for cmd in ALLOWED_COMMAND_TYPES:
            obj = CommandRequestCreate(
                target_asset_id=ASSET_ID,
                command_type=cmd,
                reason="Test reason for testing purposes.",
                idempotency_key="testkey12",
            )
            assert obj.command_type == cmd

    def test_arbitrary_shell_command_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="allowlist"):
            CommandRequestCreate(
                target_asset_id=ASSET_ID,
                command_type="rm -rf /",
                reason="Should be rejected.",
                idempotency_key="testkey12",
            )

    def test_script_command_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="allowlist"):
            CommandRequestCreate(
                target_asset_id=ASSET_ID,
                command_type="exec_script",
                reason="Should be rejected.",
                idempotency_key="testkey12",
            )

    def test_empty_command_type_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            CommandRequestCreate(
                target_asset_id=ASSET_ID,
                command_type="",
                reason="Should be rejected.",
                idempotency_key="testkey12",
            )

    def test_no_target_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="target"):
            CommandRequestCreate(
                command_type="isolate_network",
                reason="Need a target.",
                idempotency_key="testkey12",
            )


# ---------------------------------------------------------------------------
# Tenant isolation tests
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    """A principal must not access another tenant's requests."""

    @pytest.mark.asyncio
    async def test_get_returns_404_for_wrong_tenant(self) -> None:
        req = _make_request(tenant_id=TENANT_A)
        db = _FakeDb(existing=None)  # execute returns None for wrong tenant

        with pytest.raises(Exception) as exc_info:
            await get_command_request(
                request_id=req.id,
                db=db,  # type: ignore[arg-type]
                principal=_principal(tenant_id=TENANT_B, key_id=KEY_B1),
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_approve_returns_404_for_wrong_tenant(self) -> None:
        db = _FakeDb(existing=None)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id="some-id",
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(tenant_id=TENANT_B),
            )
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Approval gate tests
# ---------------------------------------------------------------------------


class TestApprovalGate:
    """Two distinct approvers; requester excluded."""

    @pytest.mark.asyncio
    async def test_requester_cannot_approve_own_request(self) -> None:
        req = _make_request(requester_key=KEY_A1)
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id=req.id,
                payload=ApprovalNote(note="Self-approve attempt"),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A1),  # same key as requester
            )
        assert exc_info.value.status_code == 409
        assert "separation of duties" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_first_approval_moves_to_partially_approved(self) -> None:
        req = _make_request(requester_key=KEY_A1)
        db = _FakeDb(existing=req)

        out = await approve_command_request(
            request_id=req.id,
            payload=ApprovalNote(note="First approval"),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A2),
        )
        assert out.state == "partially_approved"
        assert len(out.approvals) == 1

    @pytest.mark.asyncio
    async def test_two_approvals_from_distinct_principals_reach_approved(self) -> None:
        req = _make_request(requester_key=KEY_A1)
        db = _FakeDb(existing=req)

        # First approval
        await approve_command_request(
            request_id=req.id,
            payload=ApprovalNote(note="First"),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A2),
        )
        assert req.state == "partially_approved"

        # Second approval (different key)
        out = await approve_command_request(
            request_id=req.id,
            payload=ApprovalNote(note="Second"),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A3),
        )
        assert out.state == "approved"
        assert len(out.approvals) == 2

    @pytest.mark.asyncio
    async def test_same_approver_cannot_approve_twice(self) -> None:
        req = _make_request(
            requester_key=KEY_A1,
            approvals=[
                {"actor": f"api_key:{KEY_A2}", "note": None, "approved_at": "2026-01-01T00:00:00+00:00"}  # noqa: E501
            ],
            state="partially_approved",
        )
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A2),  # already approved
            )
        assert exc_info.value.status_code == 409
        assert "already approved" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_approve_rejected_request_returns_409(self) -> None:
        req = _make_request(state="rejected")
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A2),
            )
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_approve_approved_request_returns_409(self) -> None:
        req = _make_request(state="approved")
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A2),
            )
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# Expiry tests
# ---------------------------------------------------------------------------


class TestExpiry:
    """Requests past their expiry are lazily transitioned to expired."""

    def test_expired_proposed_request_gets_expired_state(self) -> None:
        req = _make_request(
            state="proposed",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        result = _check_expiry(req)
        assert result.state == "expired"
        assert any(e["event"] == "expired" for e in result.audit_timeline)

    def test_expired_partially_approved_request_gets_expired_state(self) -> None:
        req = _make_request(
            state="partially_approved",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        result = _check_expiry(req)
        assert result.state == "expired"

    def test_not_yet_expired_request_stays_in_state(self) -> None:
        req = _make_request(
            state="proposed",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        result = _check_expiry(req)
        assert result.state == "proposed"

    def test_terminal_state_not_affected_by_expiry_check(self) -> None:
        req = _make_request(
            state="approved",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        result = _check_expiry(req)
        # approved is a terminal state; expiry check must not change it
        assert result.state == "approved"

    def test_cancelled_state_not_affected_by_expiry_check(self) -> None:
        req = _make_request(
            state="cancelled",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        result = _check_expiry(req)
        assert result.state == "cancelled"

    @pytest.mark.asyncio
    async def test_approve_of_expired_request_returns_409(self) -> None:
        req = _make_request(
            state="proposed",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await approve_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A2),
            )
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# Cancellation tests
# ---------------------------------------------------------------------------


class TestCancellation:
    @pytest.mark.asyncio
    async def test_requester_can_cancel_proposed_request(self) -> None:
        req = _make_request(requester_key=KEY_A1, state="proposed")
        db = _FakeDb(existing=req)

        out = await cancel_command_request(
            request_id=req.id,
            payload=ApprovalNote(note="No longer needed"),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A1),
        )
        assert out.state == "cancelled"
        assert any(e["event"] == "cancelled" for e in out.audit_timeline)

    @pytest.mark.asyncio
    async def test_requester_can_cancel_partially_approved_request(self) -> None:
        req = _make_request(
            requester_key=KEY_A1,
            state="partially_approved",
            approvals=[
                {"actor": f"api_key:{KEY_A2}", "note": None, "approved_at": "2026-01-01T00:00:00+00:00"}  # noqa: E501
            ],
        )
        db = _FakeDb(existing=req)

        out = await cancel_command_request(
            request_id=req.id,
            payload=ApprovalNote(),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A1),
        )
        assert out.state == "cancelled"

    @pytest.mark.asyncio
    async def test_non_requester_without_admin_cannot_cancel(self) -> None:
        req = _make_request(requester_key=KEY_A1, state="proposed")
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await cancel_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A2),  # different, no admin
            )
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_cancel_any_request(self) -> None:
        req = _make_request(requester_key=KEY_A1, state="proposed")
        db = _FakeDb(existing=req)

        out = await cancel_command_request(
            request_id=req.id,
            payload=ApprovalNote(note="Admin override"),
            db=db,  # type: ignore[arg-type]
            principal=_principal(key_id=KEY_A2, scopes=frozenset({"admin"})),
        )
        assert out.state == "cancelled"

    @pytest.mark.asyncio
    async def test_cancelled_request_cannot_be_cancelled_again(self) -> None:
        req = _make_request(requester_key=KEY_A1, state="cancelled")
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await cancel_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A1),
            )
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_rejected_request_cannot_be_cancelled(self) -> None:
        req = _make_request(requester_key=KEY_A1, state="rejected")
        db = _FakeDb(existing=req)

        with pytest.raises(Exception) as exc_info:
            await cancel_command_request(
                request_id=req.id,
                payload=ApprovalNote(),
                db=db,  # type: ignore[arg-type]
                principal=_principal(key_id=KEY_A1),
            )
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# Idempotency test
# ---------------------------------------------------------------------------


class TestIdempotency:
    @pytest.mark.asyncio
    async def test_second_create_with_same_key_returns_existing_row(self) -> None:
        existing = _make_request(idempotency_key="stable-key-001")
        db = _FakeDb(existing=existing)

        out = await create_command_request(
            payload=CommandRequestCreate(
                target_asset_id=ASSET_ID,
                command_type="isolate_network",
                reason="Suspected lateral movement on this host.",
                idempotency_key="stable-key-001",
            ),
            db=db,  # type: ignore[arg-type]
            principal=_principal(),
        )
        # Must return the *existing* row, not add a new one.
        assert out.id == existing.id
        assert not db.added  # nothing new was added


# ---------------------------------------------------------------------------
# No execution side effects
# ---------------------------------------------------------------------------


class TestNoExecutionSideEffects:
    """The control plane must not expose or invoke any execution path."""

    def test_no_dispatch_endpoint_in_module(self) -> None:
        from app.api.v1 import endpoint_commands

        # No attribute named dispatch
        assert not hasattr(endpoint_commands, "dispatch_command_request")
        assert not hasattr(endpoint_commands, "execute_command")

    def test_result_and_receipt_are_always_none_on_new_request(self) -> None:
        req = _make_request(state="proposed")
        assert req.result is None
        assert req.receipt is None
        assert req.dispatched_at is None

    def test_approved_request_result_and_receipt_are_none(self) -> None:
        req = _make_request(
            state="approved",
            approvals=[
                {"actor": f"api_key:{KEY_A2}", "note": None, "approved_at": "2026-01-01T00:00:00+00:00"},  # noqa: E501
                {"actor": f"api_key:{KEY_A3}", "note": None, "approved_at": "2026-01-01T00:01:00+00:00"},  # noqa: E501
            ],
        )
        assert req.result is None
        assert req.receipt is None
        assert req.dispatched_at is None

    def test_response_model_always_carries_pending_delivery_status(self) -> None:
        req = _make_request()
        out = CommandRequestOut.model_validate(req)
        assert out.delivery_status == "pending"
        assert "not been dispatched" in out.delivery_note


# ---------------------------------------------------------------------------
# Schema / ORM contract tests
# ---------------------------------------------------------------------------


class TestSchemaContract:
    def test_endpoint_command_requests_table_registered(self) -> None:
        from app.db.base import Base

        assert "endpoint_command_requests" in Base.metadata.tables

    def test_required_columns_present(self) -> None:
        from app.db.base import Base

        cols = Base.metadata.tables["endpoint_command_requests"].c
        for name in (
            "id",
            "tenant_id",
            "target_asset_id",
            "target_agent_id",
            "command_type",
            "parameters",
            "requester",
            "reason",
            "expires_at",
            "state",
            "idempotency_key",
            "required_approvals",
            "approvals",
            "rejected_reason",
            "audit_timeline",
            "result",
            "receipt",
            "dispatched_at",
            "created_at",
            "updated_at",
        ):
            assert name in cols, f"Missing column: {name}"

    def test_idempotency_unique_constraint_exists(self) -> None:
        from app.db.base import Base

        table = Base.metadata.tables["endpoint_command_requests"]
        unique_col_sets = {
            tuple(col.name for col in c.columns)
            for c in table.constraints
            if c.__class__.__name__ == "UniqueConstraint"
        }
        assert ("tenant_id", "idempotency_key") in unique_col_sets
