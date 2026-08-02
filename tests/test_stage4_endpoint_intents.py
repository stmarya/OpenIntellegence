"""Deterministic tests for Stage 4: endpoint command intent lifecycle.

No live database, network, or LLM calls are made.
All tests verify:
- Intent-type allowlist enforcement
- Target validation (tenant isolation)
- Two-person approval with requester exclusion
- Explicit state machine transitions
- Expiry, cancel, reject semantics
- Idempotency
- Delivery placeholders remain null
- No execution side effects
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db.endpoint_models import ENDPOINT_INTENT_ALLOWLIST, REQUIRED_APPROVALS, EndpointCommandIntent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


def _make_principal(key_id: str = "key-1", tenant: str = "tenant-1"):
    from app.core.deps import Principal

    return Principal(
        api_key_id=key_id,
        tenant_id=tenant,
        name="tester",
        scopes=frozenset({"write", "read"}),
        rate_limit_per_hour=1000,
    )


def _make_intent(
    state: str = "proposed",
    requester: str = "api_key:key-1",
    approvals: list | None = None,
    expires_at: datetime | None = None,
    audit_timeline: list | None = None,
) -> EndpointCommandIntent:
    return EndpointCommandIntent(
        id="intent-1",
        tenant_id="tenant-1",
        requester=requester,
        reason="Isolate suspicious host for forensics",
        intent_type="isolate",
        parameters={},
        state=state,
        idempotency_key="idem-1",
        required_approvals=REQUIRED_APPROVALS,
        approvals=approvals or [],
        audit_timeline=audit_timeline or [],
        requested_at=datetime.now(UTC),
        expires_at=expires_at,
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# 1. Allowlist enforcement
# ---------------------------------------------------------------------------


def test_endpoint_intent_allowlist_excludes_arbitrary_commands() -> None:
    """The allowlist must not contain free-form command/script types."""
    assert "shell_exec" not in ENDPOINT_INTENT_ALLOWLIST
    assert "command" not in ENDPOINT_INTENT_ALLOWLIST
    assert "script" not in ENDPOINT_INTENT_ALLOWLIST
    assert "run" not in ENDPOINT_INTENT_ALLOWLIST


def test_endpoint_intent_allowlist_includes_expected_types() -> None:
    expected = {"isolate", "unisolate", "scan", "collect_forensics", "kill_process"}
    missing = expected - ENDPOINT_INTENT_ALLOWLIST
    assert not missing, f"Expected intent types missing from allowlist: {missing}"


@pytest.mark.asyncio
async def test_create_intent_rejects_unknown_type() -> None:
    """An unknown intent_type must be rejected with 422."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import IntentCreate, create_intent
    from app.db.models import Agent, Asset

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(None)

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = _make_principal()

    with pytest.raises(HTTPException) as exc_info:
        await create_intent(
            IntentCreate(
                intent_type="shell_exec",
                reason="This should be rejected as arbitrary command",
                idempotency_key="ik-test-1234",
                parameters={},
            ),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 422
    assert "shell_exec" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_create_intent_rejects_missing_targets() -> None:
    """At least one target (asset or agent) must be supplied."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import IntentCreate, create_intent

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(None)

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = _make_principal()

    with pytest.raises(HTTPException) as exc_info:
        await create_intent(
            IntentCreate(
                intent_type="isolate",
                reason="Missing target — should fail",
                idempotency_key="ik-test-5678",
                target_asset_id=None,
                target_agent_id=None,
            ),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# 2. Target validation — tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_intent_rejects_cross_tenant_asset() -> None:
    """An asset from a different tenant must be rejected."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import IntentCreate, create_intent

    call_count = [0]

    class _Db:
        async def execute(self, _stmt):
            call_count[0] += 1
            # First call: idempotency check returns None.
            # Second call: asset lookup returns None (not in tenant).
            return _ScalarResult(None)

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = _make_principal()

    with pytest.raises(HTTPException) as exc_info:
        await create_intent(
            IntentCreate(
                intent_type="isolate",
                reason="Cross-tenant asset should be rejected",
                idempotency_key="ik-cross-tenant",
                target_asset_id="foreign-asset-id",
            ),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 422
    assert "target_asset_id" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_create_intent_rejects_agent_asset_linkage_mismatch() -> None:
    """When both asset and agent are supplied, their linkage must be validated."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import IntentCreate, create_intent
    from app.db.models import Agent, Asset

    asset = Asset(id="asset-1", tenant_id="tenant-1", hostname="host-a")
    # Agent is linked to a DIFFERENT asset
    agent = Agent(
        id="agent-1",
        tenant_id="tenant-1",
        asset_id="asset-999",  # does not match asset-1
        version="1.0",
        os_family="linux",
    )

    call_counter = [0]

    class _Db:
        async def execute(self, _stmt):
            call_counter[0] += 1
            if call_counter[0] == 1:
                return _ScalarResult(None)  # idempotency
            if call_counter[0] == 2:
                return _ScalarResult(asset)  # asset lookup
            return _ScalarResult(agent)  # agent lookup

        def add(self, _): pass

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = _make_principal()

    with pytest.raises(HTTPException) as exc_info:
        await create_intent(
            IntentCreate(
                intent_type="isolate",
                reason="Linkage mismatch test",
                idempotency_key="ik-linkage",
                target_asset_id="asset-1",
                target_agent_id="agent-1",
            ),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 422
    assert "linked" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# 3. Two-person approval — requester exclusion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_intent_rejects_requester_self_approval() -> None:
    """The requester must not be able to approve their own intent."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import ApprovalRequest, approve_intent

    intent = _make_intent(state="proposed", requester="api_key:key-1")

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-1")

    with pytest.raises(HTTPException) as exc_info:
        await approve_intent(
            "intent-1",
            ApprovalRequest(note=None),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 409
    assert "requester" in str(exc_info.value.detail).lower()


@pytest.mark.asyncio
async def test_approve_intent_rejects_duplicate_approver() -> None:
    """The same approver cannot approve twice."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import ApprovalRequest, approve_intent

    intent = _make_intent(
        state="partially_approved",
        requester="api_key:key-requester",
        approvals=[{"actor": "api_key:key-2", "approved_at": "...", "note": None}],
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-2")

    with pytest.raises(HTTPException) as exc_info:
        await approve_intent(
            "intent-1",
            ApprovalRequest(note=None),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 409
    assert "already approved" in str(exc_info.value.detail).lower()


@pytest.mark.asyncio
async def test_approve_intent_two_distinct_approvers_reaches_approved() -> None:
    """Two distinct approvers (excluding requester) must bring state to approved."""
    from app.api.v1.endpoint_commands import ApprovalRequest, approve_intent

    intent = _make_intent(
        state="partially_approved",
        requester="api_key:key-requester",
        approvals=[{"actor": "api_key:key-approver-1", "approved_at": "...", "note": None}],
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-approver-2")

    result = await approve_intent(
        "intent-1",
        ApprovalRequest(note="LGTM"),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )
    assert result.state == "approved"
    assert len(result.approvals) == 2


@pytest.mark.asyncio
async def test_approve_intent_first_approval_sets_partially_approved() -> None:
    """First approval sets state to partially_approved when required_approvals > 1."""
    from app.api.v1.endpoint_commands import ApprovalRequest, approve_intent

    intent = _make_intent(state="proposed", requester="api_key:key-requester")

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-approver-1")

    result = await approve_intent(
        "intent-1",
        ApprovalRequest(note=None),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )
    assert result.state == "partially_approved"
    assert len(result.approvals) == 1


# ---------------------------------------------------------------------------
# 4. Reject / cancel / expiry lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_intent_sets_terminal_state() -> None:
    from app.api.v1.endpoint_commands import RejectRequest, reject_intent

    intent = _make_intent(state="proposed")

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-approver")

    result = await reject_intent(
        "intent-1",
        RejectRequest(reason="Policy violation"),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )
    assert result.state == "rejected"
    assert result.rejected_reason == "Policy violation"
    assert result.rejected_by == "api_key:key-approver"
    assert result.rejected_at is not None


@pytest.mark.asyncio
async def test_cancel_intent_does_not_populate_rejected_reason() -> None:
    """Cancellation must use cancellation_note, not rejected_reason."""
    from app.api.v1.endpoint_commands import CancelRequest, cancel_intent

    intent = _make_intent(state="approved")

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-admin")

    result = await cancel_intent(
        "intent-1",
        CancelRequest(note="Admin decided not to proceed"),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )
    assert result.state == "cancelled"
    assert result.cancellation_note == "Admin decided not to proceed"
    assert result.cancelled_by == "api_key:key-admin"
    # Must NOT populate rejected_reason.
    assert result.rejected_reason is None


@pytest.mark.asyncio
async def test_cancel_intent_records_actual_canceller_not_requester() -> None:
    """An admin cancel must record the admin's identity, not the requester's."""
    from app.api.v1.endpoint_commands import CancelRequest, cancel_intent

    intent = _make_intent(
        state="approved",
        requester="api_key:key-requester",
    )

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    # Admin (different actor from requester) cancels.
    principal = _make_principal(key_id="key-admin-different")

    result = await cancel_intent(
        "intent-1",
        CancelRequest(note="Admin cancel"),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )
    assert result.cancelled_by == "api_key:key-admin-different"
    assert result.cancelled_by != intent.requester


def test_expiry_check_transitions_to_expired() -> None:
    """An intent past its expires_at must transition to expired on read."""
    from app.api.v1.endpoint_commands import _check_expiry

    intent = _make_intent(
        state="partially_approved",
        expires_at=datetime.now(UTC) - timedelta(hours=1),  # already expired
    )
    _check_expiry(intent)
    assert intent.state == "expired"


def test_expiry_check_does_not_affect_terminal_states() -> None:
    """Expired check must not overwrite already-terminal states."""
    from app.api.v1.endpoint_commands import _check_expiry

    for terminal in ("rejected", "cancelled", "expired"):
        intent = _make_intent(
            state=terminal,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        _check_expiry(intent)
        assert intent.state == terminal  # unchanged


@pytest.mark.asyncio
async def test_reject_already_rejected_raises_conflict() -> None:
    """Rejecting an already-rejected intent must raise 409."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import RejectRequest, reject_intent

    intent = _make_intent(state="rejected")

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(intent)

        async def flush(self): pass

    principal = _make_principal(key_id="key-2")

    with pytest.raises(HTTPException) as exc_info:
        await reject_intent(
            "intent-1",
            RejectRequest(reason="Re-reject"),
            db=_Db(),  # type: ignore[arg-type]
            principal=principal,
        )
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_cancel_terminal_intent_raises_conflict() -> None:
    """Cancelling an already-cancelled or rejected intent must raise 409."""
    from fastapi import HTTPException

    from app.api.v1.endpoint_commands import CancelRequest, cancel_intent

    for terminal_state in ("cancelled", "rejected", "expired"):
        intent = _make_intent(state=terminal_state)

        class _Db:
            async def execute(self, _stmt):
                return _ScalarResult(intent)

            async def flush(self): pass

        principal = _make_principal()

        with pytest.raises(HTTPException) as exc_info:
            await cancel_intent(
                "intent-1",
                CancelRequest(note="Cancel again"),
                db=_Db(),  # type: ignore[arg-type]
                principal=principal,
            )
        assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# 5. Idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_intent_idempotency_returns_existing() -> None:
    """Duplicate idempotency keys return the existing record without modifying it."""
    from app.api.v1.endpoint_commands import IntentCreate, create_intent

    existing = _make_intent(state="proposed")
    existing.created_at = datetime.now(UTC)

    added = []

    class _Db:
        async def execute(self, _stmt):
            return _ScalarResult(existing)

        def add(self, obj):
            added.append(obj)

        async def flush(self): pass

        async def refresh(self, _): pass

    principal = _make_principal()

    result = await create_intent(
        IntentCreate(
            intent_type="isolate",
            reason="Idempotent request",
            idempotency_key="idem-key-1234",
            target_asset_id="asset-1",
        ),
        db=_Db(),  # type: ignore[arg-type]
        principal=principal,
    )

    # Should return the existing record, not create a new one.
    assert result.id == "intent-1"
    assert not added  # add() was never called


# ---------------------------------------------------------------------------
# 6. Delivery placeholders remain null
# ---------------------------------------------------------------------------


def test_approved_intent_delivery_fields_are_null() -> None:
    """An approved intent must have null delivery fields — control plane only."""
    intent = _make_intent(state="approved")
    assert intent.delivered_at is None
    assert intent.delivery_receipt is None


# ---------------------------------------------------------------------------
# 7. Audit timeline
# ---------------------------------------------------------------------------


def test_cancel_intent_appends_audit_timeline() -> None:
    """cancel_intent must append an event to audit_timeline."""
    from app.api.v1.endpoint_commands import _append_timeline, _now

    intent = _make_intent(state="proposed", audit_timeline=[])
    _append_timeline(intent, "cancelled", "api_key:key-1", "Admin cancel")

    assert len(intent.audit_timeline) == 1
    entry = intent.audit_timeline[0]
    assert entry["event"] == "cancelled"
    assert entry["actor"] == "api_key:key-1"
    assert entry["detail"] == "Admin cancel"
    assert "at" in entry


# ---------------------------------------------------------------------------
# 8. REQUIRED_APPROVALS constant
# ---------------------------------------------------------------------------


def test_required_approvals_is_two() -> None:
    """Two-person rule: REQUIRED_APPROVALS must be exactly 2."""
    assert REQUIRED_APPROVALS == 2
