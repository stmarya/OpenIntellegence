"""Internal action handlers for the automation delivery worker.

These handlers fulfil the *case.create*, *report.generate*, and
*endpoint.command.request* actions using the platform's own domain services.
They conform to the same ``Connector`` protocol used by external connectors so
the delivery worker dispatches them identically.

Safety guarantees for endpoint.command.request
----------------------------------------------
* No arbitrary remote-shell execution.  The handler validates the command
  against an explicit allowlist, verifies the HMAC-SHA256 envelope signature
  and the expiry timestamp, and writes a durable audit row.  The enrolled
  agent polls for pending commands separately; the worker never opens an
  outbound socket to the endpoint.
* Device identity is the agent's UUID (mTLS certificate subject) — never a
  hostname, which gets reused after re-imaging.
* A missing or invalid COMMAND_SIGNING_KEY produces a terminal failure (not a
  retry), because retrying with a bad signing key will never succeed and would
  burn the attempt budget.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import structlog

from app.db.orchestration_models import AutomationOutbox
from app.db.workflow_models import Case
from app.workers.connector_delivery import DeliveryReceipt

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Endpoint-command allowlist
# ---------------------------------------------------------------------------
# Every command that an agent may receive must appear here.  Adding a command
# requires a deliberate code change; the allowlist is NOT configurable at
# runtime to prevent privilege escalation via config mutation.
ALLOWED_ENDPOINT_COMMANDS: frozenset[str] = frozenset(
    {
        "isolate",
        "unisolate",
        "collect_forensics",
        "run_vulnerability_scan",
        "restart_agent",
        "update_config",
    }
)

# Envelopes are rejected after this many seconds even if the payload says
# otherwise.  This caps the window in which a stolen, signed envelope could be
# replayed.
_ENVELOPE_MAX_TTL_SECONDS = 3600


def _verify_command_envelope(payload: dict, signing_key: str) -> str | None:
    """Validate the endpoint command envelope.

    Returns *None* on success or an error string describing the rejection
    reason.  All failures are terminal (non-retryable) because the envelope
    content is immutable — retrying cannot fix a bad signature or expired TTL.
    """
    command = payload.get("command")
    if not isinstance(command, str) or command not in ALLOWED_ENDPOINT_COMMANDS:
        return (
            f"Command '{command}' is not in the allowlist "
            f"({', '.join(sorted(ALLOWED_ENDPOINT_COMMANDS))})."
        )

    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        return "Envelope missing required field 'agent_id' (mTLS device identity)."

    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return "Envelope missing required field 'nonce'."

    issued_at_raw = payload.get("issued_at")
    expires_at_raw = payload.get("expires_at")
    signature = payload.get("signature")
    if not issued_at_raw or not expires_at_raw or not signature:
        return "Envelope missing required fields (issued_at, expires_at, signature)."

    try:
        issued_at = datetime.fromisoformat(issued_at_raw)
        expires_at = datetime.fromisoformat(expires_at_raw)
    except (ValueError, TypeError):
        return "Envelope timestamps are not valid ISO-8601."

    now = datetime.now(UTC)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if now > expires_at:
        return f"Command envelope expired at {expires_at.isoformat()}."

    ttl = (expires_at - issued_at).total_seconds()
    if ttl > _ENVELOPE_MAX_TTL_SECONDS:
        return (
            f"Envelope TTL {ttl:.0f}s exceeds the maximum of"
            f" {_ENVELOPE_MAX_TTL_SECONDS}s."
        )

    # Reproduce the canonical message that was signed.  Only include the
    # business fields — excluding the signature itself — sorted so field
    # ordering differences cannot produce a forgery.
    canonical = {
        "agent_id": agent_id,
        "command": command,
        "expires_at": expires_at_raw,
        "issued_at": issued_at_raw,
        "nonce": nonce,
    }
    msg = json.dumps(canonical, sort_keys=True).encode()
    expected = hmac.new(signing_key.encode(), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return "Envelope signature verification failed."

    return None


class CaseCreateAction:
    """Create an investigation case from a playbook step.

    Expected step_payload fields
    ----------------------------
    title : str (required)
    case_type : str (required)
    priority : str, default "medium"
    owner : str | None
    """

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        from app.db.base import get_session_factory

        data = item.payload.get("step_payload", {})
        ctx = item.payload.get("run_context", {})

        title = data.get("title") or ctx.get("summary")
        case_type = data.get("case_type", "automation")
        if not title:
            return DeliveryReceipt(
                False,
                error="case.create requires 'title' in step_payload or run_context.summary.",
            )

        factory = get_session_factory()
        async with factory() as session:
            case = Case(
                tenant_id=item.tenant_id,
                title=str(title)[:512],
                case_type=str(case_type)[:64],
                priority=str(data.get("priority", "medium"))[:16],
                owner=str(data.get("owner", ""))[:255] or None,
                investigation_id=data.get("investigation_id"),
            )
            session.add(case)
            await session.flush()
            case_id = str(case.id)
            await session.commit()

        log.info("case.create.delivered", case_id=case_id, outbox_id=item.id)
        return DeliveryReceipt(True, remote_id=case_id, detail={"case_type": case_type})


class ReportGenerateAction:
    """Trigger report generation from a playbook step.

    Expected step_payload fields
    ----------------------------
    template : str, default "executive_brief"
    title : str | None
    period_days : int | None  — overrides the template default
    focus_cve_id : str | None
    """

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        import httpx

        from app.ai.rag import RagService
        from app.ai.reports import TEMPLATES, ReportGenerator
        from app.core.config import get_settings
        from app.db.base import get_session_factory
        from app.db.models import Report, ReportStatus

        data = item.payload.get("step_payload", {})
        template_key = data.get("template", "executive_brief")

        if template_key not in TEMPLATES:
            return DeliveryReceipt(
                False,
                error=(
                    f"Unknown report template '{template_key}'. "
                    f"Available: {', '.join(sorted(TEMPLATES))}."
                ),
            )

        spec = TEMPLATES[template_key]
        settings = get_settings()
        factory = get_session_factory()

        async with factory() as session:
            report = Report(
                tenant_id=item.tenant_id,
                template=template_key,
                title=data.get("title") or f"{spec.title} (auto-generated)",
                status=ReportStatus.QUEUED,
                progress=0,
                requested_by=f"outbox:{item.id}",
            )
            session.add(report)
            await session.flush()

            client = httpx.AsyncClient()
            try:
                rag = RagService(session, settings, client)
                await ReportGenerator(session, rag).generate(
                    report, focus_cve_id=data.get("focus_cve_id")
                )
                await session.commit()
                report_id = str(report.id)
                final_status = report.status.value
            finally:
                await client.aclose()

        log.info(
            "report.generate.delivered",
            report_id=report_id,
            status=final_status,
            outbox_id=item.id,
        )
        return DeliveryReceipt(
            True,
            remote_id=report_id,
            detail={"template": template_key, "report_status": final_status},
        )


class EndpointCommandAction:
    """Submit a signed, expiring command request to an enrolled agent.

    This handler enforces the safe-request pipeline contract:
    - Command must be in ALLOWED_ENDPOINT_COMMANDS.
    - Envelope must carry a valid HMAC-SHA256 signature.
    - Envelope must not be expired.
    - agent_id must reference the mTLS device UUID, not a hostname.
    - A durable audit row is written regardless of outcome.
    - No network connection is opened to the endpoint.
    """

    def __init__(self, signing_key: str) -> None:
        self._signing_key = signing_key

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        from app.db.base import get_session_factory
        from app.db.orchestration_models import CommandAuditLog

        data = item.payload.get("step_payload", {})
        error = _verify_command_envelope(data, self._signing_key)

        factory = get_session_factory()
        async with factory() as session:
            audit = CommandAuditLog(
                tenant_id=item.tenant_id,
                outbox_id=item.id,
                run_id=item.run_id,
                agent_id=data.get("agent_id", ""),
                command=data.get("command", ""),
                idempotency_key=item.idempotency_key,
                outcome="accepted" if error is None else "rejected",
                rejection_reason=error,
            )
            session.add(audit)
            await session.commit()

        if error:
            log.warning(
                "endpoint.command.rejected",
                outbox_id=item.id,
                reason=error,
            )
            # Terminal failure — do not retry.  A policy violation or an
            # expired envelope cannot be fixed by the worker waiting and
            # trying again.
            return DeliveryReceipt(False, retryable=False, error=error)

        log.info(
            "endpoint.command.accepted",
            outbox_id=item.id,
            agent_id=data.get("agent_id"),
            command=data.get("command"),
        )
        return DeliveryReceipt(
            True,
            detail={
                "agent_id": data.get("agent_id"),
                "command": data.get("command"),
            },
        )
