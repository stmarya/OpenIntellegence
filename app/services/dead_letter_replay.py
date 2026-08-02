"""Tenant-locked replay for connector dead letters only."""
from __future__ import annotations
from datetime import UTC, datetime
from secrets import token_urlsafe
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.orchestration_models import AutomationOutbox

NON_REPLAYABLE=frozenset({"endpoint.command.request","case.create","report.generate"})

async def replay_dead_letter(session:AsyncSession,*,tenant_id:str,outbox_id:str,actor:str)->AutomationOutbox:
 original=(await session.execute(select(AutomationOutbox).where(AutomationOutbox.id==outbox_id,AutomationOutbox.tenant_id==tenant_id).with_for_update())).scalar_one_or_none()
 if original is None: raise LookupError("outbox_not_found")
 if original.state!="dead_letter": raise ValueError("outbox_not_dead_letter")
 if original.action in NON_REPLAYABLE: raise ValueError("action_not_replayable")
 replay=AutomationOutbox(tenant_id=tenant_id,run_id=original.run_id,step_index=original.step_index,action=original.action,target=original.target,payload={**original.payload,"replay":{"source_outbox_id":original.id,"actor":actor,"requested_at":datetime.now(UTC).isoformat()}},idempotency_key=f"replay:{original.id}:{token_urlsafe(18)}",state="queued",available_at=datetime.now(UTC))
 session.add(replay); await session.flush(); return replay
