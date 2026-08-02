"""Safe internal automation worker; never contacts connectors or endpoints."""
from __future__ import annotations
from datetime import UTC, datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.orchestration_models import AutomationOutbox, AutomationRun
from app.db.workflow_models import Case
from app.db.models import Report

INTERNAL_ACTIONS=frozenset({"case.create","report.generate"})

class InternalAutomationWorker:
 async def process(self,session:AsyncSession,item:AutomationOutbox)->None:
  if item.action not in INTERNAL_ACTIONS: return
  run=(await session.execute(select(AutomationRun).where(AutomationRun.id==item.run_id,AutomationRun.tenant_id==item.tenant_id))).scalar_one_or_none()
  if run is None or run.state!="dispatched":
   item.state="dead_letter"; item.last_error="Run is not dispatched or not tenant-owned."; item.lease_token=None; item.lease_until=None; return
  if item.state not in {"queued","retry","delivering"}: return
  payload=item.payload.get("step_payload",{})
  if item.action=="case.create":
   title=str(payload.get("title") or run.context.get("summary") or "Automation-created case")[:512]
   case=Case(tenant_id=item.tenant_id,title=title,case_type=str(payload.get("case_type") or "automation")[:64],priority=str(payload.get("priority") or "medium")[:16],owner=None)
   session.add(case); await session.flush(); item.delivery_result={"internal_entity":"case","id":case.id}
  else:
   # This worker creates only a queued report request. It never generates report prose or calls an LLM.
   report=Report(tenant_id=item.tenant_id,template=str(payload.get("template") or "automation")[:64],title=str(payload.get("title") or run.context.get("summary") or "Automation report request")[:512],status="queued",progress=0,content_markdown=None,citations=[])
   session.add(report); await session.flush(); item.delivery_result={"internal_entity":"report","id":report.id,"body_generated":False}
  item.state="delivered"; item.delivered_at=datetime.now(UTC); item.attempts+=1; item.last_error=None; item.lease_token=None; item.lease_until=None
