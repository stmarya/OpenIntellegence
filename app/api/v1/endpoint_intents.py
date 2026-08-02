"""Approval-only endpoint intent control plane; no delivery route exists."""
from __future__ import annotations
from datetime import UTC,datetime
from typing import Annotated,Literal
from fastapi import APIRouter,Depends,HTTPException,status
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import select
from app.core.deps import DbSession,Principal,Scope,require_scope
from app.db.endpoint_intent_models import EndpointIntent,EndpointIntentAudit
from app.db.models import Agent
from app.services.endpoint_intents import validate_intent
router=APIRouter(); WritePrincipal=Annotated[Principal,Depends(require_scope(Scope.WRITE))]
class ORM(BaseModel): model_config=ConfigDict(from_attributes=True)
class IntentCreate(BaseModel): agent_id:str; intent_type:Literal["isolate_network","collect_inventory","rotate_agent_certificate"]; expires_at:datetime
class IntentOut(ORM): id:str; agent_id:str; intent_type:str; state:str; requested_by:str; expires_at:datetime; delivery_state:str; delivery_result:dict|None=None
async def _audit(db:DbSession,intent_id:str,actor:str,event:str,detail:dict)->None: db.add(EndpointIntentAudit(intent_id=intent_id,actor=actor,event_type=event,detail=detail,event_at=datetime.now(UTC)))
@router.post("/endpoint-intents",response_model=IntentOut,status_code=status.HTTP_201_CREATED)
async def create_intent(payload:IntentCreate,db:DbSession,principal:WritePrincipal)->IntentOut:
 agent=(await db.execute(select(Agent).where(Agent.id==payload.agent_id,Agent.tenant_id==principal.tenant_id))).scalar_one_or_none()
 if agent is None: raise HTTPException(status.HTTP_404_NOT_FOUND,"Tenant agent not found.")
 actor=f"api_key:{principal.api_key_id}"; decision=validate_intent(payload.intent_type,actor,[],payload.expires_at,datetime.now(UTC)); intent=EndpointIntent(tenant_id=principal.tenant_id,agent_id=agent.id,intent_type=payload.intent_type,state=decision.state,requested_by=actor,expires_at=payload.expires_at,delivery_state="not_dispatched",delivery_result=None); db.add(intent); await db.flush(); await _audit(db,intent.id,actor,"requested",{}); await db.flush(); return IntentOut.model_validate(intent)
@router.post("/endpoint-intents/{intent_id}/approve",response_model=IntentOut)
async def approve_intent(intent_id:str,db:DbSession,principal:WritePrincipal)->IntentOut:
 intent=(await db.execute(select(EndpointIntent).where(EndpointIntent.id==intent_id,EndpointIntent.tenant_id==principal.tenant_id).with_for_update())).scalar_one_or_none()
 if intent is None: raise HTTPException(status.HTTP_404_NOT_FOUND,"Endpoint intent not found.")
 actor=f"api_key:{principal.api_key_id}"; audits=(await db.execute(select(EndpointIntentAudit).where(EndpointIntentAudit.intent_id==intent.id,EndpointIntentAudit.event_type=="approved"))).scalars().all(); approvers=[x.actor for x in audits]
 if actor in approvers: raise HTTPException(status.HTTP_409_CONFLICT,"Approver already recorded.")
 decision=validate_intent(intent.intent_type,intent.requested_by,[*approvers,actor],intent.expires_at,datetime.now(UTC)); intent.state=decision.state; await _audit(db,intent.id,actor,"approved",{"decision":decision.state,"reason":decision.reason}); await db.flush(); return IntentOut.model_validate(intent)
@router.post("/endpoint-intents/{intent_id}/cancel",response_model=IntentOut)
async def cancel_intent(intent_id:str,db:DbSession,principal:WritePrincipal)->IntentOut:
 intent=(await db.execute(select(EndpointIntent).where(EndpointIntent.id==intent_id,EndpointIntent.tenant_id==principal.tenant_id).with_for_update())).scalar_one_or_none()
 if intent is None: raise HTTPException(status.HTTP_404_NOT_FOUND,"Endpoint intent not found.")
 if intent.state in {"approved","expired","cancelled","rejected"}: raise HTTPException(status.HTTP_409_CONFLICT,"Intent cannot be cancelled.")
 intent.state="cancelled"; await _audit(db,intent.id,f"api_key:{principal.api_key_id}","cancelled",{}); await db.flush(); return IntentOut.model_validate(intent)
