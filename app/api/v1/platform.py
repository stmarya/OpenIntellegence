"""Cross-cutting APIs for the ten platform hardening priorities."""
from __future__ import annotations
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.endpoint_intent_models import EndpointIntent
from app.db.models import Agent, Asset, Indicator, ThreatActor, Vulnerability
from app.db.platform_models import AiEvaluation, AgentCommand, DetectionRule, EntityRelationship, EntityRevision, Role, RoleAssignment, SavedSearch, User
from app.services.agents import resolve_agent_from_request

router=APIRouter(); ReadPrincipal=Annotated[Principal,Depends(require_scope(Scope.READ))]; WritePrincipal=Annotated[Principal,Depends(require_scope(Scope.WRITE))]; AdminPrincipal=Annotated[Principal,Depends(require_scope(Scope.ADMIN))]
class UserCreate(BaseModel): email:str=Field(max_length=320); display_name:str=Field(min_length=1,max_length=255); oidc_subject:str|None=None; mfa_required:bool=False
class RoleCreate(BaseModel): name:str=Field(min_length=1,max_length=128); description:str|None=None; scopes:list[str]
class AssignmentCreate(BaseModel): user_id:str; role_id:str
class RelationshipCreate(BaseModel): source_type:str; source_id:str; relationship_type:str; target_type:str; target_id:str; confidence:float|None=Field(default=None,ge=0,le=1); evidence:dict=Field(default_factory=dict); sources:list[str]=Field(default_factory=list); valid_from:datetime|None=None; valid_until:datetime|None=None
class SavedSearchCreate(BaseModel): name:str; query:str; filters:dict=Field(default_factory=dict); is_shared:bool=False
class DetectionCreate(BaseModel): name:str; rule_format:Literal["sigma","yara","suricata","snort"]; content:str=Field(min_length=1); version:str="1"; attack_techniques:list[str]=Field(default_factory=list)
class EvaluationCreate(BaseModel): question:str; expected_refs:list[str]=Field(default_factory=list); actual_refs:list[str]=Field(default_factory=list); model:str|None=None
class CommandAck(BaseModel): nonce:str; state:Literal["completed","failed","rejected"]; result:dict=Field(default_factory=dict)

def actor(p:Principal)->str:return f"api_key:{p.api_key_id}"
def row(item)->dict:return {column.name:getattr(item,column.name) for column in item.__table__.columns}

@router.get("/users")
async def users(db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(User).where(User.tenant_id==p.tenant_id).order_by(User.email))).scalars().all(); return {"data":[row(x) for x in items],"identity_model":"user_role"}
@router.post("/users",status_code=status.HTTP_201_CREATED)
async def create_user(payload:UserCreate,db:DbSession,p:AdminPrincipal)->dict:
 if await db.scalar(select(func.count()).select_from(User).where(User.tenant_id==p.tenant_id,func.lower(User.email)==payload.email.lower())):raise HTTPException(409,"User already exists in this tenant.")
 item=User(tenant_id=p.tenant_id,email=payload.email.lower(),display_name=payload.display_name,oidc_subject=payload.oidc_subject,mfa_required=payload.mfa_required,status="active");db.add(item);await db.flush();return row(item)
@router.get("/roles")
async def roles(db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(Role).where(Role.tenant_id==p.tenant_id).order_by(Role.name))).scalars().all();return {"data":[row(x) for x in items]}
@router.post("/roles",status_code=201)
async def create_role(payload:RoleCreate,db:DbSession,p:AdminPrincipal)->dict:
 known={Scope.READ,Scope.WRITE,Scope.IOC,Scope.ENROLL,Scope.APIKEY_READ,Scope.APIKEY_WRITE,Scope.REPORT_WRITE,Scope.ADMIN}; unknown=sorted(set(payload.scopes)-known)
 if unknown:raise HTTPException(422,{"message":"Unknown scopes","unknown":unknown})
 item=Role(tenant_id=p.tenant_id,name=payload.name,description=payload.description,scopes=sorted(set(payload.scopes)),built_in=False);db.add(item);await db.flush();return row(item)
@router.post("/role-assignments",status_code=201)
async def assign_role(payload:AssignmentCreate,db:DbSession,p:AdminPrincipal)->dict:
 user=await db.get(User,payload.user_id);role=await db.get(Role,payload.role_id)
 if not user or not role or user.tenant_id!=p.tenant_id or role.tenant_id!=p.tenant_id:raise HTTPException(404,"Tenant user or role not found.")
 item=RoleAssignment(tenant_id=p.tenant_id,user_id=user.id,role_id=role.id,assigned_by=actor(p));db.add(item);await db.flush();return row(item)

@router.get("/relationships")
async def relationships(db:DbSession,p:ReadPrincipal,entity_type:str,entity_id:str,limit:Annotated[int,Query(ge=1,le=500)]=100)->dict:
 stmt=select(EntityRelationship).where(or_(EntityRelationship.tenant_id.is_(None),EntityRelationship.tenant_id==p.tenant_id),or_((EntityRelationship.source_type==entity_type)&(EntityRelationship.source_id==entity_id),(EntityRelationship.target_type==entity_type)&(EntityRelationship.target_id==entity_id))).limit(limit)
 items=(await db.execute(stmt)).scalars().all();return {"data":[row(x) for x in items],"count":len(items),"basis":"typed_edges"}
@router.post("/relationships",status_code=201)
async def create_relationship(payload:RelationshipCreate,db:DbSession,p:WritePrincipal)->dict:
 item=EntityRelationship(tenant_id=p.tenant_id,created_by=actor(p),**payload.model_dump());db.add(item);await db.flush();return row(item)
@router.get("/entities/{entity_type}/{entity_id}/revisions")
async def revisions(entity_type:str,entity_id:str,db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(EntityRevision).where(or_(EntityRevision.tenant_id.is_(None),EntityRevision.tenant_id==p.tenant_id),EntityRevision.entity_type==entity_type,EntityRevision.entity_id==entity_id).order_by(EntityRevision.revision.desc()))).scalars().all();return {"data":[row(x) for x in items]}

@router.get("/search/global")
async def global_search(db:DbSession,p:ReadPrincipal,q:Annotated[str,Query(min_length=2,max_length=200)],limit:Annotated[int,Query(ge=1,le=100)]=25)->dict:
 pattern=f"%{q.lower()}%"; results=[]
 vulns=(await db.execute(select(Vulnerability).where(or_(func.lower(Vulnerability.cve_id).like(pattern),func.lower(Vulnerability.description).like(pattern))).limit(limit))).scalars().all();results += [{"type":"vulnerability","id":x.cve_id,"title":x.cve_id,"summary":x.title} for x in vulns]
 indicators=(await db.execute(select(Indicator).where(func.lower(Indicator.value).like(pattern)).limit(limit))).scalars().all();results += [{"type":"indicator","id":x.id,"title":x.value,"summary":x.indicator_type} for x in indicators]
 actors=(await db.execute(select(ThreatActor).where(or_(func.lower(ThreatActor.display_name).like(pattern),func.lower(ThreatActor.canonical_name).like(pattern))).limit(limit))).scalars().all();results += [{"type":"threat_actor","id":x.id,"title":x.display_name,"summary":x.actor_type} for x in actors]
 assets=(await db.execute(select(Asset).where(Asset.tenant_id==p.tenant_id,func.lower(Asset.hostname).like(pattern)).limit(limit))).scalars().all();results += [{"type":"asset","id":x.id,"title":x.hostname,"summary":x.os_family} for x in assets]
 return {"query":q,"data":results[:limit],"has_more":len(results)>limit,"search_basis":"database_exact_and_substring"}
@router.get("/saved-searches")
async def saved_searches(db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(SavedSearch).where(SavedSearch.tenant_id==p.tenant_id).order_by(SavedSearch.name))).scalars().all();return {"data":[row(x) for x in items]}
@router.post("/saved-searches",status_code=201)
async def save_search(payload:SavedSearchCreate,db:DbSession,p:WritePrincipal)->dict:
 item=SavedSearch(tenant_id=p.tenant_id,user_id=None,**payload.model_dump());db.add(item);await db.flush();return row(item)

@router.post("/agent-commands/{intent_id}/publish",status_code=201)
async def publish_command(intent_id:str,db:DbSession,p:AdminPrincipal)->dict:
 intent=(await db.execute(select(EndpointIntent).where(EndpointIntent.id==intent_id,EndpointIntent.tenant_id==p.tenant_id).with_for_update())).scalar_one_or_none()
 if not intent:raise HTTPException(404,"Intent not found.")
 if intent.state!="approved":raise HTTPException(409,"Only approved intents can be published.")
 if intent.intent_type!="collect_inventory":raise HTTPException(409,"Only non-destructive collect_inventory is enabled in this release.")
 nonce=token_urlsafe(32); envelope={"command":"collect_inventory","agent_id":intent.agent_id,"nonce":nonce,"issued_at":datetime.now(UTC).isoformat(),"expires_at":intent.expires_at.isoformat()}
 item=AgentCommand(tenant_id=p.tenant_id,agent_id=intent.agent_id,intent_id=intent.id,nonce=nonce,envelope=envelope,state="available",available_at=datetime.now(UTC),expires_at=intent.expires_at);db.add(item);intent.delivery_state="available";await db.flush();return row(item)
@router.get("/agents/commands/poll")
async def poll_commands(request:Request,db:DbSession)->dict:
 agent=await resolve_agent_from_request(request,db,get_settings());now=datetime.now(UTC)
 items=(await db.execute(select(AgentCommand).where(AgentCommand.agent_id==agent.id,AgentCommand.state=="available",AgentCommand.available_at<=now,AgentCommand.expires_at>now).order_by(AgentCommand.available_at).limit(10))).scalars().all();return {"commands":[{"id":x.id,**x.envelope} for x in items]}
@router.post("/agents/commands/{command_id}/ack")
async def acknowledge_command(command_id:str,payload:CommandAck,request:Request,db:DbSession)->dict:
 agent=await resolve_agent_from_request(request,db,get_settings());item=(await db.execute(select(AgentCommand).where(AgentCommand.id==command_id,AgentCommand.agent_id==agent.id).with_for_update())).scalar_one_or_none()
 if not item:raise HTTPException(404,"Command not found.")
 if item.nonce!=payload.nonce:raise HTTPException(409,"Nonce mismatch.")
 if item.state!="available":return row(item)
 item.state=payload.state;item.result=payload.result;item.acknowledged_at=datetime.now(UTC);intent=await db.get(EndpointIntent,item.intent_id)
 if intent:intent.delivery_state=payload.state;intent.delivery_result=payload.result
 await db.flush();return row(item)

@router.get("/ai/evaluations")
async def evaluations(db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(AiEvaluation).where(or_(AiEvaluation.tenant_id.is_(None),AiEvaluation.tenant_id==p.tenant_id)).order_by(AiEvaluation.created_at.desc()).limit(200))).scalars().all();return {"data":[row(x) for x in items]}
@router.post("/ai/evaluations",status_code=201)
async def create_evaluation(payload:EvaluationCreate,db:DbSession,p:WritePrincipal)->dict:
 expected=set(payload.expected_refs);actual=set(payload.actual_refs);score=(len(expected&actual)/len(expected)) if expected else None;item=AiEvaluation(tenant_id=p.tenant_id,question=payload.question,expected_refs=payload.expected_refs,actual_refs=payload.actual_refs,grounded=bool(actual),score=score,model=payload.model,detail={"metric":"reference_recall"});db.add(item);await db.flush();return row(item)

@router.get("/detection-rules")
async def detection_rules(db:DbSession,p:ReadPrincipal)->dict:
 items=(await db.execute(select(DetectionRule).where(DetectionRule.tenant_id==p.tenant_id).order_by(DetectionRule.updated_at.desc()))).scalars().all();return {"data":[row(x) for x in items]}
@router.post("/detection-rules",status_code=201)
async def create_detection(payload:DetectionCreate,db:DbSession,p:WritePrincipal)->dict:
 checks={"non_empty":bool(payload.content.strip()),"format":payload.rule_format,"validated":False};item=DetectionRule(tenant_id=p.tenant_id,name=payload.name,rule_format=payload.rule_format,content=payload.content,version=payload.version,status="draft",attack_techniques=payload.attack_techniques,validation=checks,author=actor(p));db.add(item);await db.flush();return row(item)
