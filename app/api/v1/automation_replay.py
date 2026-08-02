"""Dead-letter replay control-plane API; replay never delivers a connector action."""
from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter,Depends,HTTPException,status
from pydantic import BaseModel,ConfigDict
from app.core.deps import DbSession,Principal,Scope,require_scope
from app.services.dead_letter_replay import replay_dead_letter
router=APIRouter(); WritePrincipal=Annotated[Principal,Depends(require_scope(Scope.WRITE))]
class ReplayOut(BaseModel):
 model_config=ConfigDict(from_attributes=True)
 id:str; state:str; action:str; idempotency_key:str
@router.post("/automation-outbox/{outbox_id}/replay",response_model=ReplayOut,status_code=status.HTTP_202_ACCEPTED)
async def replay(outbox_id:str,db:DbSession,principal:WritePrincipal)->ReplayOut:
 try: item=await replay_dead_letter(db,tenant_id=principal.tenant_id,outbox_id=outbox_id,actor=f"api_key:{principal.api_key_id}")
 except LookupError: raise HTTPException(status.HTTP_404_NOT_FOUND,"Dead-letter item not found.")
 except ValueError as exc: raise HTTPException(status.HTTP_409_CONFLICT,str(exc))
 return ReplayOut.model_validate(item)
