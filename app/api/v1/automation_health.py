"""Safe automation capability health; no credentials or network probes."""
from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends
from app.core.config import get_settings
from app.core.deps import Principal, Scope, require_scope
from app.services.automation_capabilities import capabilities
router=APIRouter()
ReadPrincipal=Annotated[Principal,Depends(require_scope(Scope.READ))]
@router.get("/automation/capabilities")
async def get_capabilities(principal:ReadPrincipal)->dict:
 return {"tenant_scoped":True,"capabilities":[item.as_dict() for item in capabilities(get_settings()).values()]}
