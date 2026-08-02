"""Evidence correlation and grounded AI analyst-copilot endpoints."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.ai.rag import LlmError, RagService
from app.api.schemas import ListResponse, Page
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.correlation_models import Correlation, CorrelationAiBrief
from app.services.correlation import assess
from app.services.evidence_resolver import SUPPORTED_ENTITY_TYPES, resolve_evidence
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CorrelationEvaluate(BaseModel):
    """Only identity and analyst notes may be supplied by a client.

    Risk facts are resolved from persisted data in the tenant context. Legacy
    score fields are rejected instead of becoming unverified evidence.
    """
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=512)
    primary_entity_type: Literal["asset", "vulnerability", "indicator"]
    primary_entity_id: str = Field(min_length=1, max_length=255)
    analyst_notes: str | None = Field(default=None, max_length=4000)
    manual_annotation: dict | None = None


class CorrelationOut(ORM):
    id: str
    title: str
    primary_entity_type: str
    primary_entity_id: str
    evidence: dict
    factor_breakdown: list
    risk_score: int
    risk_tier: str
    automation_candidates: list
    evaluated_at: datetime


class AiBriefOut(ORM):
    id: str
    status: str
    content: str
    citations: list
    model_label: str
    generated_at: datetime


class CorrelationDetail(CorrelationOut):
    ai_briefs: list[AiBriefOut] = Field(default_factory=list)


def _rag(db: DbSession) -> RagService:
    return RagService(db, get_settings(), httpx.AsyncClient())


@router.post("/correlations/evaluate", response_model=CorrelationOut, status_code=status.HTTP_201_CREATED)
async def evaluate(payload: CorrelationEvaluate, db: DbSession, principal: WritePrincipal) -> CorrelationOut:
    if payload.primary_entity_type not in SUPPORTED_ENTITY_TYPES:
        # Defensive guard; the Literal produces FastAPI's 422 before this path.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unsupported correlation entity type.")
    if payload.manual_annotation is not None and not principal.has(Scope.ADMIN):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Manual evidence annotation requires admin scope.")

    evidence = await resolve_evidence(
        db, tenant_id=principal.tenant_id, entity_type=payload.primary_entity_type,
        entity_id=payload.primary_entity_id, analyst_notes=payload.analyst_notes,
    )
    server_resolution_status = evidence["resolution_status"]
    if payload.manual_annotation is not None:
        evidence["manual_annotation"] = payload.manual_annotation
        evidence["server_resolution_status"] = server_resolution_status
        # Annotation is preserved separately and never contributes to the score.
        evidence["resolution_status"] = "manual_input"

    vulnerability = evidence["vulnerability_context"]
    asset = evidence["asset_context"]
    sightings = evidence["ioc_sightings"]
    ransomware = evidence["ransomware_relevance"]
    outcome = assess({
        "cvss_score": vulnerability["cvss_score"], "is_kev": vulnerability["is_kev"],
        "exploit_maturity": vulnerability["exploit_maturity"], "asset_criticality": asset["criticality"],
        "internet_exposed": asset["internet_exposed"], "sighting_count": sightings["count"],
        "ransomware_relevant": ransomware["is_relevant"],
    })
    record = Correlation(
        tenant_id=principal.tenant_id, title=payload.title, primary_entity_type=payload.primary_entity_type,
        primary_entity_id=payload.primary_entity_id, evidence=evidence, factor_breakdown=outcome.factors,
        risk_score=outcome.score, risk_tier=outcome.tier, automation_candidates=outcome.automation_candidates,
        evaluated_at=datetime.now(UTC),
    )
    db.add(record)
    await db.flush()
    return CorrelationOut.model_validate(record)


@router.get("/correlations", response_model=ListResponse[CorrelationOut])
async def list_correlations(db: DbSession, principal: ReadPrincipal, limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0, risk_tier: str | None = None) -> ListResponse[CorrelationOut]:
    stmt = select(Correlation).where(Correlation.tenant_id == principal.tenant_id)
    if risk_tier:
        stmt = stmt.where(Correlation.risk_tier == risk_tier)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (await db.execute(stmt.order_by(Correlation.risk_score.desc(), Correlation.evaluated_at.desc()).limit(limit).offset(offset))).scalars().all()
    return ListResponse(data=[CorrelationOut.model_validate(item) for item in rows], page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total), provenance=await build_provenance(db, sources=None))


@router.get("/correlations/{correlation_id}", response_model=CorrelationDetail)
async def get_correlation(correlation_id: str, db: DbSession, principal: ReadPrincipal) -> CorrelationDetail:
    item = (await db.execute(select(Correlation).where(Correlation.id == correlation_id, Correlation.tenant_id == principal.tenant_id))).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Correlation not found.")
    briefs = (await db.execute(select(CorrelationAiBrief).where(CorrelationAiBrief.correlation_id == item.id).order_by(CorrelationAiBrief.generated_at.desc()))).scalars().all()
    return CorrelationDetail(**CorrelationOut.model_validate(item).model_dump(), ai_briefs=[AiBriefOut.model_validate(brief) for brief in briefs])


@router.post("/correlations/{correlation_id}/ai-brief", response_model=AiBriefOut, status_code=status.HTTP_201_CREATED)
async def generate_ai_brief(correlation_id: str, db: DbSession, principal: WritePrincipal) -> AiBriefOut:
    item = (await db.execute(select(Correlation).where(Correlation.id == correlation_id, Correlation.tenant_id == principal.tenant_id))).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Correlation not found.")
    prompt = "Write a concise analyst brief using only retrieved records. Distinguish unknowns, do not recommend automatic execution, and cite facts. Server-resolved evidence: " + json.dumps(item.evidence) + ". Factor breakdown: " + json.dumps(item.factor_breakdown)
    service = _rag(db)
    try:
        answer, citations = await service.answer(prompt, top_k=12)
    except LlmError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Grounded AI provider failed: {exc}") from exc
    finally:
        await service.client.aclose()
    citation_data = [citation.model_dump() for citation in citations]
    unavailable = item.evidence.get("server_resolution_status", item.evidence.get("resolution_status")) == "unavailable"
    brief = CorrelationAiBrief(
        correlation_id=item.id, status="grounded" if citation_data and not unavailable else "unverified",
        content=answer if citation_data and not unavailable else "No supporting persisted evidence was retrieved. The AI brief is intentionally withheld; review the deterministic evidence instead.",
        citations=citation_data if not unavailable else [], model_label="rag-grounded", generated_at=datetime.now(UTC),
    )
    db.add(brief)
    await db.flush()
    await db.refresh(brief)
    return AiBriefOut.model_validate(brief)
