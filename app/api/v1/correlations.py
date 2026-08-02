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
from app.services.evidence_resolver import EvidenceResolver, build_from_manual
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ManualEvidence(BaseModel):
    """Caller-supplied evidence for development / analyst override.

    Requires admin scope.  The assessment is always marked ``manual_input``
    and the supplied values are preserved separately from source-resolved
    evidence.
    """

    cvss_score: float | None = Field(default=None, ge=0, le=10)
    is_kev: bool = False
    exploit_maturity: str | None = None
    asset_criticality: Literal["low", "medium", "high", "critical"] | None = None
    internet_exposed: bool = False
    sighting_count: int = Field(default=0, ge=0)
    ransomware_relevant: bool = False
    source_refs: list[dict] = Field(default_factory=list)


class CorrelationEvaluate(BaseModel):
    """Request body for the evaluate endpoint.

    The client supplies only entity identity and optional analyst context.
    Scoring factors are resolved server-side from persisted platform records.

    ``manual_evidence`` is an opt-in development/analyst-override field that
    requires ``admin`` scope.  It marks the result as ``manual_input`` and
    preserves supplied values separately; they never override resolved facts.
    """

    title: str = Field(min_length=3, max_length=512)
    primary_entity_type: str = Field(min_length=2, max_length=64)
    primary_entity_id: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=4000)
    manual_evidence: ManualEvidence | None = None


class CorrelationOut(ORM):
    id: str
    title: str
    primary_entity_type: str
    primary_entity_id: str
    #: Explainable evidence snapshot; null fields are genuinely unknown, not zero.
    evidence: dict
    factor_breakdown: list
    risk_score: int
    risk_tier: str
    automation_candidates: list
    #: "resolved" | "partial" | "manual_input" | "unavailable"
    resolution_status: str
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


def _rag(db) -> RagService:
    return RagService(db, get_settings(), httpx.AsyncClient())


@router.post(
    "/correlations/evaluate", response_model=CorrelationOut, status_code=status.HTTP_201_CREATED
)
async def evaluate(
    payload: CorrelationEvaluate, db: DbSession, principal: WritePrincipal
) -> CorrelationOut:
    """Evaluate a correlation by resolving evidence from platform records.

    The caller supplies only entity identity and optional analyst notes.
    Scoring factors are resolved server-side from persisted platform records.

    If ``manual_evidence`` is provided the caller must hold ``admin`` scope;
    the result is marked ``manual_input`` and supplied values are preserved
    separately from source-resolved evidence.
    """
    if payload.manual_evidence is not None and not principal.has(Scope.ADMIN):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Supplying manual evidence requires admin scope.",
                "required": [Scope.ADMIN],
                "missing": [Scope.ADMIN],
                "granted": sorted(principal.scopes),
            },
        )

    if payload.manual_evidence is not None:
        resolved = build_from_manual(
            entity_type=payload.primary_entity_type,
            entity_id=payload.primary_entity_id,
            tenant_id=principal.tenant_id,
            manual=payload.manual_evidence.model_dump(),
            analyst_notes=payload.notes,
        )
    else:
        resolver = EvidenceResolver(db, principal.tenant_id)
        resolved = await resolver.resolve(
            payload.primary_entity_type,
            payload.primary_entity_id,
            analyst_notes=payload.notes,
        )

    outcome = assess(resolved.to_scoring_dict())
    snapshot = resolved.to_snapshot()
    if payload.notes:
        snapshot["analyst_notes"] = payload.notes

    record = Correlation(
        tenant_id=principal.tenant_id,
        title=payload.title,
        primary_entity_type=payload.primary_entity_type,
        primary_entity_id=payload.primary_entity_id,
        evidence=snapshot,
        factor_breakdown=outcome.factors,
        risk_score=outcome.score,
        risk_tier=outcome.tier,
        automation_candidates=outcome.automation_candidates,
        resolution_status=resolved.resolution_status,
        manual_evidence=resolved.manual_evidence,
        evaluated_at=datetime.now(UTC),
    )
    db.add(record)
    await db.flush()
    return CorrelationOut.model_validate(record)


@router.get("/correlations", response_model=ListResponse[CorrelationOut])
async def list_correlations(
    db: DbSession,
    principal: ReadPrincipal,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    risk_tier: str | None = None,
) -> ListResponse[CorrelationOut]:
    stmt = select(Correlation).where(Correlation.tenant_id == principal.tenant_id)
    if risk_tier:
        stmt = stmt.where(Correlation.risk_tier == risk_tier)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Correlation.risk_score.desc(), Correlation.evaluated_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ListResponse(
        data=[CorrelationOut.model_validate(x) for x in rows],
        page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total),
        provenance=await build_provenance(db, sources=None),
    )


@router.get("/correlations/{correlation_id}", response_model=CorrelationDetail)
async def get_correlation(
    correlation_id: str, db: DbSession, principal: ReadPrincipal
) -> CorrelationDetail:
    item = (
        await db.execute(
            select(Correlation).where(
                Correlation.id == correlation_id, Correlation.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Correlation not found.")
    briefs = (
        (
            await db.execute(
                select(CorrelationAiBrief)
                .where(CorrelationAiBrief.correlation_id == item.id)
                .order_by(CorrelationAiBrief.generated_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return CorrelationDetail(
        **CorrelationOut.model_validate(item).model_dump(),
        ai_briefs=[AiBriefOut.model_validate(x) for x in briefs],
    )


@router.post(
    "/correlations/{correlation_id}/ai-brief",
    response_model=AiBriefOut,
    status_code=status.HTTP_201_CREATED,
)
async def generate_ai_brief(
    correlation_id: str, db: DbSession, principal: WritePrincipal
) -> AiBriefOut:
    """Generate a grounded AI brief for a persisted correlation.

    Uses the server-resolved evidence snapshot stored at evaluation time.
    Cites retrieved workspace records.  Returns ``unverified`` status when
    no supporting evidence exists or the resolution status is ``unavailable``.
    """
    item = (
        await db.execute(
            select(Correlation).where(
                Correlation.id == correlation_id, Correlation.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Correlation not found.")

    resolution_note = (
        "This correlation used manual analyst-supplied evidence "
        "and was not source-resolved."
        if item.resolution_status == "manual_input"
        else f"Evidence resolution status: {item.resolution_status}."
    )
    prompt = (
        "Write a concise analyst brief for this server-resolved correlation. "
        "Use only retrieved workspace records for factual claims beyond "
        "the supplied evidence. Explicitly distinguish unknowns; do not "
        "recommend automatic execution; cite supporting records. "
        + resolution_note
        + " If resolution_status is 'unavailable' or 'partial', state that "
        "the evidence is incomplete and the brief is unverified. "
        "Resolved evidence: "
        + json.dumps(item.evidence)
        + ". Factor breakdown: "
        + json.dumps(item.factor_breakdown)
        + "."
    )
    service = _rag(db)
    try:
        answer, citations = await service.answer(prompt, top_k=12)
    except LlmError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Grounded AI provider failed: {exc}"
        ) from exc
    finally:
        await service.client.aclose()

    citation_data = [citation.model_dump() for citation in citations]
    if not citation_data:
        brief = CorrelationAiBrief(
            correlation_id=item.id,
            status="unverified",
            content=(
                "No supporting workspace records were retrieved. "
                "The AI brief is intentionally withheld; review the "
                "deterministic evidence and source references instead."
            ),
            citations=[],
        )
    else:
        brief = CorrelationAiBrief(
            correlation_id=item.id,
            status="grounded",
            content=answer,
            citations=citation_data,
        )
    db.add(brief)
    await db.flush()
    return AiBriefOut.model_validate(brief)

