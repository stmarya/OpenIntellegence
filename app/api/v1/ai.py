"""AI endpoints: grounded chat and report generation."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Annotated
import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from app.ai.grounding import enforce_citation_contract
from app.ai.rag import LlmError, RagService
from app.ai.reports import TEMPLATES, ReportGenerator
from app.api.schemas import ChatRequest, ChatResponse, ListResponse, Page, ReportOut, ReportRequest
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.models import Report, ReportStatus
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
ReportWriter = Annotated[Principal, Depends(require_scope(Scope.REPORT_WRITE))]

def _rag(db) -> RagService:
    settings = get_settings()
    return RagService(db, settings, httpx.AsyncClient(timeout=settings.llm_timeout_seconds))

@router.post("/chat/query", response_model=ChatResponse, summary="Ask a grounded question")
async def chat(payload: ChatRequest, db: DbSession, principal: ReadPrincipal) -> ChatResponse:
    service = _rag(db)
    try:
        answer, citations = await service.answer(payload.question, payload.top_k)
        answer, contract_ok = enforce_citation_contract(answer, citations, generated=service.is_configured)
    except LlmError as exc:
        # Provider response bodies can contain tenant prompts; never echo them to clients.
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "The language model request failed.") from exc
    finally:
        await service.client.aclose()
    provenance = await build_provenance(db, sources=None)
    if not citations:
        provenance.note = "No supporting records were retrieved; no model narrative was accepted."
    elif not contract_ok:
        provenance.note = "Retrieved evidence exists, but generated prose was withheld because citation markers were absent or invalid."
    return ChatResponse(answer=answer, citations=citations, provenance=provenance)

@router.get("/reports/templates", summary="Available report templates")
async def templates(principal: ReadPrincipal) -> dict:
    return {"templates": [{"key": spec.key, "title": spec.title, "default_period_days": spec.default_period_days} for spec in TEMPLATES.values()]}

@router.post("/reports/generate", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED, summary="Generate a report")
async def generate_report(payload: ReportRequest, background: BackgroundTasks, db: DbSession, principal: ReportWriter) -> ReportOut:
    spec = TEMPLATES[payload.template]
    report = Report(
        tenant_id=principal.tenant_id,
        template=payload.template,
        title=payload.title or f"{spec.title} — {datetime.now(UTC):%d %b %Y}",
        status=ReportStatus.QUEUED,
        progress=0,
        period_start=payload.period_start,
        period_end=payload.period_end,
        requested_by=str(principal.api_key_id),
    )
    db.add(report)
    await db.flush()
    report_id, focus = str(report.id), payload.focus_cve_id

    async def _run() -> None:
        from app.db.base import get_session_factory
        async with get_session_factory()() as session:
            target = await session.get(Report, report_id)
            if target is None:
                return
            service = _rag(session)
            try:
                await ReportGenerator(session, service).generate(target, focus_cve_id=focus)
                await session.commit()
            except Exception as exc:
                target.status = ReportStatus.FAILED
                target.error_message = type(exc).__name__
                await session.commit()
            finally:
                await service.client.aclose()
    background.add_task(_run)
    return ReportOut.model_validate(report)

@router.get("/reports", response_model=ListResponse[ReportOut], summary="List reports")
async def list_reports(db: DbSession, principal: ReadPrincipal, limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0) -> ListResponse[ReportOut]:
    stmt = select(Report).where(Report.tenant_id == principal.tenant_id)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (await db.execute(stmt.order_by(Report.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return ListResponse[ReportOut](data=[ReportOut.model_validate(r) for r in rows], page=Page(limit=limit, offset=offset, total=total, has_more=offset + limit < total), provenance=await build_provenance(db, sources=None))

@router.get("/reports/{report_id}", response_model=ReportOut, summary="Fetch a report")
async def get_report(report_id: str, db: DbSession, principal: ReadPrincipal) -> ReportOut:
    report = (await db.execute(select(Report).where(Report.id == report_id, Report.tenant_id == principal.tenant_id))).scalar_one_or_none()
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found.")
    return ReportOut.model_validate(report)
