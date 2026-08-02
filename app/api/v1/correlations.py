"""Evidence correlation and grounded AI analyst-copilot endpoints."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.ai.rag import LlmError, RagService
from app.api.schemas import ListResponse, Page
from app.core.config import get_settings
from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.alert_models import Sighting
from app.db.correlation_models import Correlation, CorrelationAiBrief
from app.db.models import Asset, AssetExposure, Vulnerability
from app.services.correlation import assess
from app.services.provenance import build_provenance

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]
WritePrincipal = Annotated[Principal, Depends(require_scope(Scope.WRITE))]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CorrelationEvaluate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=3, max_length=512)
    primary_entity_type: str = Field(min_length=2, max_length=64)
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


def _rag(db) -> RagService:
    return RagService(db, get_settings(), httpx.AsyncClient())


def _resolution_status(base: dict) -> str:
    sections = (
        "vulnerability_context",
        "asset_context",
        "asset_exposure",
        "ioc_sightings",
        "ransomware_relevance",
    )
    supporting = 0
    unknown = 0
    for section in sections:
        value = base.get(section)
        if not isinstance(value, dict):
            continue
        if value.get("available"):
            supporting += 1
            if value.get("unknown_fields"):
                unknown += 1
    if supporting == 0:
        return "unavailable"
    return "partial" if unknown else "resolved"


async def _resolve_evidence(
    payload: CorrelationEvaluate, db: DbSession, principal: Principal
) -> dict:
    evidence: dict = {
        "entity": {"type": payload.primary_entity_type, "id": payload.primary_entity_id},
        "analyst_notes": payload.analyst_notes,
        "vulnerability_context": {
            "available": False,
            "cvss_score": None,
            "is_kev": None,
            "exploit_maturity": None,
            "source_record_ids": [],
            "unknown_fields": [],
        },
        "asset_context": {
            "available": False,
            "asset_id": None,
            "criticality": None,
            "internet_exposed": None,
            "source_record_ids": [],
            "unknown_fields": [],
        },
        "asset_exposure": {
            "available": False,
            "active_exposure_count": None,
            "source_record_ids": [],
            "unknown_fields": [],
        },
        "ioc_sightings": {
            "available": False,
            "count": None,
            "source_record_ids": [],
            "unknown_fields": [],
        },
        "ransomware_relevance": {
            "available": False,
            "is_relevant": None,
            "source_record_ids": [],
            "unknown_fields": [],
        },
        "provenance_references": [],
    }

    if payload.primary_entity_type != "asset":
        evidence["resolution_status"] = "unavailable"
        return evidence

    asset = (
        await db.execute(
            select(Asset).where(
                Asset.id == payload.primary_entity_id,
                Asset.tenant_id == principal.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if asset is None:
        evidence["resolution_status"] = "unavailable"
        return evidence

    evidence["asset_context"] = {
        "available": True,
        "asset_id": asset.id,
        "criticality": asset.criticality,
        "internet_exposed": None if asset.ip_address is None else True,
        "source_record_ids": [asset.id],
        "unknown_fields": [] if asset.ip_address is not None else ["internet_exposed"],
    }
    evidence["provenance_references"].append(
        {"type": "table", "name": "assets", "record_id": asset.id}
    )

    exposure_rows = (
        await db.execute(
            select(AssetExposure, Vulnerability)
            .join(Vulnerability, Vulnerability.id == AssetExposure.vulnerability_id)
            .where(
                AssetExposure.asset_id == asset.id,
                AssetExposure.resolved_at.is_(None),
            )
            .order_by(Vulnerability.cvss_score.desc().nulls_last())
        )
    ).all()
    if exposure_rows:
        exposures = [row[0] for row in exposure_rows]
        vulnerabilities = [row[1] for row in exposure_rows]
        cvss_values = [v.cvss_score for v in vulnerabilities if v.cvss_score is not None]
        is_kev_values = [bool(v.is_kev) for v in vulnerabilities]
        exploit_values = [v.exploit_maturity.value for v in vulnerabilities if v.exploit_maturity]
        evidence["asset_exposure"] = {
            "available": True,
            "active_exposure_count": len(exposures),
            "source_record_ids": [x.id for x in exposures],
            "unknown_fields": [],
        }
        evidence["vulnerability_context"] = {
            "available": True,
            "cvss_score": max(cvss_values) if cvss_values else None,
            "is_kev": bool(any(is_kev_values)),
            "exploit_maturity": exploit_values[0] if exploit_values else None,
            "source_record_ids": [v.id for v in vulnerabilities],
            "unknown_fields": [] if cvss_values else ["cvss_score"],
        }
        evidence["provenance_references"].append(
            {"type": "table", "name": "asset_exposures", "record_ids": [x.id for x in exposures]}
        )
        evidence["provenance_references"].append(
            {
                "type": "table",
                "name": "vulnerabilities",
                "record_ids": [v.id for v in vulnerabilities],
            }
        )

    sightings = (
        await db.execute(
            select(Sighting)
            .where(
                Sighting.tenant_id == principal.tenant_id,
                Sighting.asset_id == asset.id,
            )
            .order_by(Sighting.observed_at.desc())
            .limit(500)
        )
    ).scalars().all()
    if sightings:
        evidence["ioc_sightings"] = {
            "available": True,
            "count": len(sightings),
            "source_record_ids": [s.id for s in sightings],
            "unknown_fields": [],
        }
        relevance = [
            x.context.get("ransomware_relevant")
            for x in sightings
            if isinstance(x.context, dict) and "ransomware_relevant" in x.context
        ]
        evidence["ransomware_relevance"] = {
            "available": True,
            "is_relevant": (
                True if any(v is True for v in relevance) else False if relevance else None
            ),
            "source_record_ids": [s.id for s in sightings],
            "unknown_fields": [] if relevance else ["is_relevant"],
        }
        evidence["provenance_references"].append(
            {"type": "table", "name": "sightings", "record_ids": [s.id for s in sightings]}
        )

    evidence["resolution_status"] = _resolution_status(evidence)
    return evidence


@router.post(
    "/correlations/evaluate", response_model=CorrelationOut, status_code=status.HTTP_201_CREATED
)
async def evaluate(
    payload: CorrelationEvaluate, db: DbSession, principal: WritePrincipal
) -> CorrelationOut:
    if payload.manual_annotation is not None and not principal.has(Scope.ADMIN):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Manual evidence annotation requires admin scope.",
        )

    evidence = await _resolve_evidence(payload, db, principal)
    if payload.manual_annotation is not None:
        evidence["manual_annotation"] = payload.manual_annotation
        evidence["resolution_status"] = "manual_input"
        evidence["server_resolution_status"] = _resolution_status(evidence)

    scoring_input = {
        "cvss_score": evidence["vulnerability_context"]["cvss_score"],
        "is_kev": evidence["vulnerability_context"]["is_kev"],
        "exploit_maturity": evidence["vulnerability_context"]["exploit_maturity"],
        "asset_criticality": evidence["asset_context"]["criticality"],
        "internet_exposed": evidence["asset_context"]["internet_exposed"],
        "sighting_count": evidence["ioc_sightings"]["count"],
        "ransomware_relevant": evidence["ransomware_relevance"]["is_relevant"],
        "source_refs": evidence["provenance_references"],
    }
    outcome = assess(scoring_input)
    record = Correlation(
        tenant_id=principal.tenant_id,
        title=payload.title,
        primary_entity_type=payload.primary_entity_type,
        primary_entity_id=payload.primary_entity_id,
        evidence=evidence,
        factor_breakdown=outcome.factors,
        risk_score=outcome.score,
        risk_tier=outcome.tier,
        automation_candidates=outcome.automation_candidates,
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
    item = (
        await db.execute(
            select(Correlation).where(
                Correlation.id == correlation_id, Correlation.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Correlation not found.")

    prompt = (
        "Write a concise analyst brief for this computed correlation. "
        "Use only retrieved workspace records for factual claims beyond "
        "the supplied computed evidence. Explicitly distinguish unknowns, "
        "do not recommend automatic execution, and cite supporting records. "
        "Server-resolved evidence: "
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
    if not citation_data or item.evidence.get("resolution_status") == "unavailable":
        brief = CorrelationAiBrief(
            correlation_id=item.id,
            status="unverified",
            content=(
                "No supporting persisted evidence was retrieved. "
                "The AI brief is intentionally withheld; review the "
                "deterministic evidence and source references instead."
            ),
            citations=[],
            model_label="rag-grounded",
            generated_at=datetime.now(UTC),
        )
    else:
        brief = CorrelationAiBrief(
            correlation_id=item.id,
            status="grounded",
            content=answer,
            citations=citation_data,
            model_label="rag-grounded",
            generated_at=datetime.now(UTC),
        )
    db.add(brief)
    await db.flush()
    await db.refresh(brief)
    return AiBriefOut.model_validate(brief)
