"""Tenant-scoped graph traversal over persisted typed CTI relationships."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, or_, select

from app.core.deps import DbSession, Principal, Scope, require_scope
from app.db.platform_models import EntityRelationship

router = APIRouter()
ReadPrincipal = Annotated[Principal, Depends(require_scope(Scope.READ))]


def node_key(entity_type: str, entity_id: str) -> str:
    """Return an unambiguous stable key for a graph node."""
    return f"{entity_type}:{entity_id}"


def label_from_evidence(evidence: dict, side: str, entity_id: str) -> str:
    """Use a persisted display label when one exists, otherwise keep the ID honest."""
    label = evidence.get(f"{side}_label")
    return str(label) if label not in (None, "") else entity_id


def upsert_node(
    nodes: dict[str, dict],
    entity: tuple[str, str],
    seed: tuple[str, str],
    label: str,
) -> None:
    """Add a node and enrich an ID-only seed label from persisted evidence."""
    key = node_key(*entity)
    existing = nodes.get(key)
    if existing is None:
        nodes[key] = {
            "key": key,
            "entity_type": entity[0],
            "entity_id": entity[1],
            "label": label,
            "is_seed": entity == seed,
        }
    elif existing["label"] == existing["entity_id"] and label != entity[1]:
        existing["label"] = label


@router.get("/graph/traverse")
async def traverse_graph(
    db: DbSession,
    principal: ReadPrincipal,
    entity_type: Annotated[str, Query(min_length=1, max_length=64)],
    entity_id: Annotated[str, Query(min_length=1, max_length=255)],
    depth: Annotated[int, Query(ge=1, le=3)] = 2,
    max_edges: Annotated[int, Query(ge=1, le=500)] = 200,
    relationship_types: Annotated[str | None, Query(max_length=1000)] = None,
    min_confidence: Annotated[float, Query(ge=0, le=1)] = 0,
) -> dict:
    """Traverse both inbound and outbound edges from a seed entity.

    The endpoint caps depth and edge count. It returns only persisted
    relationships visible to the tenant; it never asks a model to invent a link.
    """
    allowed_relationships = {
        value.strip()
        for value in (relationship_types or "").split(",")
        if value.strip()
    }
    seed = (entity_type, entity_id)
    frontier = {seed}
    visited = {seed}
    nodes: dict[str, dict] = {
        node_key(*seed): {
            "key": node_key(*seed),
            "entity_type": entity_type,
            "entity_id": entity_id,
            "label": entity_id,
            "is_seed": True,
        }
    }
    edges: dict[str, dict] = {}
    depth_reached = 0
    truncated = False

    for hop in range(1, depth + 1):
        if not frontier or len(edges) >= max_edges:
            break
        endpoint_conditions = []
        for current_type, current_id in frontier:
            endpoint_conditions.extend(
                [
                    and_(
                        EntityRelationship.source_type == current_type,
                        EntityRelationship.source_id == current_id,
                    ),
                    and_(
                        EntityRelationship.target_type == current_type,
                        EntityRelationship.target_id == current_id,
                    ),
                ]
            )
        filters = [
            or_(
                EntityRelationship.tenant_id.is_(None),
                EntityRelationship.tenant_id == principal.tenant_id,
            ),
            or_(*endpoint_conditions),
        ]
        if edges:
            filters.append(~EntityRelationship.id.in_(tuple(edges)))
        if allowed_relationships:
            filters.append(EntityRelationship.relationship_type.in_(allowed_relationships))
        if min_confidence > 0:
            filters.append(EntityRelationship.confidence >= min_confidence)

        remaining = max_edges - len(edges)
        statement = (
            select(EntityRelationship)
            .where(*filters)
            .order_by(EntityRelationship.created_at.asc(), EntityRelationship.id.asc())
            .limit(remaining + 1)
        )
        discovered = (await db.execute(statement)).scalars().all()
        if len(discovered) > remaining:
            truncated = True
            discovered = discovered[:remaining]

        next_frontier: set[tuple[str, str]] = set()
        for relationship in discovered:
            source = (relationship.source_type, relationship.source_id)
            target = (relationship.target_type, relationship.target_id)
            source_key = node_key(*source)
            target_key = node_key(*target)
            evidence = relationship.evidence if isinstance(relationship.evidence, dict) else {}
            upsert_node(
                nodes,
                source,
                seed,
                label_from_evidence(evidence, "source", source[1]),
            )
            upsert_node(
                nodes,
                target,
                seed,
                label_from_evidence(evidence, "target", target[1]),
            )
            edges[relationship.id] = {
                "id": relationship.id,
                "source": source_key,
                "target": target_key,
                "relationship_type": relationship.relationship_type,
                "confidence": relationship.confidence,
                "evidence": evidence,
                "sources": relationship.sources,
                "valid_from": relationship.valid_from,
                "valid_until": relationship.valid_until,
            }
            if source not in visited:
                next_frontier.add(source)
            if target not in visited:
                next_frontier.add(target)

        visited.update(next_frontier)
        frontier = next_frontier
        if discovered:
            depth_reached = hop
        if truncated:
            break

    ordered_nodes = sorted(
        nodes.values(),
        key=lambda item: (
            not item["is_seed"],
            item["entity_type"],
            item["label"],
            item["entity_id"],
        ),
    )
    ordered_edges = sorted(
        edges.values(),
        key=lambda item: (
            item["relationship_type"],
            item["source"],
            item["target"],
            item["id"],
        ),
    )
    return {
        "seed": {"entity_type": entity_type, "entity_id": entity_id},
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "depth_requested": depth,
        "depth_reached": depth_reached,
        "truncated": truncated,
        "basis": "persisted_typed_relationships",
        "provenance": {
            "note": "Every edge is a persisted relationship. No model-generated links are included.",
            "tenant_scope": "tenant_and_global_reference_data",
        },
    }
