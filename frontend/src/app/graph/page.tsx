import type { Metadata } from 'next';
import { InvestigationGraph, type GraphPayload } from '@/components/InvestigationGraph';
import { fetchJson } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Investigation graph' };

type SearchParams = Record<string, string | string[] | undefined>;

function first(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? '' : value ?? '';
}

function numberInRange(value: string, fallback: number, minimum: number, maximum: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.min(maximum, Math.max(minimum, parsed)) : fallback;
}

export default async function GraphPage({ searchParams }: { searchParams?: SearchParams }) {
  const entityType = first(searchParams?.entity_type).trim();
  const entityId = first(searchParams?.entity_id).trim();
  const depth = numberInRange(first(searchParams?.depth), 2, 1, 3);
  const maxEdges = numberInRange(first(searchParams?.max_edges), 120, 1, 500);
  const minConfidence = Math.min(1, Math.max(0, Number(first(searchParams?.min_confidence)) || 0));
  const relationshipTypes = first(searchParams?.relationship_types).trim();

  const query = new URLSearchParams({
    entity_type: entityType,
    entity_id: entityId,
    depth: String(depth),
    max_edges: String(maxEdges),
    min_confidence: String(minConfidence),
  });
  if (relationshipTypes) query.set('relationship_types', relationshipTypes);
  const outcome = entityType && entityId
    ? await fetchJson<GraphPayload>(`/graph/traverse?${query.toString()}`)
    : null;
  const graphKey = `${entityType}:${entityId}:${depth}:${maxEdges}:${minConfidence}:${relationshipTypes}`;

  return (
    <section className="content graph-page">
      <header className="graph-page-header">
        <div>
          <h1>Investigation graph</h1>
          <p className="muted">Connect threat actors, campaigns, malware, indicators, vulnerabilities, assets, alerts, investigations, and reports through persisted evidence.</p>
        </div>
        <span className="chip chip-approved">Persisted edges only</span>
      </header>

      <form className="graph-query" method="get">
        <label>
          Entity type
          <input name="entity_type" defaultValue={entityType} placeholder="indicator" required maxLength={64} />
        </label>
        <label>
          Entity identifier
          <input name="entity_id" defaultValue={entityId} placeholder="example.org or entity UUID" required maxLength={255} />
        </label>
        <label>
          Depth
          <select name="depth" defaultValue={String(depth)}>
            <option value="1">1 hop</option>
            <option value="2">2 hops</option>
            <option value="3">3 hops</option>
          </select>
        </label>
        <label>
          Maximum edges
          <input name="max_edges" type="number" min="1" max="500" defaultValue={maxEdges} />
        </label>
        <label>
          Minimum confidence
          <input name="min_confidence" type="number" min="0" max="1" step="0.05" defaultValue={minConfidence} />
        </label>
        <label>
          Relationship types
          <input name="relationship_types" defaultValue={relationshipTypes} placeholder="uses,targets,observed_on" />
        </label>
        <button type="submit">Build evidence graph</button>
      </form>

      {!entityType || !entityId ? (
        <div className="state state-empty">
          <h2>Choose a seed entity</h2>
          <p>Enter an exact entity type and identifier. The canvas does not fabricate sample telemetry when no seed is supplied.</p>
        </div>
      ) : outcome?.status === 'unavailable' ? (
        <div className="state state-error">
          <h2>Graph API unavailable</h2>
          <p>{outcome.reason}</p>
        </div>
      ) : outcome?.status === 'ok' && outcome.data.nodes.length === 1 && outcome.data.edges.length === 0 ? (
        <div className="state state-empty">
          <h2>No persisted relationship found</h2>
          <p>The seed exists as the requested pivot, but no visible typed edge was returned. This is not presented as a clean intelligence assessment.</p>
        </div>
      ) : outcome?.status === 'ok' ? (
        <InvestigationGraph key={graphKey} graph={outcome.data} />
      ) : null}
    </section>
  );
}
