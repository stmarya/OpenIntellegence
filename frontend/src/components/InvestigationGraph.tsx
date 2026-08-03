'use client';

import Link from 'next/link';
import { useMemo, useRef, useState } from 'react';

export type GraphNode = {
  key: string;
  entity_type: string;
  entity_id: string;
  label: string;
  is_seed: boolean;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  confidence: number | null;
  evidence: Record<string, unknown>;
  sources: string[];
  valid_from?: string | null;
  valid_until?: string | null;
};

export type GraphPayload = {
  seed: { entity_type: string; entity_id: string };
  nodes: GraphNode[];
  edges: GraphEdge[];
  depth_requested: number;
  depth_reached: number;
  truncated: boolean;
  basis: string;
  provenance?: { note?: string | null; tenant_scope?: string | null };
};

type Position = { x: number; y: number };
type LocalSnapshot = {
  fixture_kind: string | null;
  saved_at: string;
  seed: GraphPayload['seed'];
  depth: number;
  nodes: string[];
  edges: string[];
  selected_key: string;
  visible_types: string[];
  zoom: number;
};

const WIDTH = 1080;
const HEIGHT = 660;
const CENTER = { x: WIDTH / 2, y: HEIGHT / 2 };
const MAX_RENDERED_NODES = 120;
const SYNTHETIC_FIXTURE = 'synthetic_test_only';
const SNAPSHOT_PREFIX = 'openintel.graph';

const ROUTES: Record<string, string> = {
  asset: 'assets',
  campaign: 'campaigns',
  correlation: 'correlations',
  indicator: 'indicators',
  investigation: 'investigations',
  malware: 'malware',
  ransomware: 'ransomware',
  threat_actor: 'threat-actors',
  vulnerability: 'vulnerabilities',
};

function detailHref(node: GraphNode): string | null {
  const route = ROUTES[node.entity_type.toLowerCase().replaceAll('-', '_')];
  return route ? `/${route}/${encodeURIComponent(node.entity_id)}` : null;
}

function colorFor(entityType: string): string {
  const palette = ['#16A9A0', '#4B92D6', '#D9A036', '#C56CF0', '#E06C34', '#5EC27F', '#D6383D'];
  let hash = 0;
  for (const character of entityType) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  return palette[hash % palette.length];
}

function buildPositions(nodes: GraphNode[]): Map<string, Position> {
  const positions = new Map<string, Position>();
  const seed = nodes.find((node) => node.is_seed) ?? nodes[0];
  if (seed) positions.set(seed.key, CENTER);
  const others = nodes.filter((node) => node.key !== seed?.key);
  const rings = [10, 18, 28, 40, 56];
  let offset = 0;
  rings.forEach((capacity, ringIndex) => {
    const ring = others.slice(offset, offset + capacity);
    const radius = 105 + ringIndex * 62;
    ring.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(1, ring.length) - Math.PI / 2;
      positions.set(node.key, {
        x: CENTER.x + Math.cos(angle) * radius,
        y: CENTER.y + Math.sin(angle) * radius,
      });
    });
    offset += capacity;
  });
  return positions;
}

function safeFilePart(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '-').slice(0, 80) || 'graph';
}

function download(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function snapshotKey(graph: GraphPayload): string {
  return `${SNAPSHOT_PREFIX}.${graph.seed.entity_type}.${graph.seed.entity_id}`;
}

export function InvestigationGraph({ graph }: { graph: GraphPayload }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const renderNodes = useMemo(
    () => graph.nodes.slice(0, MAX_RENDERED_NODES),
    [graph.nodes],
  );
  const renderedKeys = useMemo(
    () => new Set(renderNodes.map((node) => node.key)),
    [renderNodes],
  );
  const positions = useMemo(() => buildPositions(renderNodes), [renderNodes]);
  const entityTypes = useMemo(
    () => [...new Set(renderNodes.map((node) => node.entity_type))].sort(),
    [renderNodes],
  );
  const containsSynthetic = useMemo(
    () => graph.edges.some((edge) => edge.evidence.fixture_kind === SYNTHETIC_FIXTURE),
    [graph.edges],
  );
  const [visibleTypes, setVisibleTypes] = useState(() => new Set(entityTypes));
  const [selectedKey, setSelectedKey] = useState(
    renderNodes.find((node) => node.is_seed)?.key ?? renderNodes[0]?.key ?? '',
  );
  const [zoom, setZoom] = useState(1);
  const [notice, setNotice] = useState('');
  const selected = renderNodes.find((node) => node.key === selectedKey) ?? null;
  const visibleKeys = useMemo(
    () => new Set(renderNodes.filter((node) => visibleTypes.has(node.entity_type)).map((node) => node.key)),
    [renderNodes, visibleTypes],
  );
  const visibleEdges = graph.edges.filter(
    (edge) => renderedKeys.has(edge.source) && renderedKeys.has(edge.target) && visibleKeys.has(edge.source) && visibleKeys.has(edge.target),
  );
  const connectedEdges = selected
    ? graph.edges.filter((edge) => edge.source === selected.key || edge.target === selected.key)
    : [];

  function toggleType(entityType: string): void {
    setVisibleTypes((current) => {
      const next = new Set(current);
      if (next.has(entityType)) next.delete(entityType);
      else next.add(entityType);
      return next;
    });
  }

  function exportJson(): void {
    download(
      `cti-graph-${safeFilePart(graph.seed.entity_id)}.json`,
      JSON.stringify(graph, null, 2),
      'application/json',
    );
    setNotice('Complete evidence JSON exported.');
  }

  function exportSvg(): void {
    if (!svgRef.current) return;
    const clone = svgRef.current.cloneNode(true) as SVGSVGElement;
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    style.textContent = `
      .graph-edge{stroke:#657181;stroke-width:1.2;opacity:.72}
      .graph-edge-label{fill:#8793A3;font-size:9px;paint-order:stroke;stroke:#0A0C0F;stroke-width:3px}
      .graph-node circle{stroke:#0A0C0F;stroke-width:4}
      .graph-node-active circle{stroke:#fff;stroke-width:5}
      .graph-node-label{fill:#E7EAF0;font:700 10px Arial;paint-order:stroke;stroke:#0A0C0F;stroke-width:3px}
      .graph-node-type{fill:#9AA4B2;font:8px Arial;paint-order:stroke;stroke:#0A0C0F;stroke-width:3px}
    `;
    clone.prepend(style);
    const source = new XMLSerializer().serializeToString(clone);
    download(
      `cti-graph-${safeFilePart(graph.seed.entity_id)}.svg`,
      `<?xml version="1.0" encoding="UTF-8"?>\n${source}`,
      'image/svg+xml',
    );
    setNotice('Current visual graph exported as a self-contained SVG.');
  }

  function saveSnapshot(): void {
    const snapshot: LocalSnapshot = {
      fixture_kind: containsSynthetic ? SYNTHETIC_FIXTURE : null,
      saved_at: new Date().toISOString(),
      seed: graph.seed,
      depth: graph.depth_requested,
      nodes: graph.nodes.map((node) => node.key),
      edges: graph.edges.map((edge) => edge.id),
      selected_key: selectedKey,
      visible_types: [...visibleTypes],
      zoom,
    };
    try {
      localStorage.setItem(snapshotKey(graph), JSON.stringify(snapshot));
      setNotice('Local view saved. Intelligence evidence remains server-owned.');
    } catch {
      setNotice('The browser refused local storage. Export evidence JSON instead.');
    }
  }

  function restoreSnapshot(): void {
    try {
      const raw = localStorage.getItem(snapshotKey(graph));
      if (!raw) {
        setNotice('No local view exists for this seed entity.');
        return;
      }
      const snapshot = JSON.parse(raw) as LocalSnapshot;
      const sameSeed = snapshot.seed.entity_type === graph.seed.entity_type
        && snapshot.seed.entity_id === graph.seed.entity_id;
      if (!sameSeed || !Array.isArray(snapshot.visible_types)) {
        setNotice('The local view is invalid for this seed and was not restored.');
        return;
      }
      const restoredTypes = snapshot.visible_types.filter((value) => entityTypes.includes(value));
      setVisibleTypes(new Set(restoredTypes));
      if (renderedKeys.has(snapshot.selected_key)) setSelectedKey(snapshot.selected_key);
      if (Number.isFinite(snapshot.zoom)) setZoom(Math.min(1.8, Math.max(0.45, snapshot.zoom)));
      setNotice(`Local view restored from ${snapshot.saved_at}. Evidence was reloaded from the server.`);
    } catch {
      setNotice('The saved local view is unreadable and was not restored.');
    }
  }

  async function copyReportSummary(): Promise<void> {
    const lines = [
      containsSynthetic ? 'WARNING: SYNTHETIC TEST DATA — NOT TENANT TELEMETRY' : null,
      `Investigation graph: ${graph.seed.entity_type} ${graph.seed.entity_id}`,
      `Basis: ${graph.basis}`,
      `Nodes: ${graph.nodes.length}; relationships: ${graph.edges.length}; depth: ${graph.depth_reached}`,
      ...graph.edges.slice(0, 50).map((edge) => {
        const confidence = edge.confidence === null
          ? 'unknown confidence'
          : `${Math.round(edge.confidence * 100)}% confidence`;
        return `- ${edge.source} --${edge.relationship_type}--> ${edge.target} (${confidence}; sources: ${edge.sources.join(', ') || 'not recorded'})`;
      }),
    ].filter((line): line is string => line !== null);
    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setNotice('Evidence summary copied for a report draft. Verify citations before publishing.');
    } catch {
      setNotice('Clipboard access was refused by the browser. Export evidence JSON instead.');
    }
  }

  return (
    <div className="graph-workspace">
      {containsSynthetic ? (
        <p className="banner graph-synthetic" role="alert">
          SYNTHETIC TEST DATA — This graph contains development fixtures and is not tenant telemetry.
        </p>
      ) : null}
      <div className="graph-toolbar" aria-label="Graph controls">
        <button type="button" onClick={() => setZoom((value) => Math.min(1.8, value + 0.15))}>Zoom in</button>
        <button type="button" onClick={() => setZoom((value) => Math.max(0.45, value - 0.15))}>Zoom out</button>
        <button type="button" onClick={() => setZoom(1)}>Fit view</button>
        <button type="button" onClick={exportSvg}>Export SVG</button>
        <button type="button" onClick={exportJson}>Export evidence JSON</button>
        <button type="button" onClick={saveSnapshot}>Save local view</button>
        <button type="button" onClick={restoreSnapshot}>Restore local view</button>
        <button type="button" onClick={copyReportSummary}>Copy report summary</button>
        <span className="graph-counts">{graph.nodes.length} nodes · {graph.edges.length} edges · {graph.depth_reached} hops</span>
      </div>
      {notice ? <p className="graph-notice" role="status">{notice}</p> : null}

      <div className="graph-filters" aria-label="Entity type filters">
        {entityTypes.map((entityType) => (
          <label key={entityType}>
            <input
              type="checkbox"
              checked={visibleTypes.has(entityType)}
              onChange={() => toggleType(entityType)}
            />
            <span style={{ color: colorFor(entityType) }}>{entityType}</span>
          </label>
        ))}
      </div>

      <div className="graph-layout">
        <div className="graph-canvas" aria-label="CTI relationship graph">
          <svg ref={svgRef} viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-labelledby="graph-title graph-description">
            <title id="graph-title">Investigation relationship graph for {graph.seed.entity_id}</title>
            <desc id="graph-description">Persisted typed relationships. Select a node to inspect evidence.</desc>
            <defs>
              <marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L8,3 z" fill="#657181" />
              </marker>
            </defs>
            <g transform={`translate(${CENTER.x * (1 - zoom)} ${CENTER.y * (1 - zoom)}) scale(${zoom})`}>
              {visibleEdges.map((edge) => {
                const source = positions.get(edge.source);
                const target = positions.get(edge.target);
                if (!source || !target) return null;
                const midX = (source.x + target.x) / 2;
                const midY = (source.y + target.y) / 2;
                return (
                  <g key={edge.id}>
                    <line className="graph-edge" x1={source.x} y1={source.y} x2={target.x} y2={target.y} markerEnd="url(#graph-arrow)" />
                    {visibleEdges.length <= 40 ? (
                      <text className="graph-edge-label" x={midX} y={midY - 4} textAnchor="middle">{edge.relationship_type}</text>
                    ) : null}
                  </g>
                );
              })}
              {renderNodes.filter((node) => visibleKeys.has(node.key)).map((node) => {
                const position = positions.get(node.key);
                if (!position) return null;
                const active = selectedKey === node.key;
                const shortLabel = node.label.length > 24 ? `${node.label.slice(0, 21)}…` : node.label;
                return (
                  <g
                    key={node.key}
                    className={`graph-node${node.is_seed ? ' graph-node-seed' : ''}${active ? ' graph-node-active' : ''}`}
                    transform={`translate(${position.x} ${position.y})`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${node.entity_type}: ${node.label}`}
                    onClick={() => setSelectedKey(node.key)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') setSelectedKey(node.key);
                    }}
                  >
                    <circle r={node.is_seed ? 28 : 22} fill={colorFor(node.entity_type)} />
                    <text className="graph-node-label" y={node.is_seed ? 43 : 37} textAnchor="middle">{shortLabel}</text>
                    <text className="graph-node-type" y={node.is_seed ? 56 : 50} textAnchor="middle">{node.entity_type}</text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        <aside className="graph-inspector" aria-live="polite">
          {selected ? (
            <>
              <small>Selected entity</small>
              <h2>{selected.label}</h2>
              <dl>
                <dt>Type</dt><dd>{selected.entity_type}</dd>
                <dt>Identifier</dt><dd><code>{selected.entity_id}</code></dd>
                <dt>Relationships</dt><dd>{connectedEdges.length}</dd>
              </dl>
              <div className="graph-inspector-actions">
                <Link href={`/graph?entity_type=${encodeURIComponent(selected.entity_type)}&entity_id=${encodeURIComponent(selected.entity_id)}&depth=${graph.depth_requested}`}>Re-center and expand</Link>
                {detailHref(selected) ? <Link href={detailHref(selected) as string}>Open entity detail</Link> : null}
              </div>
              <h3>Connected evidence</h3>
              {connectedEdges.length ? (
                <ul className="graph-evidence-list">
                  {connectedEdges.map((edge) => (
                    <li key={edge.id}>
                      <strong>{edge.relationship_type}</strong>
                      <span>{edge.source === selected.key ? `to ${edge.target}` : `from ${edge.source}`}</span>
                      <small>
                        Confidence: {edge.confidence === null ? 'Unknown' : `${Math.round(edge.confidence * 100)}%`} · Sources: {edge.sources.length || 0}
                      </small>
                      {Object.keys(edge.evidence).length ? <pre>{JSON.stringify(edge.evidence, null, 2)}</pre> : <small>No structured evidence recorded.</small>}
                    </li>
                  ))}
                </ul>
              ) : <p className="muted">No visible relationship is connected to this node.</p>}
            </>
          ) : <p className="muted">Select a node to inspect its evidence.</p>}
        </aside>
      </div>

      {graph.nodes.length > MAX_RENDERED_NODES ? (
        <p className="banner">The API returned {graph.nodes.length} nodes. The canvas renders the first {MAX_RENDERED_NODES}; export JSON preserves the complete response.</p>
      ) : null}
      {graph.truncated ? <p className="banner">The traversal reached the configured edge cap. Narrow the relationship types or confidence threshold before treating this as a complete neighbourhood.</p> : null}
      <p className="muted">{graph.provenance?.note ?? 'Graph basis was not reported.'}</p>
    </div>
  );
}
