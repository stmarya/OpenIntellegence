import { fireEvent, render, screen } from '@testing-library/react';
import { InvestigationGraph, type GraphPayload } from './InvestigationGraph';

const syntheticGraph: GraphPayload = {
  seed: { entity_type: 'campaign', entity_id: 'synthetic-campaign' },
  depth_requested: 2,
  depth_reached: 1,
  truncated: false,
  basis: 'persisted_typed_relationships',
  provenance: { note: 'Every edge is persisted.' },
  nodes: [
    {
      key: 'campaign:synthetic-campaign',
      entity_type: 'campaign',
      entity_id: 'synthetic-campaign',
      label: 'Synthetic campaign',
      is_seed: true,
    },
    {
      key: 'threat_actor:synthetic-actor',
      entity_type: 'threat_actor',
      entity_id: 'synthetic-actor',
      label: 'Synthetic actor',
      is_seed: false,
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'campaign:synthetic-campaign',
      target: 'threat_actor:synthetic-actor',
      relationship_type: 'attributed_to',
      confidence: 0.8,
      evidence: {
        fixture_kind: 'synthetic_test_only',
        note: 'Not tenant telemetry.',
      },
      sources: ['synthetic_graph_fixture'],
    },
  ],
};


describe('InvestigationGraph', () => {
  it('prominently labels synthetic fixtures', () => {
    render(<InvestigationGraph graph={syntheticGraph} />);
    expect(screen.getByRole('alert')).toHaveTextContent('SYNTHETIC TEST DATA');
    expect(screen.getByRole('alert')).toHaveTextContent('not tenant telemetry');
  });

  it('selects a node and exposes its connected evidence', () => {
    render(<InvestigationGraph graph={syntheticGraph} />);
    fireEvent.click(screen.getByRole('button', { name: 'threat_actor: Synthetic actor' }));
    expect(screen.getByText('Synthetic actor')).toBeInTheDocument();
    expect(screen.getByText('attributed_to')).toBeInTheDocument();
    expect(screen.getByText(/Confidence: 80%/)).toBeInTheDocument();
  });

  it('does not show a synthetic warning for ordinary persisted evidence', () => {
    const ordinary: GraphPayload = {
      ...syntheticGraph,
      edges: syntheticGraph.edges.map((edge) => ({
        ...edge,
        evidence: { note: 'Analyst-confirmed relationship.' },
        sources: ['analyst_review'],
      })),
    };
    render(<InvestigationGraph graph={ordinary} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
