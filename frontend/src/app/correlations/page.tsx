import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { RiskBadge } from '@/components/RiskBadge';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Correlations' };

type CorrelationRow = {
  id: string;
  title?: string | null;
  primary_entity_type?: string | null;
  primary_entity_id?: string | null;
  risk_score?: number | null;
  risk_tier?: string | null;
  automation_candidates?: unknown[];
  evaluated_at?: string | null;
};

const columns: Column<CorrelationRow>[] = [
  {
    key: 'title',
    header: 'Correlation',
    render: (row) => (
      <>
        <Link href={`/correlations/${row.id}`}>
          <strong>{unknown(row.title)}</strong>
        </Link>
        <br />
        <small>
          {unknown(row.primary_entity_type)} · {unknown(row.primary_entity_id)}
        </small>
      </>
    ),
  },
  {
    key: 'risk',
    header: 'Risk',
    render: (row) => <RiskBadge score={row.risk_score ?? null} knownExploited={row.risk_tier === 'critical'} />,
  },
  { key: 'tier', header: 'Tier', render: (row) => <>{unknown(row.risk_tier)}</> },
  {
    key: 'automation',
    header: 'Automation candidates',
    render: (row) => <>{row.automation_candidates?.length ?? 0} proposed</>,
  },
  { key: 'evaluated', header: 'Evaluated', render: (row) => <small>{unknown(row.evaluated_at)}</small> },
];

export default async function CorrelationsPage() {
  const envelope = await fetchList<CorrelationRow>('/correlations');
  return (
    <section className="content">
      <h1>Correlations</h1>
      <p className="muted">
        Scores come from a deterministic factor breakdown, never from a model. Automation candidates are proposals for a
        human to approve; nothing on this page dispatches an action.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No correlations evaluated"
        emptyDetail="The API responded successfully and no correlation has been evaluated for this tenant."
        caption="An AI brief is withheld entirely when no supporting evidence was retrieved."
      />
    </section>
  );
}
