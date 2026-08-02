import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { RiskBadge } from '@/components/RiskBadge';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
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
        <Link href={`/correlations/${encodeURIComponent(row.id)}`}>
          <strong>{unknown(row.title)}</strong>
        </Link>
        <br />
        <small>
          {unknown(row.primary_entity_type)} \u00b7 {unknown(row.primary_entity_id)}
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
    render: (row) =>
      row.automation_candidates ? <>{row.automation_candidates.length} proposed</> : <>Not reported</>,
  },
  { key: 'evaluated', header: 'Evaluated', render: (row) => <small>{unknown(row.evaluated_at)}</small> },
];

export default async function CorrelationsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<CorrelationRow>(withPageQuery('/correlations', state));
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
        page={pageMetaOf(envelope)}
        basePath="/correlations"
        emptyTitle="No correlations evaluated"
        emptyDetail="The API responded successfully and no correlation has been evaluated for this tenant."
        caption="An AI brief is withheld entirely when no supporting evidence was retrieved."
      />
      <p className="muted">
        A correlation links records that share an entity. It is a lead worth checking, not a confirmed incident, and the
        factor breakdown on each correlation shows exactly why the score is what it is.
      </p>
    </section>
  );
}
