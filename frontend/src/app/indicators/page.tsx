import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Indicators' };

type IndicatorRow = {
  id: string;
  indicator_type?: string | null;
  value?: string | null;
  verdict?: string | null;
  confidence?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
  source?: string | null;
};

const columns: Column<IndicatorRow>[] = [
  {
    key: 'indicator',
    header: 'Indicator',
    render: (row) => (
      <>
        <Link href={`/indicators/${encodeURIComponent(row.id)}`}>
          <strong>{unknown(row.value)}</strong>
        </Link>
        <br />
        <small>{unknown(row.indicator_type)}</small>
      </>
    ),
  },
  {
    key: 'verdict',
    header: 'Verdict',
    render: (row) =>
      row.verdict ? (
        <StatusChip label={row.verdict} tone={row.verdict === 'malicious' ? 'blocked' : 'neutral'} />
      ) : (
        <StatusChip label="Not enriched" tone="unknown" />
      ),
  },
  { key: 'confidence', header: 'Confidence', render: (row) => <>{unknown(row.confidence)}</> },
  {
    key: 'seen',
    header: 'First / last seen',
    render: (row) => (
      <>
        {unknown(row.first_seen)}
        <br />
        <small>{unknown(row.last_seen)}</small>
      </>
    ),
  },
  { key: 'source', header: 'Source', render: (row) => <small>{unknown(row.source)}</small> },
];

export default async function IndicatorsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams, 100);
  const envelope = await fetchList<IndicatorRow>(withPageQuery('/iocs', state));
  return (
    <section className="content">
      <h1>Indicators and observables</h1>
      <p className="muted">
        An indicator with no verdict is reported as not enriched. It is never folded into a clean verdict, because that
        would state an assurance the platform has not earned.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        note={noteOf(envelope)}
        page={pageMetaOf(envelope)}
        basePath="/indicators"
        emptyTitle="No indicators recorded"
        emptyDetail="The API responded successfully and this tenant currently holds no indicator records."
        caption="Enrichment state is shown per indicator so partial coverage stays visible."
      />
    </section>
  );
}
