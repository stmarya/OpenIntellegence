import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Threat actors' };

type ActorRow = {
  id: string;
  name?: string | null;
  slug?: string | null;
  description?: string | null;
  victim_count?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
};

const columns: Column<ActorRow>[] = [
  {
    key: 'actor',
    header: 'Actor',
    render: (row) => (
      <>
        <Link href={`/threat-actors/${encodeURIComponent(row.id)}`}>
          <strong>{unknown(row.name)}</strong>
        </Link>
        <br />
        <small>{row.description ?? 'No description supplied by the source.'}</small>
      </>
    ),
  },
  { key: 'victims', header: 'Observed victims', render: (row) => <>{row.victim_count ?? 'Unknown'}</> },
  { key: 'first', header: 'First seen', render: (row) => <>{unknown(row.first_seen)}</> },
  { key: 'last', header: 'Last seen', render: (row) => <>{unknown(row.last_seen)}</> },
];

export default async function ThreatActorsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<ActorRow>(withPageQuery('/actors', state));
  return (
    <section className="content">
      <h1>Threat actors</h1>
      <p className="muted">
        Victim counts reflect what the ingested sources observed, not the true scale of an actor&apos;s activity. The
        console does not infer attribution on its own.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        page={pageMetaOf(envelope)}
        basePath="/threat-actors"
        emptyTitle="No actor records"
        emptyDetail="The API responded successfully and no threat actor has been ingested yet."
        caption="Ordering follows observed victim count from the ingested feeds."
      />
    </section>
  );
}
