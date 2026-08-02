import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Ransomware groups' };

type GroupRow = {
  group_name: string;
  victim_count?: number | null;
  country_count?: number | null;
  earliest_victim_at?: string | null;
  latest_victim_at?: string | null;
};

const columns: Column<GroupRow>[] = [
  { key: 'group', header: 'Group', render: (row) => <strong>{unknown(row.group_name)}</strong> },
  { key: 'victims', header: 'Victims ingested', render: (row) => <>{row.victim_count ?? 'Unknown'}</> },
  { key: 'countries', header: 'Countries observed', render: (row) => <>{row.country_count ?? 'Unknown'}</> },
  {
    key: 'window',
    header: 'First / latest claim',
    render: (row) => (
      <>
        {unknown(row.earliest_victim_at)}
        <br />
        <small>{unknown(row.latest_victim_at)}</small>
      </>
    ),
  },
];

export default async function RansomwareGroupsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<GroupRow>(withPageQuery('/ransomware/groups', state));
  return (
    <section className="content">
      <h1>Ransomware groups</h1>
      <nav aria-label="Ransomware views" className="muted">
        <Link href="/ransomware">Victims</Link>
        {' \u00b7 '}
        <strong>Groups</strong>
      </nav>
      <p className="muted">
        Groups are aggregated from ingested leak-site victims by the name each post carried. A group absent from this
        list means no victim was ingested under that name, which is not evidence the group is dormant.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.group_name}
        note={noteOf(envelope)}
        page={pageMetaOf(envelope)}
        basePath="/ransomware/groups"
        emptyTitle="No groups aggregated"
        emptyDetail="The API responded successfully and no leak-site victim carries a group name yet."
        caption="Counts describe ingested claims, not confirmed intrusions."
      />
    </section>
  );
}
