import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Collections' };

type CollectionRow = {
  id: string;
  name?: string | null;
  description?: string | null;
  purpose?: string | null;
  owner?: string | null;
  member_refs?: string[];
  is_shared?: boolean | null;
  last_curated_at?: string | null;
};

const columns: Column<CollectionRow>[] = [
  {
    key: 'collection',
    header: 'Collection',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>{row.description ?? row.purpose ?? 'No description recorded.'}</small>
      </>
    ),
  },
  { key: 'owner', header: 'Owner', render: (row) => <>{row.owner ?? 'Unassigned'}</> },
  { key: 'members', header: 'Members', render: (row) => <>{row.member_refs?.length ?? 0}</> },
  {
    key: 'sharing',
    header: 'Visibility',
    render: (row) =>
      row.is_shared ? (
        <StatusChip label="Shared with tenant" tone="neutral" />
      ) : (
        <StatusChip label="Private to owner" tone="pending" />
      ),
  },
  { key: 'curated', header: 'Last curated', render: (row) => <small>{row.last_curated_at ?? 'Never'}</small> },
];

export default async function CollectionsPage() {
  const envelope = await fetchList<CollectionRow>('/collections');
  return (
    <section className="content">
      <h1>Collections</h1>
      <p className="muted">
        A collection is curated by a person on purpose. Membership is never inferred from a search result, so a
        collection that has not been touched in months shows its staleness rather than implying ongoing review.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No collections"
        emptyDetail="The API responded successfully and no collection has been created for this tenant."
      />
    </section>
  );
}
