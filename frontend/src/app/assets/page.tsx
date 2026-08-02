import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Assets' };

type AssetRow = {
  id: string;
  hostname?: string | null;
  asset_type?: string | null;
  os_family?: string | null;
  os_version?: string | null;
  criticality?: string | null;
  internet_exposed?: boolean | null;
  exposed_cve_count?: number | null;
  last_seen_at?: string | null;
};

const columns: Column<AssetRow>[] = [
  {
    key: 'host',
    header: 'Asset',
    render: (row) => (
      <>
        <strong>{unknown(row.hostname)}</strong>
        <br />
        <small>
          {unknown(row.os_family)} {row.os_version ?? ''}
        </small>
      </>
    ),
  },
  { key: 'criticality', header: 'Criticality', render: (row) => <>{unknown(row.criticality)}</> },
  {
    key: 'exposure',
    header: 'Internet exposure',
    render: (row) =>
      row.internet_exposed === null || row.internet_exposed === undefined ? (
        <StatusChip label="Unknown" tone="unknown" />
      ) : row.internet_exposed ? (
        <StatusChip label="Internet exposed" tone="blocked" />
      ) : (
        <StatusChip label="Not internet exposed" tone="neutral" />
      ),
  },
  {
    key: 'cves',
    header: 'Open CVE exposure',
    render: (row) => <>{row.exposed_cve_count ?? 'Unknown'}</>,
  },
  { key: 'seen', header: 'Last seen', render: (row) => <small>{unknown(row.last_seen_at)}</small> },
];

export default async function AssetsPage() {
  const envelope = await fetchList<AssetRow>('/assets');
  return (
    <section className="content">
      <h1>Assets</h1>
      <p className="muted">
        Assets are the bridge between external intelligence and internal risk. Exposure counts come from recorded
        CVE-to-asset matches, so an asset with no inventory shows unknown rather than zero.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No assets in this tenant"
        emptyDetail="The API responded successfully and no asset has been registered or enrolled yet."
        caption="Ordering follows open exposure count, because a high score on nothing is not urgent."
      />
    </section>
  );
}
