import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Software inventory' };

type AgentRow = {
  id: string;
  asset_id?: string | null;
  os_family?: string | null;
  version?: string | null;
  last_heartbeat_at?: string | null;
};

const columns: Column<AgentRow>[] = [
  { key: 'agent', header: 'Reporting agent', render: (row) => <strong>{row.id}</strong> },
  { key: 'asset', header: 'Asset', render: (row) => <>{unknown(row.asset_id)}</> },
  { key: 'os', header: 'Platform', render: (row) => <>{unknown(row.os_family)}</> },
  {
    key: 'inventory',
    header: 'Inventory freshness',
    render: (row) => <small>{row.last_heartbeat_at ?? 'No inventory received'}</small>,
  },
];

export default async function SoftwareInventoryPage() {
  const envelope = await fetchList<AgentRow>('/agents');
  return (
    <section className="content">
      <h1>Software inventory</h1>
      <p className="muted">
        Installed software is reported per agent and is only as fresh as that agent&apos;s last inventory push. Packages
        without a CPE cannot be matched to a CVE, and the API reports that unmatched count alongside the inventory so
        the exposure figure never looks more complete than it is.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No inventory source"
        emptyDetail="The API responded successfully and no agent is enrolled, so there is no installed-software record to summarise."
        caption="Vendor names taken from public vulnerability feeds are never treated as installed software."
      />
    </section>
  );
}
