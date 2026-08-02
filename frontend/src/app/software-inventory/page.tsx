import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
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
  {
    key: 'agent',
    header: 'Reporting agent',
    render: (row) => <Link href={`/agents/${encodeURIComponent(row.id)}`}>{row.id}</Link>,
  },
  { key: 'asset', header: 'Asset', render: (row) => <>{unknown(row.asset_id)}</> },
  { key: 'os', header: 'Platform', render: (row) => <>{unknown(row.os_family)}</> },
  { key: 'version', header: 'Agent version', render: (row) => <>{unknown(row.version)}</> },
  {
    key: 'inventory',
    header: 'Last contact',
    render: (row) =>
      row.last_heartbeat_at ? (
        <small>{row.last_heartbeat_at}</small>
      ) : (
        <StatusChip label="No inventory received" tone="unknown" />
      ),
  },
];

/**
 * Software inventory.
 *
 * The platform exposes installed software per agent, not as one queryable
 * collection. This page therefore lists the reporting agents and says so
 * plainly, rather than implying a consolidated software table exists.
 */
export default async function SoftwareInventoryPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<AgentRow>(withPageQuery('/agents', state));
  return (
    <section className="content">
      <h1>Software inventory</h1>
      <p className="muted">
        Installed software is reported per agent and is only as fresh as that agent&apos;s last inventory push. This page
        lists the agents that can report it; open an agent to read the packages it last sent. An agent with no inventory
        means nothing was received, never that nothing is installed.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        page={pageMetaOf(envelope)}
        basePath="/software-inventory"
        emptyTitle="No inventory source"
        emptyDetail="The API responded successfully and no agent is enrolled, so there is no installed-software record to summarise."
        caption="Vendor names taken from public vulnerability feeds are never treated as installed software."
      />
      <p className="muted">
        CPE matching between installed packages and CVEs is not performed. No endpoint reports a match state, so no
        exposure figure is derived here; asset-level exposure is on the <Link href="/assets">asset surface</Link>.
      </p>
    </section>
  );
}
