import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Software inventory' };

/** Mirrors AgentOut in app/api/schemas.py. */
type AgentRow = {
  id: string;
  asset_id?: string | null;
  os_family?: string | null;
  version?: string | null;
  status?: string | null;
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
    key: 'status',
    header: 'Agent state',
    render: (row) =>
      row.status === 'active' ? (
        <StatusChip label="Active" tone="approved" />
      ) : (
        <StatusChip label={row.status ?? 'Unknown'} tone="unknown" />
      ),
  },
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
        CPE matching does run: each heartbeat carrying an inventory recomputes that asset&apos;s exposure, and every
        resulting row records the join that produced it, so a false positive can be traced to its rule. Coverage is
        still partial, because a package reported without a CPE identifier cannot be matched at all and is counted as
        unmatched on the agent page rather than passed over silently.
      </p>
      <p className="muted">
        No exposure figure is derived on this page, since an agent count and a vulnerability count answer different
        questions. Asset-level exposure, including the matching basis for each CVE, is on the{' '}
        <Link href="/assets">asset surface</Link>.
      </p>
    </section>
  );
}
