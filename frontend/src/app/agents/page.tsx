import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Endpoint agents' };

type AgentRow = {
  id: string;
  asset_id?: string | null;
  os_family?: string | null;
  version?: string | null;
  status?: string | null;
  enrolled_at?: string | null;
  last_heartbeat_at?: string | null;
  cert_expires_at?: string | null;
};

const columns: Column<AgentRow>[] = [
  {
    key: 'agent',
    header: 'Agent',
    render: (row) => (
      <>
        <strong>
          <Link href={`/agents/${row.id}`}>{row.id}</Link>
        </strong>
        <br />
        <small>
          {unknown(row.os_family)} · agent {unknown(row.version)}
        </small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? (
        <StatusChip label={row.status} tone={row.status === 'active' ? 'approved' : 'blocked'} />
      ) : (
        <StatusChip label="Unknown" tone="unknown" />
      ),
  },
  {
    key: 'heartbeat',
    header: 'Last heartbeat',
    render: (row) => <>{row.last_heartbeat_at ?? 'Never reported'}</>,
  },
  { key: 'cert', header: 'Certificate expires', render: (row) => <small>{unknown(row.cert_expires_at)}</small> },
];

export default async function EndpointAgentsPage() {
  const envelope = await fetchList<AgentRow>('/agents');
  return (
    <section className="content">
      <h1>Endpoint agents</h1>
      <p className="muted">
        An agent that stopped reporting stays in this list. Silence is the condition you most need to see, so it is
        surfaced as stale or never reported rather than hidden.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No agent enrolled"
        emptyDetail="The API responded successfully and no endpoint agent has completed enrollment for this tenant."
        caption="This surface reads fleet state only. It cannot send a command to an endpoint."
      />
    </section>
  );
}
