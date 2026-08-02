import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { ResourceTable } from '@/components/ResourceTable';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Endpoint agent' };

type SoftwareRow = {
  id?: string | null;
  name?: string | null;
  vendor?: string | null;
  version?: string | null;
  install_path?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
};

const columns: Column<SoftwareRow>[] = [
  {
    key: 'package',
    header: 'Package',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>{row.vendor ?? 'Vendor not reported'}</small>
      </>
    ),
  },
  { key: 'version', header: 'Version', render: (row) => <>{unknown(row.version)}</> },
  { key: 'path', header: 'Install path', render: (row) => <small>{row.install_path ?? 'Not reported'}</small> },
  { key: 'seen', header: 'Last seen', render: (row) => <small>{row.last_seen_at ?? 'Never reported'}</small> },
];

export default async function AgentDetailPage({ params }: { params: { agentId: string } }) {
  const { agentId } = params;
  const software = await fetchList<SoftwareRow>(`/agents/${agentId}/software`);

  return (
    <DetailShell
      backHref="/agents"
      backLabel="Back to endpoint agents"
      title={`Agent ${agentId}`}
      intro="This view reads the software this agent last reported. It is a read surface only and offers no way to send a command to the endpoint."
      outcome={software}
    >
      <p className="muted">
        Fleet metadata such as heartbeat and certificate expiry is shown on the agent list, because the API exposes no
        single-agent read endpoint yet. Those fields are deliberately not duplicated here from a stale copy.
      </p>

      <h2>Reported software</h2>
      <ResourceTable
        outcome={rowsOf(software)}
        columns={columns}
        rowKey={(row) => String(row.id ?? `${row.name}@${row.version}`)}
        emptyTitle="No software reported"
        emptyDetail="The API responded successfully and this agent has reported no software inventory. That means nothing was reported, not that the endpoint has no software installed."
        caption="An inventory reflects the last successful report. A silent agent keeps showing its last known state, never an empty machine."
      />
    </DetailShell>
  );
}
