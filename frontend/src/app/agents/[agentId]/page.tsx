import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Endpoint agent' };

/**
 * Mirrors the dict returned by agent_software in app/api/v1/assets.py.
 *
 * This endpoint does not use the ListResponse envelope: it returns a bare
 * object with the inventory under `software`, and it does not paginate.
 */
type SoftwareItem = {
  name?: string | null;
  version?: string | null;
  vendor?: string | null;
  cpe_uri?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
};

type AgentSoftwareResponse = {
  agent_id?: string | null;
  asset_id?: string | null;
  count?: number | null;
  unmatched_count?: number | null;
  software?: SoftwareItem[];
};

const TABS: TabDefinition[] = [
  { key: 'software', label: 'Reported software' },
  { key: 'fleet', label: 'Fleet metadata' },
];

const columns: Column<SoftwareItem>[] = [
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
  {
    key: 'cpe',
    header: 'CPE identifier',
    render: (row) =>
      row.cpe_uri ? (
        <small>
          <code>{row.cpe_uri}</code>
        </small>
      ) : (
        <StatusChip label="No CPE" tone="unknown" />
      ),
  },
  { key: 'first', header: 'First seen', render: (row) => <small>{row.first_seen ?? 'Not reported'}</small> },
  { key: 'seen', header: 'Last seen', render: (row) => <small>{row.last_seen ?? 'Never reported'}</small> },
];

export default async function AgentDetailPage({
  params,
  searchParams,
}: {
  params: { agentId: string };
  searchParams?: SearchParams;
}) {
  const { agentId } = params;
  const tab = resolveTab(TABS, searchParams?.tab);
  const basePath = `/agents/${encodeURIComponent(agentId)}`;
  const outcome = await fetchJson<AgentSoftwareResponse>(`/agents/${encodeURIComponent(agentId)}/software`);
  const record = outcome.status === 'ok' ? outcome.data : null;
  const software = record?.software ?? [];
  const unmatched = record?.unmatched_count ?? null;

  return (
    <DetailShell
      backHref="/agents"
      backLabel="Back to endpoint agents"
      title={`Agent ${agentId}`}
      intro="This view reads the software this agent last reported. It is a read surface only and offers no way to send a command to the endpoint."
      outcome={outcome}
    >
      <TabNav basePath={basePath} tabs={TABS} active={tab} />

      {tab === 'software' ? (
        <>
          {unmatched != null && unmatched > 0 ? (
            <p className="banner">
              {unmatched} of {record?.count ?? software.length} reported packages carry no CPE identifier. Those packages
              cannot be matched against CVE data at all, so this agent&apos;s exposure count is a floor rather than a
              complete assessment.
            </p>
          ) : null}
          <DataTable
            columns={columns}
            rows={software}
            rowKey={(row) => `${row.name ?? 'unnamed'}@${row.version ?? 'unversioned'}`}
            emptyLabel="This agent has reported no software inventory. That means nothing was reported, not that the endpoint has no software installed."
            caption="An inventory reflects the last successful report. A silent agent keeps showing its last known state, never an empty machine."
          />
          <p className="muted">
            The full inventory is returned in one response; this endpoint does not paginate, so nothing is being withheld
            below the last row.
          </p>
        </>
      ) : null}

      {tab === 'fleet' ? (
        <p className="muted">
          Heartbeat, certificate expiry, and platform details are shown on the agent list, because the API exposes no
          single-agent read endpoint. Copying those values from a list response would present a possibly stale snapshot
          as a current reading, which matters most for exactly the field that tells you whether the agent is still
          alive.
        </p>
      ) : null}
    </DetailShell>
  );
}
