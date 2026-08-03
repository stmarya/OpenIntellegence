import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Endpoint agent' };

/** Mirrors AgentOut in app/api/schemas.py. */
type Agent = {
  id?: string | null;
  version?: string | null;
  os_family?: string | null;
  status?: string | null;
  asset_id?: string | null;
  cert_expires_at?: string | null;
  last_heartbeat_at?: string | null;
  enrolled_at?: string | null;
};

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

function certificateValue(expiresAt?: string | null) {
  if (!expiresAt) return 'No certificate expiry recorded.';
  const expiry = Date.parse(expiresAt);
  if (Number.isNaN(expiry)) return expiresAt;
  if (expiry <= Date.now()) {
    return `${expiresAt} — already expired. This agent can no longer authenticate a heartbeat.`;
  }
  return expiresAt;
}

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
  const encoded = encodeURIComponent(agentId);

  const [agentOutcome, softwareOutcome] = await Promise.all([
    fetchJson<Agent>(`/agents/${encoded}`),
    fetchJson<AgentSoftwareResponse>(`/agents/${encoded}/software`),
  ]);

  const agent = agentOutcome.status === 'ok' ? agentOutcome.data : null;
  const record = softwareOutcome.status === 'ok' ? softwareOutcome.data : null;
  const software = record?.software ?? [];
  const unmatched = record?.unmatched_count ?? null;

  const fleetFields: Field[] = agent
    ? [
        {
          key: 'status',
          label: 'Reported state',
          value:
            agent.status === 'active' ? (
              <StatusChip label="Active" tone="approved" />
            ) : (
              <StatusChip label={agent.status ?? 'Unknown'} tone="unknown" />
            ),
        },
        { key: 'heartbeat', label: 'Last contact', value: unknown(agent.last_heartbeat_at) },
        { key: 'enrolled', label: 'Enrolled', value: unknown(agent.enrolled_at) },
        { key: 'version', label: 'Agent version', value: unknown(agent.version) },
        { key: 'os', label: 'Platform', value: unknown(agent.os_family) },
        { key: 'asset', label: 'Asset', value: unknown(agent.asset_id) },
        {
          key: 'cert',
          label: 'Certificate expires',
          value: certificateValue(agent.cert_expires_at),
        },
      ]
    : [];

  return (
    <DetailShell
      backHref="/agents"
      backLabel="Back to endpoint agents"
      title={`Agent ${agentId}`}
      intro="This view reads the software this agent last reported. It is a read surface only and offers no way to send a command to the endpoint."
      outcome={softwareOutcome}
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
        agent ? (
          <>
            <FieldTable fields={fleetFields} caption="Read fresh for this agent, not copied from the fleet list." />
            <p className="muted">
              A heartbeat records last contact, not current health. An agent shown as active stopped being verified the
              moment it last checked in, so read the contact time alongside the state rather than trusting the state on
              its own.
            </p>
          </>
        ) : (
          <p className="muted">
            {agentOutcome.status === 'unavailable'
              ? agentOutcome.reason
              : 'This agent could not be read.'}
          </p>
        )
      ) : null}
    </DetailShell>
  );
}
