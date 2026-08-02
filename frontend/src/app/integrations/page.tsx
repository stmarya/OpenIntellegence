import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { ErrorState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, mapOutcome, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Integrations' };

type CapabilityRow = {
  action: string;
  available?: boolean | null;
  delivery_mode?: string | null;
  reason?: string | null;
};

type SettingsPayload = {
  policy?: {
    endpoint_command_delivery?: string | null;
    non_replayable_actions?: string[];
    allowed_endpoint_intents?: string[];
  } | null;
};

const columns: Column<CapabilityRow>[] = [
  { key: 'action', header: 'Outbound action', render: (row) => <strong>{row.action}</strong> },
  {
    key: 'configured',
    header: 'Configuration',
    render: (row) =>
      row.available ? (
        <StatusChip label="Configured" tone="approved" />
      ) : (
        <StatusChip label="Not configured" tone="unknown" />
      ),
  },
  {
    key: 'delivery',
    header: 'Delivery',
    render: (row) =>
      row.delivery_mode === 'control_plane' ? (
        <StatusChip label="Recorded, never delivered" tone="blocked" />
      ) : (
        <>{unknown(row.delivery_mode)}</>
      ),
  },
  { key: 'reason', header: 'Detail', render: (row) => <small>{row.reason ?? 'No detail supplied.'}</small> },
];

export default async function IntegrationsPage() {
  const [capabilities, settings] = await Promise.all([
    fetchJson<{ capabilities?: CapabilityRow[] }>('/automation/capabilities'),
    fetchJson<SettingsPayload>('/settings'),
  ]);

  const rows = mapOutcome(capabilities, (payload) => payload.capabilities ?? []);
  const policy = settings.status === 'ok' ? settings.data.policy ?? null : null;

  return (
    <section className="content">
      <h1>Integrations</h1>
      <p className="muted">
        This is the register of every boundary the platform has with something outside itself. It does not re-fetch
        the health of each inbound feed, because that surface already owns those numbers and two pages reporting the
        same thing eventually disagree.
      </p>

      <h2>Inbound intelligence</h2>
      <p className="muted">
        Threat intelligence enters through registered ingestion connectors. Their per-connector state, including
        connectors that have never executed, is on <Link href="/connectors">connectors</Link>. Rejected records and
        run history are on the <Link href="/import">import workbench</Link>, and the resulting defects are triaged
        on <Link href="/data-quality">data quality</Link>. There is no way to add a connector from the console; the
        registry is defined in code.
      </p>

      <h2>Outbound delivery</h2>
      <ResourceTable
        outcome={rows}
        columns={columns}
        rowKey={(row) => row.action}
        emptyTitle="No outbound integrations registered"
        emptyDetail="The API responded successfully and no outbound action is registered."
        caption="Actions the platform can take against a third-party system"
      />
      <p className="muted">
        Configured means a credential or endpoint is present in configuration. Nothing here was probed, so a row
        marked configured is not a statement that the destination is reachable or that the credential still works.
        Playbook-level state for the same actions is on <Link href="/automation">automation</Link>.
      </p>

      <h2>Endpoint control channel</h2>
      <p className="muted">
        {policy?.endpoint_command_delivery
          ? `Endpoint command delivery is reported as ${policy.endpoint_command_delivery}.`
          : 'The policy surface did not report an endpoint command delivery mode.'}{' '}
        Requests to act on an endpoint are recorded as intents and require two distinct approvers, and the requester
        may not approve their own. No transport exists that would carry an approved intent to an agent, so an
        approved isolation request changes a record and nothing on the machine. Review them on{' '}
        <Link href="/endpoint-intents">endpoint intents</Link>.
      </p>
      {policy?.allowed_endpoint_intents && policy.allowed_endpoint_intents.length > 0 ? (
        <ul>
          {policy.allowed_endpoint_intents.map((intent) => (
            <li key={intent}>
              <code>{intent}</code>
            </li>
          ))}
        </ul>
      ) : null}

      <h2>Programmatic access</h2>
      <p className="muted">
        External systems authenticate with scoped API keys rather than a per-integration credential. Keys are issued
        and revoked on the <Link href="/developer">developer portal</Link>, and every principal holding access is
        listed on <Link href="/access">access and roles</Link>.
      </p>

      {settings.status !== 'ok' ? (
        <ErrorState title="Policy detail unavailable" detail={settings.reason} />
      ) : null}
    </section>
  );
}
