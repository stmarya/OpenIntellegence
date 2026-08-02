import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, mapOutcome, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Automation' };

type CapabilityRow = {
  action: string;
  available?: boolean | null;
  delivery_mode?: string | null;
  reason?: string | null;
};

const columns: Column<CapabilityRow>[] = [
  { key: 'action', header: 'Action', render: (row) => <strong>{row.action}</strong> },
  {
    key: 'available',
    header: 'Configured',
    render: (row) =>
      row.available ? (
        <StatusChip label="Configured" tone="approved" />
      ) : (
        <StatusChip label="Not configured" tone="unknown" />
      ),
  },
  {
    key: 'delivery',
    header: 'Delivery mode',
    render: (row) =>
      row.delivery_mode === 'control_plane' ? (
        <StatusChip label="Control plane only" tone="blocked" />
      ) : (
        <>{unknown(row.delivery_mode)}</>
      ),
  },
  { key: 'reason', header: 'Detail', render: (row) => <small>{row.reason ?? 'No detail supplied.'}</small> },
];

export default async function AutomationPage() {
  const outcome = mapOutcome(
    await fetchJson<{ capabilities?: CapabilityRow[] }>('/automation/capabilities'),
    (payload) => payload.capabilities ?? []
  );
  return (
    <section className="content">
      <h1>Automation</h1>
      <p className="muted">
        Capability state is derived from configuration alone. No credential is read and no outbound probe is made to
        determine whether an action is available.
      </p>
      <ResourceTable
        outcome={outcome}
        columns={columns}
        rowKey={(row) => row.action}
        emptyTitle="No automation actions registered"
        emptyDetail="The API responded successfully and no automation action is registered."
        caption="Endpoint command requests are control-plane only and are rejected from playbooks entirely."
      />
    </section>
  );
}
