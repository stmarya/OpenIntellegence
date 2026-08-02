import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'System health' };

type FeedRow = {
  source?: string | null;
  status?: string | null;
  last_success_at?: string | null;
  error_message?: string | null;
};

const columns: Column<FeedRow>[] = [
  { key: 'component', header: 'Ingestion component', render: (row) => <strong>{unknown(row.source)}</strong> },
  {
    key: 'status',
    header: 'Reported state',
    render: (row) =>
      row.status ? (
        <StatusChip label={row.status} tone={row.status === 'failed' ? 'blocked' : 'neutral'} />
      ) : (
        <StatusChip label="Unknown" tone="unknown" />
      ),
  },
  { key: 'success', header: 'Last success', render: (row) => <>{row.last_success_at ?? 'Never'}</> },
  { key: 'error', header: 'Last error', render: (row) => <small>{row.error_message ?? 'None recorded'}</small> },
];

export default async function SystemHealthPage() {
  const outcome = await fetchJson<FeedRow[]>('/feeds');
  return (
    <section className="content">
      <h1>System health</h1>
      <p className="muted">
        Component state is read from the platform&apos;s own reporting. An unreachable component is shown as unknown,
        never as healthy, so a monitoring gap is not mistaken for a green system.
      </p>
      <ResourceTable
        outcome={outcome}
        columns={columns}
        rowKey={(row) => String(row.source)}
        emptyTitle="No component reported"
        emptyDetail="The API responded successfully and no ingestion component is registered."
        caption="Database, queue, and model-provider readiness join this table once their probes are exposed."
      />
    </section>
  );
}
