import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Connectors' };

type FeedRow = {
  source?: string | null;
  status?: string | null;
  last_run_at?: string | null;
  last_success_at?: string | null;
  records_ingested?: number | null;
  records_quarantined?: number | null;
  error_message?: string | null;
};

const columns: Column<FeedRow>[] = [
  { key: 'source', header: 'Connector', render: (row) => <strong>{unknown(row.source)}</strong> },
  {
    key: 'status',
    header: 'Last run outcome',
    render: (row) =>
      row.status === 'never_run' ? (
        <StatusChip label="Never run" tone="unknown" />
      ) : row.status === 'failed' ? (
        <StatusChip label="Failed" tone="blocked" />
      ) : (
        <StatusChip label={row.status ?? 'Unknown'} tone={row.status ? 'neutral' : 'unknown'} />
      ),
  },
  {
    key: 'runs',
    header: 'Last run / last success',
    render: (row) => (
      <>
        {unknown(row.last_run_at)}
        <br />
        <small>{row.last_success_at ?? 'No successful run recorded'}</small>
      </>
    ),
  },
  {
    key: 'volume',
    header: 'Ingested / quarantined',
    render: (row) => (
      <>
        {row.records_ingested ?? 'Unknown'} / {row.records_quarantined ?? 'Unknown'}
      </>
    ),
  },
  { key: 'error', header: 'Last error', render: (row) => <small>{row.error_message ?? 'None recorded'}</small> },
];

/**
 * Ingestion connector runs.
 *
 * This surface owns connector state outright. System health previously read
 * the same table, which made one subsystem look like two independent
 * confirmations of the same fact.
 */
export default async function ConnectorsPage() {
  const outcome = await fetchJson<FeedRow[]>('/feeds');
  return (
    <section className="content">
      <h1>Connectors</h1>
      <p className="muted">
        A connector that has never run is reported as such, because a silent feed and a feed with genuinely no data look
        identical until you say which one it is. This page describes ingestion runs only; platform component state lives
        on <Link href="/system-health">system health</Link>.
      </p>
      <ResourceTable
        outcome={outcome}
        columns={columns}
        rowKey={(row) => String(row.source)}
        emptyTitle="No connectors registered"
        emptyDetail="The API responded successfully and no connector is registered in the ingestion registry."
        caption="Quarantined records are kept and replayable, never silently discarded."
      />
      <p className="muted">
        A successful run means records were accepted, not that the upstream source was complete or correct. Rejected
        records are counted here and itemised under <Link href="/data-quality">data quality</Link>.
      </p>
    </section>
  );
}
