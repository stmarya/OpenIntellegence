import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Reports' };

type ReportRow = {
  id: string;
  title?: string | null;
  template?: string | null;
  status?: string | null;
  progress?: number | null;
  period_start?: string | null;
  period_end?: string | null;
  created_at?: string | null;
};

const columns: Column<ReportRow>[] = [
  {
    key: 'report',
    header: 'Report',
    render: (row) => (
      <>
        <Link href={`/reports/${row.id}`}>
          <strong>{unknown(row.title)}</strong>
        </Link>
        <br />
        <small>{unknown(row.template)}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status === 'completed' ? (
        <StatusChip label="Completed" tone="approved" />
      ) : row.status === 'failed' ? (
        <StatusChip label="Failed" tone="blocked" />
      ) : (
        <StatusChip label={row.status ?? 'Unknown'} tone={row.status ? 'pending' : 'unknown'} />
      ),
  },
  { key: 'progress', header: 'Progress', render: (row) => <>{row.progress ?? 'Unknown'}</> },
  {
    key: 'period',
    header: 'Period',
    render: (row) => (
      <small>
        {unknown(row.period_start)} to {unknown(row.period_end)}
      </small>
    ),
  },
  { key: 'created', header: 'Requested', render: (row) => <small>{unknown(row.created_at)}</small> },
];

export default async function ReportsPage() {
  const envelope = await fetchList<ReportRow>('/reports');
  return (
    <section className="content">
      <h1>Reports</h1>
      <p className="muted">
        Generation is queued and polled rather than awaited, because a real report takes far longer than any sensible
        HTTP timeout. Facts are gathered by query first, and the narrative is written only around those facts.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No reports requested"
        emptyDetail="The API responded successfully and no report has been requested for this tenant."
        caption="A queued report shows its real progress value, never a simulated one."
      />
    </section>
  );
}
