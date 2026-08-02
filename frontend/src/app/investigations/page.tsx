import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Investigations' };

type InvestigationRow = {
  id: string;
  title?: string | null;
  hypothesis?: string | null;
  status?: string | null;
  priority?: string | null;
  confidence?: number | null;
  owner?: string | null;
  opened_at?: string | null;
};

const columns: Column<InvestigationRow>[] = [
  {
    key: 'investigation',
    header: 'Investigation',
    render: (row) => (
      <>
        <strong>
          <Link href={`/investigations/${row.id}`}>{unknown(row.title)}</Link>
        </strong>
        <br />
        <small>{row.hypothesis ?? 'No hypothesis recorded.'}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? <StatusChip label={row.status} tone="neutral" /> : <StatusChip label="Unknown" tone="unknown" />,
  },
  { key: 'priority', header: 'Priority', render: (row) => <>{unknown(row.priority)}</> },
  {
    key: 'confidence',
    header: 'Analyst confidence',
    render: (row) => <>{row.confidence ?? 'Not stated'}</>,
  },
  { key: 'opened', header: 'Opened', render: (row) => <small>{unknown(row.opened_at)}</small> },
];

export default async function InvestigationsPage() {
  const envelope = await fetchList<InvestigationRow>('/investigations');
  return (
    <section className="content">
      <h1>Investigations</h1>
      <p className="muted">
        Confidence stays an analyst judgement. An investigation with no stated confidence is shown as not stated rather
        than assigned a default the analyst never made.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No investigations open"
        emptyDetail="The API responded successfully and no investigation exists for this tenant."
      />
    </section>
  );
}
