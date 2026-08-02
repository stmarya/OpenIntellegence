import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Cases' };

type CaseRow = {
  id: string;
  title?: string | null;
  case_type?: string | null;
  status?: string | null;
  priority?: string | null;
  owner?: string | null;
  sla_due_at?: string | null;
  closure_reason?: string | null;
};

const columns: Column<CaseRow>[] = [
  {
    key: 'case',
    header: 'Case',
    render: (row) => (
      <>
        <strong>
          <Link href={`/cases/${encodeURIComponent(row.id)}`}>{unknown(row.title)}</Link>
        </strong>
        <br />
        <small>{unknown(row.case_type)}</small>
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
  { key: 'owner', header: 'Owner', render: (row) => <>{row.owner ?? 'Unassigned'}</> },
  { key: 'sla', header: 'SLA due', render: (row) => <small>{row.sla_due_at ?? 'No SLA set'}</small> },
  {
    key: 'closure',
    header: 'Closure reason',
    render: (row) => <small>{row.closure_reason ?? 'Not closed'}</small>,
  },
];

export default async function CasesPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<CaseRow>(withPageQuery('/cases', state));
  return (
    <section className="content">
      <h1>Cases</h1>
      <p className="muted">
        A case carries ownership, SLA, tasks, and a closure reason. It is deliberately separate from an investigation,
        which holds the hypothesis and the evidence canvas.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        page={pageMetaOf(envelope)}
        basePath="/cases"
        emptyTitle="No cases open"
        emptyDetail="The API responded successfully and no case exists for this tenant."
        caption="Ordering puts the nearest SLA deadline first."
      />
      <p className="muted">
        Closed cases remain listed with their closure reason. Hiding them would make the queue look tidier than the
        history actually was.
      </p>
    </section>
  );
}
