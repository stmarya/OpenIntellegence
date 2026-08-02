import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Intelligence requirements' };

type RequirementRow = {
  id: string;
  code?: string | null;
  title?: string | null;
  priority?: string | null;
  status?: string | null;
  owner?: string | null;
  covering_sources?: string[];
  review_due_at?: string | null;
};

const columns: Column<RequirementRow>[] = [
  {
    key: 'requirement',
    header: 'Requirement',
    render: (row) => (
      <>
        <strong>
          {unknown(row.code)} — {unknown(row.title)}
        </strong>
        <br />
        <small>Owner: {row.owner ?? 'Unassigned'}</small>
      </>
    ),
  },
  { key: 'priority', header: 'Priority', render: (row) => <>{unknown(row.priority)}</> },
  {
    key: 'coverage',
    header: 'Source coverage',
    render: (row) =>
      row.covering_sources?.length ? (
        <small>{row.covering_sources.join(', ')}</small>
      ) : (
        <StatusChip label="No source mapped" tone="unknown" />
      ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? <StatusChip label={row.status} tone="neutral" /> : <StatusChip label="Unknown" tone="unknown" />,
  },
  { key: 'review', header: 'Review due', render: (row) => <small>{row.review_due_at ?? 'Not scheduled'}</small> },
];

export default async function IntelligenceRequirementsPage() {
  const envelope = await fetchList<RequirementRow>('/intelligence-requirements');
  return (
    <section className="content">
      <h1>Intelligence requirements</h1>
      <p className="muted">
        Requirements are what the programme is actually being asked to answer. Coverage is recorded deliberately, never
        inferred from collection volume, so a requirement with no mapped source reads as uncovered.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No requirements defined"
        emptyDetail="The API responded successfully and no intelligence requirement has been defined for this tenant."
        caption="Ordering follows requirement code so the list reads the same way every time."
      />
    </section>
  );
}
