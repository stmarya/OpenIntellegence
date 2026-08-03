import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
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
  coverage_note?: string | null;
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
        <>
          <small>{row.covering_sources.join(', ')}</small>
          {row.coverage_note ? (
            <>
              <br />
              <small>{row.coverage_note}</small>
            </>
          ) : null}
        </>
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

export default async function IntelligenceRequirementsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<RequirementRow>(withPageQuery('/intelligence-requirements', state));
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
        page={pageMetaOf(envelope)}
        basePath="/intelligence-requirements"
        emptyTitle="No requirements defined"
        emptyDetail="The API responded successfully and no intelligence requirement has been defined for this tenant."
        caption="Ordering follows requirement code so the list reads the same way every time."
      />
      <p className="muted">
        A mapped source means someone asserted the source is relevant. It does not confirm the source is currently
        collecting, which is reported on the connector surface.
      </p>
    </section>
  );
}
