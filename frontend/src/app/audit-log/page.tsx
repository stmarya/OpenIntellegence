import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Audit log' };

type AuditRow = {
  id: string;
  source?: string | null;
  subject?: string | null;
  subject_id?: string | null;
  actor?: string | null;
  event_type?: string | null;
  detail?: Record<string, unknown> | null;
  event_at?: string | null;
};

const columns: Column<AuditRow>[] = [
  {
    key: 'event',
    header: 'Event',
    render: (row) => (
      <>
        <strong>{unknown(row.event_type)}</strong>
        <br />
        <small>{unknown(row.source)}</small>
      </>
    ),
  },
  {
    key: 'subject',
    header: 'Subject',
    render: (row) => (
      <>
        {unknown(row.subject)}
        <br />
        <small>{unknown(row.subject_id)}</small>
      </>
    ),
  },
  { key: 'actor', header: 'Actor', render: (row) => <>{unknown(row.actor)}</> },
  {
    key: 'detail',
    header: 'Detail',
    render: (row) => (
      <small>{row.detail && Object.keys(row.detail).length > 0 ? JSON.stringify(row.detail) : 'None recorded'}</small>
    ),
  },
  { key: 'at', header: 'Recorded at', render: (row) => <>{unknown(row.event_at)}</> },
];

export default async function AuditLogPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<AuditRow>(withPageQuery('/audit-log', state));
  return (
    <section className="content">
      <h1>Audit log</h1>
      <p className="muted">
        These records are append-only. Coverage currently spans the subsystems that persist audit rows, and the note
        below states which, so a quiet log is never mistaken for a quiet platform.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        note={noteOf(envelope)}
        page={pageMetaOf(envelope)}
        basePath="/audit-log"
        emptyTitle="No audit events recorded"
        emptyDetail="The API responded successfully and no auditable event has been recorded for this tenant yet."
        caption="Most recent event first."
      />
    </section>
  );
}
