import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Detection content' };

type DetectionRow = {
  id: string;
  name?: string | null;
  content_format?: string | null;
  external_id?: string | null;
  severity?: string | null;
  status?: string | null;
  attack_techniques?: string[];
  version?: string | null;
  last_validated_at?: string | null;
};

const columns: Column<DetectionRow>[] = [
  {
    key: 'content',
    header: 'Detection',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>
          {unknown(row.content_format)} · {row.external_id ?? 'no external id'}
        </small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Lifecycle',
    render: (row) =>
      row.status === 'production' ? (
        <StatusChip label="Production" tone="approved" />
      ) : row.status === 'retired' ? (
        <StatusChip label="Retired" tone="blocked" />
      ) : (
        <StatusChip label={row.status ?? 'Unknown'} tone={row.status ? 'pending' : 'unknown'} />
      ),
  },
  { key: 'severity', header: 'Severity', render: (row) => <>{unknown(row.severity)}</> },
  {
    key: 'techniques',
    header: 'ATT&CK techniques',
    render: (row) => <small>{row.attack_techniques?.length ? row.attack_techniques.join(', ') : 'None mapped'}</small>,
  },
  {
    key: 'validated',
    header: 'Last validated',
    render: (row) => <>{row.last_validated_at ?? 'Never validated'}</>,
  },
];

export default async function DetectionContentPage() {
  const envelope = await fetchList<DetectionRow>('/detection-content');
  return (
    <section className="content">
      <h1>Detection content</h1>
      <p className="muted">
        Detection rules are tracked as intelligence product with an explicit lifecycle. Content that has never been
        validated says so plainly, because an unvalidated rule sitting in production is exactly the thing you need to
        find.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No detection content"
        emptyDetail="The API responded successfully and no detection content is registered for this tenant."
        caption="A technique with no rule mapped to it is uncovered, and this table does not hide that."
      />
    </section>
  );
}
