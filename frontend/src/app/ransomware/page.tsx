import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Ransomware' };

type VictimRow = {
  id: string;
  victim_name?: string | null;
  group_name?: string | null;
  country?: string | null;
  sector?: string | null;
  discovered_at?: string | null;
  needs_review?: boolean | null;
};

const columns: Column<VictimRow>[] = [
  {
    key: 'victim',
    header: 'Victim',
    render: (row) => (
      <>
        <strong>{unknown(row.victim_name)}</strong>
        <br />
        <small>
          {unknown(row.country)} · {unknown(row.sector)}
        </small>
      </>
    ),
  },
  { key: 'group', header: 'Group', render: (row) => <>{unknown(row.group_name)}</> },
  { key: 'discovered', header: 'Discovered', render: (row) => <>{unknown(row.discovered_at)}</> },
  {
    key: 'review',
    header: 'Normalisation',
    render: (row) =>
      row.needs_review ? (
        <StatusChip label="Name not normalised" tone="pending" />
      ) : (
        <StatusChip label="Reviewed" tone="neutral" />
      ),
  },
];

export default async function RansomwarePage() {
  const envelope = await fetchList<VictimRow>('/ransomware/victims');
  return (
    <section className="content">
      <h1>Ransomware intelligence</h1>
      <p className="muted">
        Victims are de-duplicated across leak-site feeds, and every merge stays auditable. Rows whose victim name is
        still a raw URL or status prefix are flagged rather than quietly cleaned up.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        note={noteOf(envelope)}
        emptyTitle="No victim records"
        emptyDetail="The API responded successfully and no leak-site victim has been ingested yet."
        caption="Leak-site claims are attacker assertions, not verified breach confirmations."
      />
    </section>
  );
}
