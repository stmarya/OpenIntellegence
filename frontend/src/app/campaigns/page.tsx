import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Campaigns' };

type CampaignRow = {
  id: string;
  name?: string | null;
  status?: string | null;
  confidence?: number | null;
  actor_names?: string[];
  targeted_sectors?: string[];
  attack_techniques?: string[];
  last_seen?: string | null;
};

const columns: Column<CampaignRow>[] = [
  {
    key: 'campaign',
    header: 'Campaign',
    render: (row) => (
      <>
        <Link href={`/campaigns/${row.id}`}>
          <strong>{unknown(row.name)}</strong>
        </Link>
        <br />
        <small>{row.actor_names?.length ? row.actor_names.join(', ') : 'No attributed actor'}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? <StatusChip label={row.status} tone="neutral" /> : <StatusChip label="Unknown" tone="unknown" />,
  },
  {
    key: 'confidence',
    header: 'Confidence',
    render: (row) => <>{row.confidence ?? 'Not stated'}</>,
  },
  {
    key: 'targets',
    header: 'Targeting',
    render: (row) => <small>{row.targeted_sectors?.length ? row.targeted_sectors.join(', ') : 'Unknown'}</small>,
  },
  { key: 'last', header: 'Last seen', render: (row) => <>{unknown(row.last_seen)}</> },
];

export default async function CampaignsPage() {
  const envelope = await fetchList<CampaignRow>('/campaigns');
  return (
    <section className="content">
      <h1>Campaigns</h1>
      <p className="muted">
        Confidence is shown exactly as the source recorded it. A campaign with no stated confidence reads &quot;Not
        stated&quot; instead of receiving a default number the analyst never assigned.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        emptyTitle="No campaign records"
        emptyDetail="The API responded successfully and no campaign has been created or ingested yet."
      />
    </section>
  );
}
