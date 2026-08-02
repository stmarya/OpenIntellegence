import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Endpoint intents' };

type IntentRow = {
  id: string;
  agent_id?: string | null;
  intent_type?: string | null;
  state?: string | null;
  effective_state?: string | null;
  requested_by?: string | null;
  expires_at?: string | null;
  delivery_state?: string | null;
};

const columns: Column<IntentRow>[] = [
  {
    key: 'intent',
    header: 'Intent',
    render: (row) => (
      <>
        <Link href={`/endpoint-intents/${encodeURIComponent(row.id)}`}>
          <strong>{unknown(row.intent_type)}</strong>
        </Link>
        <br />
        <small>agent {unknown(row.agent_id)}</small>
      </>
    ),
  },
  {
    key: 'state',
    header: 'Approval state',
    render: (row) => {
      const state = row.effective_state ?? row.state;
      if (state === 'approved') return <StatusChip label="Approved" tone="approved" />;
      if (state === 'pending') return <StatusChip label="Awaiting second approver" tone="pending" />;
      if (!state) return <StatusChip label="Unknown" tone="unknown" />;
      return <StatusChip label={state} tone="blocked" />;
    },
  },
  {
    key: 'delivery',
    header: 'Delivery',
    render: (row) => (
      <StatusChip
        label={row.delivery_state === 'not_dispatched' ? 'Not dispatched' : unknown(row.delivery_state)}
        tone="blocked"
      />
    ),
  },
  { key: 'requester', header: 'Requested by', render: (row) => <small>{unknown(row.requested_by)}</small> },
  { key: 'expires', header: 'Expires', render: (row) => <>{unknown(row.expires_at)}</> },
];

export default async function EndpointIntentsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<IntentRow>(withPageQuery('/endpoint-intents', state));
  return (
    <section className="content">
      <h1>Endpoint intents</h1>
      <p className="muted">
        This is an approval ledger, not a command channel. The platform records what someone wanted to do to an endpoint
        and who agreed to it, and stops there. Two distinct approvers are required and the requester cannot be one of
        them.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        page={pageMetaOf(envelope)}
        basePath="/endpoint-intents"
        emptyTitle="No intent requested"
        emptyDetail="The API responded successfully and no endpoint intent has been raised for this tenant."
        caption="An intent past its expiry window is reported as expired, never as still awaiting approval."
      />
      <p className="muted">
        Approving here is not offered: approval is a write action, and the record of who approved what has to be created
        by an authenticated actor rather than by a read-only console.
      </p>
    </section>
  );
}
