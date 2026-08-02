import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Developer portal' };

type ApiKeyRow = {
  id: string;
  name?: string | null;
  masked_key?: string | null;
  scopes?: string[];
  status?: string | null;
  rate_limit_per_hour?: number | null;
  created_at?: string | null;
  expires_at?: string | null;
  revoked_reason?: string | null;
};

const columns: Column<ApiKeyRow>[] = [
  {
    key: 'key',
    header: 'Key',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>{unknown(row.masked_key)}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status === 'revoked' ? (
        <StatusChip label="Revoked" tone="blocked" />
      ) : (
        <StatusChip label={row.status ?? 'Unknown'} tone={row.status ? 'approved' : 'unknown'} />
      ),
  },
  {
    key: 'scopes',
    header: 'Scopes',
    render: (row) => <small>{row.scopes?.length ? row.scopes.join(', ') : 'None granted'}</small>,
  },
  {
    key: 'limit',
    header: 'Rate limit',
    render: (row) => <>{row.rate_limit_per_hour ? `${row.rate_limit_per_hour} / hour` : 'Not set'}</>,
  },
  {
    key: 'lifecycle',
    header: 'Created / expires',
    render: (row) => (
      <small>
        {unknown(row.created_at)}
        <br />
        {row.expires_at ?? 'No expiry'}
      </small>
    ),
  },
  {
    key: 'revocation',
    header: 'Revocation reason',
    render: (row) => <small>{row.revoked_reason ?? 'Not revoked'}</small>,
  },
];

export default async function DeveloperPortalPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<ApiKeyRow>(withPageQuery('/api-keys', state));
  return (
    <section className="content">
      <h1>Developer portal and API keys</h1>
      <p className="muted">
        Only the masked form of a key is ever shown here. The secret is displayed once at creation and stored hashed, so
        the platform genuinely cannot show it again. Revoked keys stay listed with their reason, because deleting them
        would erase the record of what once had access.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        page={pageMetaOf(envelope)}
        basePath="/developer"
        emptyTitle="No API keys issued"
        emptyDetail="The API responded successfully and no key has been issued for this tenant."
        caption="Key material never passes through browser state."
      />
      <p className="muted">
        Issuing and revoking keys are write actions and are not offered here. The console remains read-only, and a
        control that cannot complete would misrepresent what this session can do.
      </p>
    </section>
  );
}
