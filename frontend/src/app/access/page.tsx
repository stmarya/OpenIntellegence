import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { ErrorState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchJson, fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Access and roles' };

type PrincipalRow = {
  id: string;
  name?: string | null;
  masked_key?: string | null;
  scopes?: string[];
  status?: string | null;
  rate_limit_per_hour?: number | null;
  created_by?: string | null;
  created_at?: string | null;
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  revoked_reason?: string | null;
};

type ScopeRow = {
  scope: string;
  description?: string | null;
  grantable?: boolean | null;
  held_by_caller?: boolean | null;
};

type ScopePayload = {
  scopes?: ScopeRow[];
  role_model?: { named_roles?: string | null; detail?: string | null } | null;
};

function statusTone(status: string | null | undefined) {
  if (status === 'revoked') return 'blocked' as const;
  if (status === 'expiring') return 'pending' as const;
  if (status === 'active') return 'approved' as const;
  return 'unknown' as const;
}

const principalColumns: Column<PrincipalRow>[] = [
  {
    key: 'principal',
    header: 'Principal',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>
          <code>{row.masked_key ?? 'Key not shown'}</code>
        </small>
      </>
    ),
  },
  {
    key: 'scopes',
    header: 'Authority',
    render: (row) =>
      row.scopes && row.scopes.length > 0 ? (
        <small>{row.scopes.join(', ')}</small>
      ) : (
        <StatusChip label="No scopes" tone="blocked" />
      ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) => (
      <>
        <StatusChip label={unknown(row.status)} tone={statusTone(row.status)} />
        {row.revoked_reason ? (
          <>
            <br />
            <small>{row.revoked_reason}</small>
          </>
        ) : null}
      </>
    ),
  },
  {
    key: 'last_used',
    header: 'Last used',
    render: (row) =>
      row.last_used_at ? <small>{row.last_used_at}</small> : <StatusChip label="Never used" tone="unknown" />,
  },
  {
    key: 'expires',
    header: 'Expires',
    render: (row) => (row.expires_at ? <small>{row.expires_at}</small> : <small>No expiry set</small>),
  },
];

const scopeColumns: Column<ScopeRow>[] = [
  {
    key: 'scope',
    header: 'Scope',
    render: (row) => (
      <>
        <code>{row.scope}</code>
        <br />
        <small>{row.description ?? 'No description recorded.'}</small>
      </>
    ),
  },
  {
    key: 'grantable',
    header: 'Grantable',
    render: (row) =>
      row.grantable ? (
        <StatusChip label="Can be granted" tone="neutral" />
      ) : (
        <StatusChip label="Not grantable via API" tone="blocked" />
      ),
  },
  {
    key: 'held',
    header: 'Your session',
    render: (row) =>
      row.held_by_caller ? (
        <StatusChip label="Held" tone="approved" />
      ) : (
        <StatusChip label="Not held" tone="pending" />
      ),
  },
];

export default async function AccessPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const [principals, scopes] = await Promise.all([
    fetchList<PrincipalRow>(withPageQuery('/access/principals', state)),
    fetchJson<ScopePayload>('/access/scopes'),
  ]);

  return (
    <section className="content">
      <h1>Access and roles</h1>
      <p className="muted">
        This platform has no user directory and no named roles. A principal is an API key, and its authority is the
        scope set stored on that key. The page is titled for the question people arrive with, but it answers it with
        the access model that actually exists rather than an invented roster of people.
      </p>

      <h2>Principals</h2>
      <ResourceTable
        outcome={rowsOf(principals)}
        columns={principalColumns}
        rowKey={(row) => row.id}
        page={pageMetaOf(principals)}
        basePath="/access"
        note={noteOf(principals)}
        emptyTitle="No principals"
        emptyDetail="The API answered and this tenant has no API keys. Nothing can currently authenticate against it."
      />
      <p className="muted">
        Revoked keys stay listed with the reason they were revoked. Removing them would tidy the roster at the cost
        of the only record of what once held access, which is the first thing asked for after an incident. Key
        material is never shown; only the masked form is stored. Issue and revoke keys on the{' '}
        <Link href="/developer">developer portal</Link>.
      </p>

      <h2>Scope catalogue</h2>
      {scopes.status === 'ok' ? (
        <>
          <DataTable
            columns={scopeColumns}
            rows={scopes.data.scopes ?? []}
            rowKey={(row) => row.scope}
            caption="Every scope the API enforces, and whether this session holds it"
            emptyLabel="The API returned no scope catalogue."
          />
          {scopes.data.role_model?.detail ? (
            <p className="muted">{scopes.data.role_model.detail}</p>
          ) : null}
        </>
      ) : (
        <ErrorState title="Scope catalogue unavailable" detail={scopes.reason} />
      )}

      <h2>Not available here</h2>
      <p className="muted">
        There is no user invitation, no group membership, no role assignment, and no single sign-on. None of these
        are switched off pending configuration; the endpoints and tables do not exist. Assigning a person to a case
        is therefore a free-text string, not a reference to an identity the platform can verify.
      </p>
    </section>
  );
}
