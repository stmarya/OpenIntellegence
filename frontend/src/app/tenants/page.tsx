import type { Metadata } from 'next';
import Link from 'next/link';
import { FieldTable, type Field } from '@/components/FieldTable';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { ErrorState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchJson, fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Tenants and sharing' };

type TenantPayload = {
  id?: string | null;
  slug?: string | null;
  name?: string | null;
  is_active?: boolean | null;
  created_at?: string | null;
  active_principal_count?: number | null;
  isolation?: {
    model?: string | null;
    cross_tenant_sharing?: string | null;
    detail?: string | null;
  } | null;
};

type SharingGroupRow = {
  id: string;
  name?: string | null;
  description?: string | null;
  purpose?: string | null;
  owner?: string | null;
  member_refs?: string[];
  last_curated_at?: string | null;
};

const sharingColumns: Column<SharingGroupRow>[] = [
  {
    key: 'group',
    header: 'Shared collection',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>{row.description ?? row.purpose ?? 'No description recorded.'}</small>
      </>
    ),
  },
  { key: 'owner', header: 'Owner', render: (row) => <>{row.owner ?? 'Unassigned'}</> },
  {
    key: 'members',
    header: 'Members',
    render: (row) =>
      row.member_refs ? <>{row.member_refs.length}</> : <StatusChip label="Not reported" tone="unknown" />,
  },
  {
    key: 'curated',
    header: 'Last curated',
    render: (row) =>
      row.last_curated_at ? <small>{row.last_curated_at}</small> : <StatusChip label="Never curated" tone="unknown" />,
  },
];

export default async function TenantsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const [tenant, groups] = await Promise.all([
    fetchJson<TenantPayload>('/tenants/current'),
    fetchList<SharingGroupRow>(withPageQuery('/sharing-groups', state)),
  ]);

  return (
    <section className="content">
      <h1>Tenants and sharing</h1>
      <p className="muted">
        Only your own tenant appears here. No session in this platform is authorised across tenant boundaries, so a
        list of every tenant is not something this console is entitled to show, and an administrator view that
        pretended otherwise would be misrepresenting the isolation model.
      </p>

      <h2>Current tenant</h2>
      {tenant.status === 'ok' ? (
        <>
          <FieldTable
            caption="The tenant this session is scoped to"
            fields={
              [
                { key: 'name', label: 'Name', value: unknown(tenant.data.name) },
                { key: 'slug', label: 'Slug', value: <code>{unknown(tenant.data.slug)}</code> },
                { key: 'id', label: 'Identifier', value: <code>{unknown(tenant.data.id)}</code> },
                {
                  key: 'active',
                  label: 'State',
                  value:
                    tenant.data.is_active === true ? (
                      <StatusChip label="Active" tone="approved" />
                    ) : tenant.data.is_active === false ? (
                      <StatusChip label="Inactive" tone="blocked" />
                    ) : (
                      <StatusChip label="Not reported" tone="unknown" />
                    ),
                },
                {
                  key: 'principals',
                  label: 'Principals not revoked',
                  value:
                    typeof tenant.data.active_principal_count === 'number' ? (
                      <Link href="/access">{tenant.data.active_principal_count}</Link>
                    ) : (
                      <StatusChip label="Unavailable" tone="unknown" />
                    ),
                },
                {
                  key: 'created',
                  label: 'Created',
                  value: tenant.data.created_at ?? 'Not recorded',
                },
                {
                  key: 'isolation',
                  label: 'Isolation model',
                  value: <code>{unknown(tenant.data.isolation?.model)}</code>,
                },
              ] satisfies Field[]
            }
          />
          {tenant.data.isolation?.detail ? <p className="muted">{tenant.data.isolation.detail}</p> : null}
        </>
      ) : (
        <ErrorState title="Tenant record unavailable" detail={tenant.reason} />
      )}

      <h2>Sharing groups</h2>
      <ResourceTable
        outcome={rowsOf(groups)}
        columns={sharingColumns}
        rowKey={(row) => row.id}
        page={pageMetaOf(groups)}
        basePath="/tenants"
        note={noteOf(groups)}
        emptyTitle="Nothing shared within this tenant"
        emptyDetail="The API answered and no collection is marked shared. Collections default to private to their owner."
      />
      <p className="muted">
        Sharing here means visible to every principal inside this tenant. It is not sharing with another tenant, a
        partner organisation, or a community such as a sharing community or ISAC. Those mechanisms do not exist, so
        an empty table above means nothing has been shared internally rather than that external sharing is disabled.
        Curate membership on <Link href="/collections">collections</Link>.
      </p>
    </section>
  );
}
