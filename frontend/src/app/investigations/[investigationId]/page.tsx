import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { ResourceTable } from '@/components/ResourceTable';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchJson, fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Investigation' };

type InvestigationDetail = {
  id?: string | null;
  title?: string | null;
  hypothesis?: string | null;
  status?: string | null;
  priority?: string | null;
  confidence?: number | null;
  owner?: string | null;
  opened_at?: string | null;
  closed_at?: string | null;
  summary?: string | null;
};

type EntityRow = {
  id: string;
  entity_type?: string | null;
  entity_ref?: string | null;
  role?: string | null;
  note?: string | null;
  added_at?: string | null;
};

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'entities', label: 'Linked entities' },
];

const entityColumns: Column<EntityRow>[] = [
  {
    key: 'entity',
    header: 'Entity',
    render: (row) => (
      <>
        <strong>{unknown(row.entity_ref)}</strong>
        <br />
        <small>{unknown(row.entity_type)}</small>
      </>
    ),
  },
  { key: 'role', header: 'Role in hypothesis', render: (row) => <>{row.role ?? 'Not stated'}</> },
  { key: 'note', header: 'Analyst note', render: (row) => <small>{row.note ?? 'No note recorded.'}</small> },
  { key: 'added', header: 'Linked at', render: (row) => <small>{unknown(row.added_at)}</small> },
];

export default async function InvestigationDetailPage({
  params,
  searchParams,
}: {
  params: { investigationId: string };
  searchParams?: SearchParams;
}) {
  const { investigationId } = params;
  const tab = resolveTab(TABS, searchParams?.tab);
  const basePath = `/investigations/${encodeURIComponent(investigationId)}`;
  const state = readPageState(searchParams);

  const [detail, entities] = await Promise.all([
    fetchJson<InvestigationDetail>(`/investigations/${investigationId}`),
    fetchList<EntityRow>(withPageQuery(`/investigations/${investigationId}/entities`, state)),
  ]);

  const record = detail.status === 'ok' ? detail.data : null;
  const fields: Field[] = [
    { key: 'hypothesis', label: 'Hypothesis', value: record?.hypothesis ?? 'No hypothesis recorded.' },
    { key: 'status', label: 'Status', value: unknown(record?.status) },
    { key: 'priority', label: 'Priority', value: unknown(record?.priority) },
    { key: 'confidence', label: 'Analyst confidence', value: record?.confidence ?? 'Not stated by an analyst.' },
    { key: 'owner', label: 'Owner', value: record?.owner ?? 'Unassigned' },
    { key: 'opened', label: 'Opened', value: unknown(record?.opened_at) },
    { key: 'closed', label: 'Closed', value: record?.closed_at ?? 'Still open' },
    { key: 'summary', label: 'Summary', value: record?.summary ?? 'No summary written.' },
  ];

  return (
    <DetailShell
      backHref="/investigations"
      backLabel="Back to investigations"
      title={record?.title ?? `Investigation ${investigationId}`}
      intro="An investigation holds a hypothesis and the entities linked to it. Confidence remains a human judgement and is shown as not stated when nobody has made one."
      outcome={detail}
    >
      <TabNav basePath={basePath} tabs={TABS} active={tab} />

      {tab === 'overview' ? (
        <>
          <FieldTable fields={fields} caption="Fields the investigation record actually carries." />
          <p className="muted">
            No relationship graph is drawn. Links are stored as flat references without the typed edges a graph would
            need, and a diagram inferred from co-membership would assert connections nobody made.
          </p>
        </>
      ) : null}

      {tab === 'entities' ? (
        <ResourceTable
          outcome={rowsOf(entities)}
          columns={entityColumns}
          rowKey={(row) => row.id}
          page={pageMetaOf(entities)}
          basePath={`${basePath}?tab=entities`}
          emptyTitle="No entities linked"
          emptyDetail="The API responded successfully and no entity has been linked to this investigation."
          caption="A link is an analyst assertion. It is never inferred automatically from a search result."
        />
      ) : null}
    </DetailShell>
  );
}
