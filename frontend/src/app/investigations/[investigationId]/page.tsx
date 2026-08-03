import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Investigation' };

/**
 * Mirrors InvestigationDetail in app/api/v1/workflows.py.
 *
 * Entities and cases arrive embedded in this one response. There is no
 * GET /investigations/{id}/entities -- that path accepts POST only.
 */
type EntityRow = {
  id: string;
  entity_type?: string | null;
  entity_id?: string | null;
  relationship?: string | null;
  evidence?: string | null;
  source_refs?: unknown[];
  created_at?: string | null;
};

type CaseRow = {
  id: string;
  title?: string | null;
  case_type?: string | null;
  status?: string | null;
  priority?: string | null;
  sla_due_at?: string | null;
};

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
  created_at?: string | null;
  entities?: EntityRow[];
  cases?: CaseRow[];
};

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'entities', label: 'Linked entities' },
  { key: 'cases', label: 'Cases' },
];

const entityColumns: Column<EntityRow>[] = [
  {
    key: 'entity',
    header: 'Entity',
    render: (row) => (
      <>
        <strong>{unknown(row.entity_id)}</strong>
        <br />
        <small>{unknown(row.entity_type)}</small>
      </>
    ),
  },
  {
    key: 'relationship',
    header: 'Relationship',
    render: (row) => <StatusChip label={row.relationship ?? 'related_to'} tone="neutral" />,
  },
  {
    key: 'evidence',
    header: 'Analyst evidence',
    render: (row) => <small>{row.evidence ?? 'No evidence recorded.'}</small>,
  },
  {
    key: 'sources',
    header: 'Source references',
    render: (row) => <small>{row.source_refs?.length ? `${row.source_refs.length} recorded` : 'None'}</small>,
  },
  { key: 'added', header: 'Linked at', render: (row) => <small>{unknown(row.created_at)}</small> },
];

const caseColumns: Column<CaseRow>[] = [
  { key: 'title', header: 'Case', render: (row) => <strong>{unknown(row.title)}</strong> },
  { key: 'type', header: 'Type', render: (row) => <>{unknown(row.case_type)}</> },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? <StatusChip label={row.status} tone="neutral" /> : <StatusChip label="Unknown" tone="unknown" />,
  },
  { key: 'priority', header: 'Priority', render: (row) => <>{unknown(row.priority)}</> },
  { key: 'sla', header: 'SLA due', render: (row) => <small>{row.sla_due_at ?? 'No SLA set'}</small> },
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

  const detail = await fetchJson<InvestigationDetail>(
    `/investigations/${encodeURIComponent(investigationId)}`,
  );
  const record = detail.status === 'ok' ? detail.data : null;
  const entities = record?.entities ?? [];
  const cases = record?.cases ?? [];

  const fields: Field[] = [
    { key: 'hypothesis', label: 'Hypothesis', value: record?.hypothesis ?? 'No hypothesis recorded.' },
    { key: 'status', label: 'Status', value: unknown(record?.status) },
    { key: 'priority', label: 'Priority', value: unknown(record?.priority) },
    { key: 'confidence', label: 'Analyst confidence', value: record?.confidence ?? 'Not stated by an analyst.' },
    { key: 'owner', label: 'Owner', value: record?.owner ?? 'Unassigned' },
    { key: 'opened', label: 'Opened', value: unknown(record?.opened_at) },
    { key: 'closed', label: 'Closed', value: record?.closed_at ?? 'Still open' },
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
            An investigation is a line of enquiry; a case is the work that follows from it. The two are kept separate so
            that closing the work does not imply the question was answered.
          </p>
        </>
      ) : null}

      {tab === 'entities' ? (
        <>
          <DataTable
            columns={entityColumns}
            rows={entities}
            rowKey={(row) => row.id}
            emptyLabel="No entity has been linked to this investigation."
            caption="A link is an analyst assertion. It is never inferred automatically from a search result."
          />
          <p className="muted">
            The relationship label is what the analyst chose when linking, defaulting to a generic association. It is
            not a typed edge, so no relationship graph is drawn from it: a diagram inferred from co-membership would
            assert connections nobody made.
          </p>
        </>
      ) : null}

      {tab === 'cases' ? (
        <>
          <DataTable
            columns={caseColumns}
            rows={cases}
            rowKey={(row) => row.id}
            emptyLabel="No case has been opened from this investigation."
            caption="Cases created against this line of enquiry."
          />
          <p className="muted">
            An investigation with no case means no work was raised from it, not that the enquiry found nothing.
          </p>
        </>
      ) : null}
    </DetailShell>
  );
}
