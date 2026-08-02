import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchJson, fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Case' };

type CaseDetail = {
  id?: string | null;
  title?: string | null;
  case_type?: string | null;
  status?: string | null;
  priority?: string | null;
  owner?: string | null;
  summary?: string | null;
  sla_due_at?: string | null;
  closed_at?: string | null;
  closure_reason?: string | null;
  created_at?: string | null;
};

type TaskRow = {
  id: string;
  title?: string | null;
  status?: string | null;
  assignee?: string | null;
  due_at?: string | null;
};

type EventRow = {
  id: string;
  event_type?: string | null;
  actor?: string | null;
  detail?: Record<string, unknown> | null;
  event_at?: string | null;
  created_at?: string | null;
};

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'tasks', label: 'Tasks' },
  { key: 'events', label: 'Event trail' },
];

const taskColumns: Column<TaskRow>[] = [
  { key: 'task', header: 'Task', render: (row) => <strong>{unknown(row.title)}</strong> },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? <StatusChip label={row.status} tone="neutral" /> : <StatusChip label="Unknown" tone="unknown" />,
  },
  { key: 'assignee', header: 'Assignee', render: (row) => <>{row.assignee ?? 'Unassigned'}</> },
  { key: 'due', header: 'Due', render: (row) => <small>{row.due_at ?? 'No due date'}</small> },
];

const eventColumns: Column<EventRow>[] = [
  { key: 'event', header: 'Event', render: (row) => <strong>{unknown(row.event_type)}</strong> },
  { key: 'actor', header: 'Actor', render: (row) => <>{unknown(row.actor)}</> },
  {
    key: 'detail',
    header: 'Detail',
    render: (row) => (
      <small>{row.detail && Object.keys(row.detail).length > 0 ? JSON.stringify(row.detail) : 'None recorded'}</small>
    ),
  },
  { key: 'at', header: 'Recorded at', render: (row) => <small>{unknown(row.event_at ?? row.created_at)}</small> },
];

export default async function CaseDetailPage({
  params,
  searchParams,
}: {
  params: { caseId: string };
  searchParams?: SearchParams;
}) {
  const { caseId } = params;
  const tab = resolveTab(TABS, searchParams?.tab);
  const basePath = `/cases/${encodeURIComponent(caseId)}`;
  const state = readPageState(searchParams);

  const [detail, tasks, events] = await Promise.all([
    fetchJson<CaseDetail>(`/cases/${caseId}`),
    fetchList<TaskRow>(withPageQuery(`/cases/${caseId}/tasks`, state)),
    fetchList<EventRow>(withPageQuery(`/cases/${caseId}/events`, state)),
  ]);

  const record = detail.status === 'ok' ? detail.data : null;
  const fields: Field[] = [
    { key: 'type', label: 'Case type', value: unknown(record?.case_type) },
    { key: 'status', label: 'Status', value: unknown(record?.status) },
    { key: 'priority', label: 'Priority', value: unknown(record?.priority) },
    { key: 'owner', label: 'Owner', value: record?.owner ?? 'Unassigned' },
    { key: 'sla', label: 'SLA due', value: record?.sla_due_at ?? 'No SLA set' },
    { key: 'opened', label: 'Opened', value: unknown(record?.created_at) },
    { key: 'closed', label: 'Closed', value: record?.closed_at ?? 'Still open' },
    {
      key: 'closure',
      label: 'Closure reason',
      value: record?.closure_reason ?? 'Not closed, so no closure reason has been recorded.',
    },
    { key: 'summary', label: 'Summary', value: record?.summary ?? 'No summary written.' },
  ];

  return (
    <DetailShell
      backHref="/cases"
      backLabel="Back to cases"
      title={record?.title ?? `Case ${caseId}`}
      intro="A case records ownership, deadline, work, and outcome. The event trail is append-only, so the history of the case cannot be quietly rewritten."
      outcome={detail}
    >
      <TabNav basePath={basePath} tabs={TABS} active={tab} />

      {tab === 'overview' ? (
        <>
          <FieldTable fields={fields} caption="Fields the case record actually carries." />
          <p className="muted">
            Advancing status, assigning work, and closing the case are write actions and are not offered here. The
            console is read-only, and a control that cannot complete would misstate what this session can do.
          </p>
        </>
      ) : null}

      {tab === 'tasks' ? (
        <ResourceTable
          outcome={rowsOf(tasks)}
          columns={taskColumns}
          rowKey={(row) => row.id}
          page={pageMetaOf(tasks)}
          basePath={`${basePath}?tab=tasks`}
          emptyTitle="No tasks on this case"
          emptyDetail="The API responded successfully and no task has been created for this case."
        />
      ) : null}

      {tab === 'events' ? (
        <ResourceTable
          outcome={rowsOf(events)}
          columns={eventColumns}
          rowKey={(row) => row.id}
          page={pageMetaOf(events)}
          basePath={`${basePath}?tab=events`}
          emptyTitle="No events recorded"
          emptyDetail="The API responded successfully and no event has been recorded against this case."
          caption="Append-only. Entries are never edited or removed."
        />
      ) : null}
    </DetailShell>
  );
}
