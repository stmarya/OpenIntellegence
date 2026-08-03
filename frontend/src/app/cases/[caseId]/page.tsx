import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Case' };

/**
 * Mirrors CaseDetail in app/api/v1/workflows.py.
 *
 * Tasks and events arrive embedded in this one response. There is no
 * GET /cases/{id}/tasks or GET /cases/{id}/events -- those paths accept POST
 * only, so fetching them as lists yields nothing forever.
 */
type TaskRow = {
  id: string;
  title?: string | null;
  status?: string | null;
  assignee?: string | null;
  due_at?: string | null;
  completed_at?: string | null;
};

type EventRow = {
  id: string;
  event_type?: string | null;
  body?: string | null;
  actor?: string | null;
  event_at?: string | null;
};

type CaseDetail = {
  id?: string | null;
  investigation_id?: string | null;
  title?: string | null;
  case_type?: string | null;
  status?: string | null;
  priority?: string | null;
  owner?: string | null;
  sla_due_at?: string | null;
  closed_at?: string | null;
  closure_reason?: string | null;
  created_at?: string | null;
  tasks?: TaskRow[];
  events?: EventRow[];
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
  {
    key: 'completed',
    header: 'Completed',
    render: (row) => <small>{row.completed_at ?? 'Not completed'}</small>,
  },
];

const eventColumns: Column<EventRow>[] = [
  { key: 'event', header: 'Event', render: (row) => <strong>{unknown(row.event_type)}</strong> },
  { key: 'actor', header: 'Actor', render: (row) => <>{row.actor ?? 'Actor not recorded'}</> },
  { key: 'body', header: 'Entry', render: (row) => <>{row.body ?? 'No text recorded.'}</> },
  { key: 'at', header: 'Recorded at', render: (row) => <small>{unknown(row.event_at)}</small> },
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

  const detail = await fetchJson<CaseDetail>(`/cases/${encodeURIComponent(caseId)}`);
  const record = detail.status === 'ok' ? detail.data : null;
  const tasks = record?.tasks ?? [];
  const events = record?.events ?? [];

  const fields: Field[] = [
    { key: 'type', label: 'Case type', value: unknown(record?.case_type) },
    { key: 'status', label: 'Status', value: unknown(record?.status) },
    { key: 'priority', label: 'Priority', value: unknown(record?.priority) },
    { key: 'owner', label: 'Owner', value: record?.owner ?? 'Unassigned' },
    {
      key: 'investigation',
      label: 'Parent investigation',
      value: record?.investigation_id ?? 'Not linked to an investigation.',
    },
    { key: 'sla', label: 'SLA due', value: record?.sla_due_at ?? 'No SLA set' },
    { key: 'opened', label: 'Opened', value: unknown(record?.created_at) },
    { key: 'closed', label: 'Closed', value: record?.closed_at ?? 'Still open' },
    {
      key: 'closure',
      label: 'Closure reason',
      value: record?.closure_reason ?? 'Not closed, so no closure reason has been recorded.',
    },
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
        <>
          <DataTable
            columns={taskColumns}
            rows={tasks}
            rowKey={(row) => row.id}
            emptyLabel="No task has been created on this case."
            caption="Every task recorded against this case, returned in full with the case itself."
          />
          <p className="muted">
            An empty task list means no work was ever recorded here, not that the case required none.
          </p>
        </>
      ) : null}

      {tab === 'events' ? (
        <>
          <DataTable
            columns={eventColumns}
            rows={events}
            rowKey={(row) => row.id}
            emptyLabel="No event has been recorded against this case."
            caption="Append-only. Entries are never edited or removed."
          />
          <p className="muted">
            The actor on each entry is the API key that wrote it, not a named person. This platform has no user model,
            so an event cannot be attributed to an individual.
          </p>
        </>
      ) : null}
    </DetailShell>
  );
}
