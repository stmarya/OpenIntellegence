import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Alert rules' };

/** Mirrors AlertRuleOut in app/api/v1/alerting.py. */
type AlertRuleRow = {
  id: string;
  name?: string | null;
  description?: string | null;
  trigger_type?: string | null;
  condition?: Record<string, unknown> | null;
  severity?: string | null;
  enabled?: boolean | null;
  cooldown_minutes?: number | null;
  auto_create_case?: boolean | null;
  created_at?: string | null;
};

function severityTone(severity?: string | null) {
  if (severity === 'critical' || severity === 'high') return 'blocked' as const;
  if (severity === 'medium') return 'pending' as const;
  if (severity === 'low') return 'neutral' as const;
  return 'unknown' as const;
}

function describeCondition(condition?: Record<string, unknown> | null) {
  if (!condition || Object.keys(condition).length === 0) {
    return 'No condition recorded. This rule matches on its trigger type alone.';
  }
  return JSON.stringify(condition);
}

const columns: Column<AlertRuleRow>[] = [
  {
    key: 'rule',
    header: 'Rule',
    render: (row) => (
      <>
        <strong>{unknown(row.name)}</strong>
        <br />
        <small>{row.description ?? 'No description recorded'}</small>
      </>
    ),
  },
  {
    key: 'state',
    header: 'State',
    render: (row) =>
      row.enabled === true ? (
        <StatusChip label="Enabled" tone="approved" />
      ) : row.enabled === false ? (
        <StatusChip label="Disabled" tone="unknown" />
      ) : (
        <StatusChip label="Unknown" tone="unknown" />
      ),
  },
  {
    key: 'trigger',
    header: 'Trigger and severity',
    render: (row) => (
      <>
        {unknown(row.trigger_type)}
        <br />
        <StatusChip label={row.severity ?? 'Unknown'} tone={severityTone(row.severity)} />
      </>
    ),
  },
  {
    key: 'condition',
    header: 'Condition',
    render: (row) => (
      <small>
        <code>{describeCondition(row.condition)}</code>
      </small>
    ),
  },
  {
    key: 'behaviour',
    header: 'Cooldown / auto case',
    render: (row) => (
      <>
        {row.cooldown_minutes == null ? 'Unknown' : `${row.cooldown_minutes} min`}
        <br />
        <small>{row.auto_create_case ? 'Opens a case automatically' : 'No case opened automatically'}</small>
      </>
    ),
  },
  { key: 'created', header: 'Created', render: (row) => <small>{unknown(row.created_at)}</small> },
];

export default async function AlertRulesPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<AlertRuleRow>(withPageQuery('/alert-rules', state));

  return (
    <section className="content">
      <h1>Alert rules</h1>
      <p className="muted">
        The conditions that raise an alert in this tenant. A rule describes what the platform is watching for, which is
        not the same as what is happening: an enabled rule that has never matched is evidence that nothing met its
        condition, not that the estate is quiet. A condition that was written too narrowly stays silent in exactly the
        same way as a clean environment.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        note={noteOf(envelope)}
        page={pageMetaOf(envelope)}
        basePath="/alert-rules"
        emptyTitle="No alert rules defined"
        emptyDetail="The API responded successfully and this tenant has defined no alert rules. Nothing is being watched for automatically."
        caption="Conditions are shown as stored, so a rule can be audited against what it actually matches."
      />
      <p className="muted">
        Cooldown suppresses repeat notifications, not repeat events. While a rule is cooling down, further matches are
        counted as occurrences on the existing alert rather than raised again, so a low alert count can reflect
        suppression rather than a quiet period. Check the occurrence count on <Link href="/alerts">alerts</Link> before
        reading a rule as low-volume.
      </p>
      <p className="muted">
        Rules are created and amended through the API with a write scope. This console is read-only and does not offer a
        create action, because a control that always fails would imply an authority this session does not hold.
      </p>
    </section>
  );
}
