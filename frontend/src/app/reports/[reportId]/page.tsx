import type { Metadata } from 'next';
import Link from 'next/link';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type ReportDetail = {
  id?: string;
  title?: string | null;
  template?: string | null;
  status?: string | null;
  progress?: number | null;
  period_start?: string | null;
  period_end?: string | null;
  created_at?: string | null;
  completed_at?: string | null;
  requested_by?: string | null;
  error_message?: string | null;
  content?: string | null;
  citations?: string[];
};

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Generation record' },
  { key: 'body', label: 'Report body' },
  { key: 'sources', label: 'Sources cited' },
];

export function generateMetadata({ params }: { params: { reportId: string } }): Metadata {
  return { title: `Report ${params.reportId}` };
}

export default async function ReportDetailPage({
  params,
  searchParams,
}: {
  params: { reportId: string };
  searchParams?: SearchParams;
}) {
  const outcome = await fetchJson<ReportDetail>(`/reports/${encodeURIComponent(params.reportId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;
  const tab = resolveTab(TABS, searchParams?.tab);
  const basePath = `/reports/${encodeURIComponent(params.reportId)}`;

  const fields: Field[] = record
    ? [
        { key: 'template', label: 'Template', value: unknown(record.template) },
        {
          key: 'status',
          label: 'Status',
          value:
            record.status === 'completed' ? (
              <StatusChip label="Completed" tone="approved" />
            ) : record.status === 'failed' ? (
              <StatusChip label="Failed" tone="blocked" />
            ) : (
              <StatusChip label={record.status ?? 'Unknown'} tone={record.status ? 'pending' : 'unknown'} />
            ),
        },
        { key: 'progress', label: 'Progress', value: record.progress ?? 'Unknown' },
        {
          key: 'period',
          label: 'Reporting period',
          value: `${unknown(record.period_start)} to ${unknown(record.period_end)}`,
        },
        { key: 'requested', label: 'Requested by', value: unknown(record.requested_by) },
        { key: 'created', label: 'Requested at', value: unknown(record.created_at) },
        { key: 'completed', label: 'Completed at', value: record.completed_at ?? 'Not completed' },
        { key: 'error', label: 'Failure reason', value: record.error_message ?? 'None recorded' },
      ]
    : [];

  return (
    <DetailShell
      backHref="/reports"
      backLabel="All reports"
      title={record?.title ?? `Report ${params.reportId}`}
      intro="Progress is the real value stored by the generator, never an animation. A failed report keeps its failure reason instead of disappearing from the list."
      outcome={outcome}
    >
      <TabNav basePath={basePath} tabs={TABS} active={tab} />

      {tab === 'overview' ? (
        <>
          <FieldTable fields={fields} caption="What the generator recorded about this run." />
          <p className="muted">
            A completed report is a generated draft, not an approved product. Review and approval are human decisions
            and are not recorded by this console.
          </p>
        </>
      ) : null}

      {tab === 'body' ? (
        record?.content ? (
          <p>{record.content}</p>
        ) : (
          <p className="muted">
            No body has been written yet. Facts are gathered by query before any narrative is composed, so an incomplete
            report shows nothing rather than a draft assembled from guesses.
          </p>
        )
      ) : null}

      {tab === 'sources' ? (
        record?.citations?.length ? (
          <ul>
            {record.citations.map((citation) => (
              <li key={citation}>
                <small>{citation}</small>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">
            No citation was recorded with this report. Statements in the body should be verified against the underlying
            records before the report is circulated; the <Link href="/ai-analyst">analyst</Link> withholds uncited
            answers for the same reason.
          </p>
        )
      ) : null}
    </DetailShell>
  );
}
