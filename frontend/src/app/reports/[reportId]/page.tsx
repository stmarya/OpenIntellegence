import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
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
};

export function generateMetadata({ params }: { params: { reportId: string } }): Metadata {
  return { title: `Report ${params.reportId}` };
}

export default async function ReportDetailPage({ params }: { params: { reportId: string } }) {
  const outcome = await fetchJson<ReportDetail>(`/reports/${encodeURIComponent(params.reportId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;

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
      <FieldTable fields={fields} />
      <h2>Report body</h2>
      {record?.content ? (
        <p>{record.content}</p>
      ) : (
        <p className="muted">
          No body has been written yet. Facts are gathered by query before any narrative is composed, so an incomplete
          report shows nothing rather than a draft assembled from guesses.
        </p>
      )}
    </DetailShell>
  );
}
