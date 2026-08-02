import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { Pagination } from '@/components/Pagination';
import { ErrorState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { readPageState, type PageMeta, type SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Import workbench' };

type QuarantineRecord = {
  id: string;
  source?: string | null;
  reason?: string | null;
  raw_payload?: unknown;
  created_at?: string | null;
};

type QuarantinePayload = {
  total?: number | null;
  by_reason?: Record<string, number>;
  page?: { limit: number; offset: number; has_more: boolean };
  records?: QuarantineRecord[];
};

type RunRow = {
  id: string;
  source?: string | null;
  status?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  records_fetched?: number | null;
  records_ingested?: number | null;
  records_quarantined?: number | null;
  error_message?: string | null;
};

type RunsPayload = { runs?: RunRow[] };

function runTone(status: string | null | undefined) {
  if (status === 'success') return 'approved' as const;
  if (status === 'failed') return 'blocked' as const;
  if (status === 'partial') return 'pending' as const;
  if (status === 'running') return 'neutral' as const;
  return 'unknown' as const;
}

function summarisePayload(payload: unknown): string {
  if (payload === null || payload === undefined) return 'No payload retained.';
  try {
    const text = JSON.stringify(payload);
    return text.length > 160 ? `${text.slice(0, 160)}\u2026` : text;
  } catch {
    return 'Payload could not be rendered as text.';
  }
}

const quarantineColumns: Column<QuarantineRecord>[] = [
  {
    key: 'source',
    header: 'Source',
    render: (row) => (
      <>
        <strong>{unknown(row.source)}</strong>
        <br />
        <small>{row.created_at ?? 'No timestamp recorded'}</small>
      </>
    ),
  },
  {
    key: 'reason',
    header: 'Rejection reason',
    render: (row) => <>{row.reason ?? 'No reason recorded.'}</>,
  },
  {
    key: 'payload',
    header: 'Retained payload',
    render: (row) => (
      <small>
        <code>{summarisePayload(row.raw_payload)}</code>
      </small>
    ),
  },
];

const runColumns: Column<RunRow>[] = [
  {
    key: 'source',
    header: 'Connector',
    render: (row) => (
      <>
        <strong>{unknown(row.source)}</strong>
        <br />
        <small>{row.started_at ?? 'No start time recorded'}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Outcome',
    render: (row) => (
      <>
        <StatusChip label={unknown(row.status)} tone={runTone(row.status)} />
        {row.error_message ? (
          <>
            <br />
            <small>{row.error_message}</small>
          </>
        ) : null}
      </>
    ),
  },
  {
    key: 'volume',
    header: 'Fetched / ingested / quarantined',
    render: (row) => (
      <small>
        {unknown(row.records_fetched)} / {unknown(row.records_ingested)} / {unknown(row.records_quarantined)}
      </small>
    ),
  },
  {
    key: 'finished',
    header: 'Finished',
    render: (row) =>
      row.finished_at ? <small>{row.finished_at}</small> : <StatusChip label="Did not finish" tone="pending" />,
  },
];

export default async function ImportWorkbenchPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const [quarantine, runs] = await Promise.all([
    fetchJson<QuarantinePayload>(`/quarantine?limit=${state.limit}&offset=${state.offset}`),
    fetchJson<RunsPayload>('/runs?limit=50'),
  ]);

  const records = quarantine.status === 'ok' ? quarantine.data.records ?? [] : [];
  const total = quarantine.status === 'ok' ? quarantine.data.total : null;
  const byReason = quarantine.status === 'ok' ? quarantine.data.by_reason ?? {} : {};
  const reasons = Object.entries(byReason).sort((a, b) => b[1] - a[1]);

  const meta: PageMeta | null =
    quarantine.status === 'ok' && typeof total === 'number' && quarantine.data.page
      ? {
          limit: quarantine.data.page.limit,
          offset: quarantine.data.page.offset,
          total,
          has_more: Boolean(quarantine.data.page.has_more),
        }
      : null;

  return (
    <section className="content">
      <h1>Import workbench</h1>
      <p className="muted">
        Records that failed normalisation are parked here with the payload that caused the failure, not discarded.
        A connector that silently drops what it cannot parse looks perfectly healthy while losing volume, which is
        precisely the failure this surface exists to make visible.
      </p>

      <h2>Quarantine backlog</h2>
      {quarantine.status === 'ok' ? (
        <>
          <p className="muted">
            {typeof total === 'number'
              ? `${total} record${total === 1 ? '' : 's'} are currently held in quarantine across all connectors.`
              : 'The API did not report a backlog total, so the size of this backlog is unknown.'}
          </p>
          {reasons.length > 0 ? (
            <ul>
              {reasons.map(([reason, count]) => (
                <li key={reason}>
                  {reason} — {count}
                </li>
              ))}
            </ul>
          ) : null}
          <DataTable
            columns={quarantineColumns}
            rows={records}
            rowKey={(row) => row.id}
            caption="Records rejected during normalisation"
            emptyLabel="The API answered and no record is currently quarantined."
          />
          <Pagination basePath="/import" meta={meta} rowCount={records.length} />
        </>
      ) : (
        <ErrorState title="Quarantine backlog unavailable" detail={quarantine.reason} />
      )}
      <p className="muted">
        The reason breakdown above counts the whole backlog, not just the rows on this page. Replaying a quarantined
        record is a write action guarded by a scope this read-only surface cannot assume it holds, so no replay
        control is offered here rather than presenting a button that would be refused.
      </p>

      <h2>Ingestion runs</h2>
      {runs.status === 'ok' ? (
        <DataTable
          columns={runColumns}
          rows={runs.data.runs ?? []}
          rowKey={(row) => row.id}
          caption="The 50 most recent connector executions"
          emptyLabel="The API answered and no ingestion run has ever been recorded."
        />
      ) : (
        <ErrorState title="Run history unavailable" detail={runs.reason} />
      )}
      <p className="muted">
        This list is capped at the 50 most recent runs and is not paginated, because the endpoint accepts a limit but
        reports no total. Treat it as a recent window rather than a complete history. Triggering a run requires the
        administrative scope and is not offered from the console. Per-connector health, including connectors that
        have never run at all, is on <Link href="/connectors">connectors</Link>; the resulting data defects are
        triaged on <Link href="/data-quality">data quality</Link>.
      </p>

      <h2>File and manual import</h2>
      <p className="muted">
        There is no upload here. Ingestion runs through registered connectors, and no endpoint accepts an analyst
        supplied STIX bundle, CSV, or IOC list. A drop zone that queued a file nowhere would be worse than its
        absence, so the gap is stated instead.
      </p>
    </section>
  );
}
