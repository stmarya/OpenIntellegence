import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { DemoDataBanner } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { intelligenceRepository, type DataQualityMetric } from '@/data/repositories/intelligence-repository';
import { pageMetaOf, withPageQuery } from '@/lib/pagination';
import { fetchJson, fetchList, rowsOf } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Data quality' };

const SAMPLE_LIMIT = 200;

type QuarantineSummary = { total?: number; by_reason?: Record<string, number> };
type IndicatorRow = { id: string; verdict?: string | null };
type VictimRow = { id: string; needs_review?: boolean | null };
type FeedRow = { source?: string | null; status?: string | null };

type Queue = {
  id: string;
  queue: string;
  count: string;
  basis: string;
  exhaustive: boolean;
};

const queueColumns: Column<Queue>[] = [
  { key: 'queue', header: 'Work queue', render: (row) => <strong>{row.queue}</strong> },
  { key: 'count', header: 'Items', render: (row) => <>{row.count}</> },
  {
    key: 'coverage',
    header: 'Counting basis',
    render: (row) =>
      row.exhaustive ? (
        <StatusChip label="Counted in full" tone="neutral" />
      ) : (
        <StatusChip label="Sampled" tone="unknown" />
      ),
  },
  { key: 'basis', header: 'How it is derived', render: (row) => <small>{row.basis}</small> },
];

const metricColumns: Column<DataQualityMetric>[] = [
  { key: 'metric', header: 'Measure', render: (row) => <strong>{row.metric}</strong> },
  { key: 'value', header: 'Count', render: (row) => <>{row.value}</> },
  { key: 'basis', header: 'How it is counted', render: (row) => <small>{row.basis}</small> },
];

type QuarantineRow = { reason: string; count: number };

const quarantineColumns: Column<QuarantineRow>[] = [
  { key: 'reason', header: 'Rejection reason', render: (row) => <strong>{row.reason}</strong> },
  { key: 'count', header: 'Records held', render: (row) => <>{row.count}</> },
];

/**
 * Data quality work queues.
 *
 * Queues are built from live endpoints where the data supports it. Where a
 * queue can only be sampled, it is labelled as sampled: an under-count
 * presented as a total would let a backlog look like it had been cleared.
 */
export default async function DataQualityPage() {
  const sample = { limit: SAMPLE_LIMIT, offset: 0 };
  const [quarantine, indicators, victims, feeds] = await Promise.all([
    fetchJson<QuarantineSummary>('/quarantine'),
    fetchList<IndicatorRow>(withPageQuery('/iocs', sample)),
    fetchList<VictimRow>(withPageQuery('/ransomware/victims', sample)),
    fetchJson<FeedRow[]>('/feeds'),
  ]);

  const indicatorRows = rowsOf(indicators);
  const victimRows = rowsOf(victims);
  const indicatorTotal = pageMetaOf(indicators)?.total ?? null;
  const victimTotal = pageMetaOf(victims)?.total ?? null;

  const queues: Queue[] = [];

  queues.push({
    id: 'quarantine',
    queue: 'Records held in quarantine',
    count:
      quarantine.status === 'ok' && typeof quarantine.data.total === 'number'
        ? String(quarantine.data.total)
        : 'Unavailable',
    basis: 'Reported directly by the ingestion quarantine endpoint. Held records are replayable once corrected.',
    exhaustive: true,
  });

  queues.push({
    id: 'unenriched',
    queue: 'Indicators awaiting enrichment',
    count:
      indicatorRows.status === 'ok'
        ? `${indicatorRows.data.filter((row) => !row.verdict).length} of ${indicatorRows.data.length} read`
        : 'Unavailable',
    basis:
      indicatorTotal !== null && indicatorTotal > SAMPLE_LIMIT
        ? `Counted across the first ${SAMPLE_LIMIT} of ${indicatorTotal} indicators. The real backlog is larger than shown.`
        : 'Counted across every indicator returned. An indicator without a verdict is unenriched, not clean.',
    exhaustive: indicatorTotal !== null && indicatorTotal <= SAMPLE_LIMIT,
  });

  queues.push({
    id: 'victim-normalisation',
    queue: 'Victim names awaiting normalisation',
    count:
      victimRows.status === 'ok'
        ? `${victimRows.data.filter((row) => row.needs_review).length} of ${victimRows.data.length} read`
        : 'Unavailable',
    basis:
      victimTotal !== null && victimTotal > SAMPLE_LIMIT
        ? `Counted across the first ${SAMPLE_LIMIT} of ${victimTotal} victim records.`
        : 'Counted across every victim record returned. Raw URLs and status prefixes are flagged rather than auto-cleaned.',
    exhaustive: victimTotal !== null && victimTotal <= SAMPLE_LIMIT,
  });

  queues.push({
    id: 'silent-connectors',
    queue: 'Connectors never run or failing',
    count:
      feeds.status === 'ok'
        ? String(feeds.data.filter((row) => row.status === 'never_run' || row.status === 'failed').length)
        : 'Unavailable',
    basis: 'Derived from the connector registry. A connector that never ran produces no data and no error.',
    exhaustive: true,
  });

  const unavailableQueues = [
    ['Duplicate entity merge candidates', 'No de-duplication candidate endpoint is exposed.'],
    ['Unmapped ATT&CK techniques', 'Technique mappings are read from records; there is no review queue to read.'],
    ['Assets missing CPE identifiers', 'Software inventory exposes no CPE-matching state to count.'],
    ['Stale agent telemetry', 'No staleness threshold is evaluated server-side, so no queue can be counted honestly.'],
    ['Orphaned relationships', 'Relationship integrity is not evaluated by any endpoint.'],
  ];

  const quarantineRows =
    quarantine.status === 'ok'
      ? Object.entries(quarantine.data.by_reason ?? {}).map(([reason, count]) => ({ reason, count }))
      : [];

  return (
    <section className="content">
      <h1>Data quality</h1>
      <p className="muted">
        Data quality is an analyst surface, not a hidden admin metric. Missing values stay missing here: an absent score
        is counted as unknown and never rendered as zero, and an unenriched record is never presented as clean.
      </p>

      <h2>Work queues</h2>
      <DataTable
        columns={queueColumns}
        rows={queues}
        rowKey={(row) => row.id}
        caption="Each queue states whether it was counted in full or sampled."
      />

      <h2>Queues that cannot be counted yet</h2>
      <p className="muted">
        These are listed rather than omitted. A queue missing from the console looks like a queue with nothing in it.
      </p>
      <ul>
        {unavailableQueues.map(([name, reason]) => (
          <li key={name}>
            <strong>{name}</strong> — <small>{reason}</small>
          </li>
        ))}
      </ul>

      <h2>Quarantine breakdown</h2>
      <p className="muted">
        Records that failed validation are held rather than discarded, so a malformed feed costs you visibility instead
        of data. Connector-level counts are on the <Link href="/connectors">connector surface</Link>.
      </p>
      {quarantine.status === 'unavailable' ? (
        <p className="muted">Quarantine could not be read: {quarantine.reason}</p>
      ) : quarantineRows.length > 0 ? (
        <DataTable
          columns={quarantineColumns}
          rows={quarantineRows}
          rowKey={(row) => row.reason}
          caption="Every held record keeps its rejection reason so it can be corrected and replayed."
        />
      ) : (
        <p className="muted">The API responded successfully and no record is currently held in quarantine.</p>
      )}

      <h2>Reference corpus counters</h2>
      <DemoDataBanner label="These counters are computed from the bundled historical corpus, not from tenant data." />
      <DataTable
        columns={metricColumns}
        rows={intelligenceRepository.dataQualityMetrics()}
        rowKey={(row) => row.id}
        caption="Counters derived from the pinned source snapshot."
      />
    </section>
  );
}
