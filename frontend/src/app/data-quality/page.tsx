import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository, type DataQualityMetric } from '@/data/repositories/intelligence-repository';
import { fetchJson, mapOutcome } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Data quality' };

const columns: Column<DataQualityMetric>[] = [
  { key: 'metric', header: 'Measure', render: (row) => <strong>{row.metric}</strong> },
  { key: 'value', header: 'Count', render: (row) => <>{row.value}</> },
  { key: 'basis', header: 'How it is counted', render: (row) => <small>{row.basis}</small> },
];

type QuarantineSummary = { total?: number; by_reason?: Record<string, number> };
type QuarantineRow = { reason: string; count: number };

const quarantineColumns: Column<QuarantineRow>[] = [
  { key: 'reason', header: 'Rejection reason', render: (row) => <strong>{row.reason}</strong> },
  { key: 'count', header: 'Records held', render: (row) => <>{row.count}</> },
];

export default async function DataQualityPage() {
  const metrics = intelligenceRepository.dataQualityMetrics();
  const quarantine = await fetchJson<QuarantineSummary>('/quarantine');
  const quarantineRows = mapOutcome(quarantine, (payload) =>
    Object.entries(payload.by_reason ?? {}).map(([reason, count]) => ({ reason, count }))
  );
  const total = quarantine.status === 'ok' ? quarantine.data.total : null;

  return (
    <section className="content">
      <DemoDataBanner label="Snapshot counters are computed from the bundled historical corpus." />
      <h1>Data quality</h1>
      <p className="muted">
        Data quality is an analyst surface, not a hidden admin metric. Missing values stay missing here: an absent score
        is counted as unknown and never rendered as zero, and an unenriched record is never presented as clean.
      </p>
      <DataTable
        columns={columns}
        rows={metrics}
        rowKey={(row) => row.id}
        caption="Counters derived from the pinned source snapshot."
      />
      <h2>Quarantine</h2>
      <p className="muted">
        Records that failed validation are held rather than discarded, so a malformed feed costs you visibility instead
        of data.{' '}
        {total === null || total === undefined ? '' : `The API currently reports ${total} quarantined record(s).`}
      </p>
      <ResourceTable
        outcome={quarantineRows}
        columns={quarantineColumns}
        rowKey={(row) => row.reason}
        emptyTitle="Nothing in quarantine"
        emptyDetail="The API responded successfully and no record is currently held in quarantine."
        caption="Every held record keeps its rejection reason so it can be corrected and replayed."
      />
    </section>
  );
}
