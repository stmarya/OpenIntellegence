import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository, type DataQualityMetric } from '@/data/repositories/intelligence-repository';

export const metadata: Metadata = { title: 'Data quality' };

const columns: Column<DataQualityMetric>[] = [
  { key: 'metric', header: 'Measure', render: (row) => <strong>{row.metric}</strong> },
  { key: 'value', header: 'Count', render: (row) => <>{row.value}</> },
  { key: 'basis', header: 'How it is counted', render: (row) => <small>{row.basis}</small> },
];

export default function DataQualityPage() {
  const metrics = intelligenceRepository.dataQualityMetrics();
  return (
    <section className="content">
      <DemoDataBanner label="Quality counters are computed from the bundled snapshot." />
      <h1>Data quality</h1>
      <p className="muted">
        Data quality is an analyst surface, not a hidden admin metric. Missing values stay missing here: an absent score
        is counted as unknown and never rendered as zero, and an unenriched record is never presented as clean.
      </p>
      <DataTable
        columns={columns}
        rows={metrics}
        rowKey={(row) => row.id}
        caption="Quarantine replay, duplicate review, and entity resolution queues appear once the ingestion service is connected."
      />
    </section>
  );
}
