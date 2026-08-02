import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository, type PostureMetric } from '@/data/repositories/intelligence-repository';

export const metadata: Metadata = { title: 'Executive intelligence' };

const columns: Column<PostureMetric>[] = [
  { key: 'label', header: 'Measure', render: (row) => <strong>{row.label}</strong> },
  { key: 'value', header: 'Value', render: (row) => <>{row.value}</> },
  { key: 'basis', header: 'Basis', render: (row) => <small>{row.basis}</small> },
];

export default function ExecutiveIntelligencePage() {
  const metrics = intelligenceRepository.postureMetrics();
  return (
    <section className="content">
      <DemoDataBanner label="Executive figures are derived from the bundled snapshot." />
      <h1>Executive intelligence</h1>
      <p className="muted">
        Every figure states the source it was computed from. Measures that depend on tenant-scoped APIs are reported as
        unavailable rather than estimated.
      </p>
      <DataTable
        columns={columns}
        rows={metrics}
        rowKey={(row) => row.id}
        caption="Unavailable means the platform has no verified value, not that the value is zero."
      />
    </section>
  );
}
