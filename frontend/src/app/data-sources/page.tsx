import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { StatusChip } from '@/components/StatusChip';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository, type DatasetSummary } from '@/data/repositories/intelligence-repository';

export const metadata: Metadata = { title: 'Data sources' };

const columns: Column<DatasetSummary>[] = [
  {
    key: 'source',
    header: 'Source',
    render: (row) => (
      <>
        <strong>{row.label}</strong>
        <br />
        <small>{row.provenance.sourceFile}</small>
      </>
    ),
  },
  {
    key: 'kind',
    header: 'Kind',
    render: (row) =>
      row.provenance.kind === 'source_snapshot' ? (
        <StatusChip label="Pinned source snapshot" tone="neutral" />
      ) : (
        <StatusChip label="Synthetic fixture" tone="unknown" />
      ),
  },
  { key: 'records', header: 'Records', render: (row) => <>{row.recordCount}</> },
  {
    key: 'origin',
    header: 'Origin',
    render: (row) => (
      <>
        {row.provenance.repository}
        <br />
        <small>
          {row.provenance.directory} · commit {row.provenance.commit.slice(0, 7)}
        </small>
      </>
    ),
  },
  { key: 'sha', header: 'File digest', render: (row) => <small>{row.provenance.sourceSha}</small> },
  {
    key: 'collection',
    header: 'Collection state',
    render: () => <StatusChip label="Scheduled collection not connected" tone="unknown" />,
  },
];

export default function DataSourcesPage() {
  const datasets = intelligenceRepository.listDatasets();
  return (
    <section className="content">
      <DemoDataBanner label="Source catalog for the bundled snapshot." />
      <h1>Data sources</h1>
      <p className="muted">
        Each entry is pinned to an immutable upstream commit and file digest, so any figure in the console can be traced
        back to the exact bytes it came from. Scheduling, freshness, and run history become available once the ingestion
        service is connected.
      </p>
      <DataTable
        columns={columns}
        rows={datasets}
        rowKey={(row) => row.key}
        caption="Collection state is reported as unknown because no live collector is attached to this build."
      />
    </section>
  );
}
