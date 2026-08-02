import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';
import { intelligenceRepository, type DatasetSummary } from '@/data/repositories/intelligence-repository';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Data sources' };

type FeedRow = {
  source?: string | null;
  name?: string | null;
  status?: string | null;
  last_run_at?: string | null;
  last_success_at?: string | null;
  records_ingested?: number | null;
  error?: string | null;
};

const feedColumns: Column<FeedRow>[] = [
  {
    key: 'feed',
    header: 'Feed',
    render: (row) => (
      <>
        <strong>{unknown(row.source ?? row.name)}</strong>
        <br />
        <small>{row.error ?? 'No error reported.'}</small>
      </>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    render: (row) =>
      row.status ? (
        <StatusChip label={row.status} tone={row.status === 'healthy' ? 'approved' : 'blocked'} />
      ) : (
        <StatusChip label="Unknown" tone="unknown" />
      ),
  },
  {
    key: 'last_success',
    header: 'Last success',
    render: (row) => <>{row.last_success_at ?? 'Never succeeded'}</>,
  },
  { key: 'last_run', header: 'Last run', render: (row) => <small>{row.last_run_at ?? 'Never run'}</small> },
];

const catalogColumns: Column<DatasetSummary>[] = [
  {
    key: 'source',
    header: 'Dataset',
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
];

export default async function DataSourcesPage() {
  const datasets = intelligenceRepository.listDatasets();
  const feeds = await fetchJson<FeedRow[]>('/feeds');

  return (
    <section className="content">
      <h1>Data sources</h1>
      <p className="muted">
        Two different things live on this page and they are kept apart on purpose: feeds the platform is actually
        collecting right now, and the pinned corpus this build was developed against.
      </p>

      <h2>Live collection</h2>
      <ResourceTable
        outcome={feeds}
        columns={feedColumns}
        rowKey={(row) => String(row.source ?? row.name)}
        emptyTitle="No feed configured"
        emptyDetail="The API responded successfully and no ingestion feed is configured for this tenant."
        caption="A feed that has never succeeded says so. Degraded collection is reported, never smoothed over."
      />

      <h2>Pinned development corpus</h2>
      <p className="muted">
        These files are historical public research data pinned to an immutable upstream commit and file digest. They are
        not tenant telemetry and are never mixed into the live figures elsewhere in the console.
      </p>
      <DataTable
        columns={catalogColumns}
        rows={datasets}
        rowKey={(row) => row.key}
        caption="Every figure traceable to the exact bytes it came from."
      />
    </section>
  );
}
