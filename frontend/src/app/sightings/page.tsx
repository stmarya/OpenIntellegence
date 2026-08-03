import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Sightings' };

/** Mirrors SightingOut in app/api/v1/alerting.py. */
type SightingRow = {
  id: string;
  entity_type?: string | null;
  entity_id?: string | null;
  asset_id?: string | null;
  source?: string | null;
  observed_at?: string | null;
  confidence?: number | null;
  context?: Record<string, unknown> | null;
};

function describeContext(context?: Record<string, unknown> | null) {
  if (!context || Object.keys(context).length === 0) {
    return 'No context submitted with this sighting.';
  }
  return JSON.stringify(context);
}

const columns: Column<SightingRow>[] = [
  {
    key: 'entity',
    header: 'Observed entity',
    render: (row) => (
      <>
        <strong>{unknown(row.entity_id)}</strong>
        <br />
        <small>{unknown(row.entity_type)}</small>
      </>
    ),
  },
  {
    key: 'observed',
    header: 'Observed at',
    render: (row) => <>{unknown(row.observed_at)}</>,
  },
  {
    key: 'source',
    header: 'Reported by',
    render: (row) => (
      <>
        {unknown(row.source)}
        <br />
        <small>{row.asset_id ? `Asset ${row.asset_id}` : 'No asset attributed'}</small>
      </>
    ),
  },
  {
    key: 'confidence',
    header: 'Reporter confidence',
    render: (row) =>
      row.confidence == null ? (
        <StatusChip label="Not scored" tone="unknown" />
      ) : (
        <>{row.confidence}</>
      ),
  },
  {
    key: 'context',
    header: 'Context',
    render: (row) => (
      <small>
        <code>{describeContext(row.context)}</code>
      </small>
    ),
  },
];

export default async function SightingsPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<SightingRow>(withPageQuery('/sightings', state));

  return (
    <section className="content">
      <h1>Sightings</h1>
      <p className="muted">
        Raw observations reported into this tenant: something submitted that a given entity was seen at a given time. A
        sighting is a report, not a finding. It records that a source claims an observation, and carries no judgement
        about whether the entity is malicious or whether the observation was correct.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => row.id}
        note={noteOf(envelope)}
        page={pageMetaOf(envelope)}
        basePath="/sightings"
        emptyTitle="No sightings reported"
        emptyDetail="The API responded successfully and no sighting has been submitted for this tenant. Nothing has reported an observation; this is not evidence that the entities below were absent."
        caption="Confidence is the reporting source's own score and is not normalised across sources."
      />
      <p className="muted">
        Confidence is supplied by whoever submitted the sighting. Two sources scoring the same observation at 80 are not
        making comparable claims, so these numbers should not be averaged or ranked against each other. A sighting with
        no score is shown as not scored rather than assumed low.
      </p>
      <p className="muted">
        Telemetry coverage is partial. An entity with no sighting here was not necessarily absent from the estate — it
        may simply sit outside what the reporting sources can see. Sightings tied to a specific alert are shown on that{' '}
        <Link href="/alerts">alert</Link>, and those tied to an indicator on its{' '}
        <Link href="/indicators">indicator</Link> page.
      </p>
    </section>
  );
}
