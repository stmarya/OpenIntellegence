import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Indicator' };

type Indicator = {
  id: string;
  indicator_type?: string | null;
  value?: string | null;
  verdict?: string | null;
  confidence?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
  source?: string | null;
};

type SightingRef = {
  id: string;
  source: string;
  observed_at: string;
  asset_id?: string | null;
  confidence?: number | null;
};

type IndicatorDetail = {
  indicator: Indicator;
  sightings: SightingRef[];
  sighting_match_basis: string;
  enrichment_state: string;
};

const sightingColumns: Column<SightingRef>[] = [
  { key: 'observed', header: 'Observed at', render: (row) => <>{unknown(row.observed_at)}</> },
  { key: 'source', header: 'Reported by', render: (row) => <>{unknown(row.source)}</> },
  { key: 'asset', header: 'Asset', render: (row) => <small>{row.asset_id ?? 'No asset attributed'}</small> },
  { key: 'confidence', header: 'Confidence', render: (row) => <>{row.confidence ?? 'Unknown'}</> },
];

export default async function IndicatorDetailPage({ params }: { params: { indicatorId: string } }) {
  const outcome = await fetchJson<IndicatorDetail>(`/iocs/${encodeURIComponent(params.indicatorId)}`);
  const detail = outcome.status === 'ok' ? outcome.data : null;

  return (
    <DetailShell
      backHref="/indicators"
      backLabel="Back to indicators"
      title={detail ? unknown(detail.indicator.value) : 'Indicator'}
      intro="An indicator record and the sightings this tenant reported against its exact value."
      outcome={outcome}
    >
      {detail ? (
        <>
          <FieldTable
            caption="Enrichment state is a field in its own right, not an inference from a missing verdict."
            fields={[
              { key: 'type', label: 'Type', value: unknown(detail.indicator.indicator_type) },
              {
                key: 'verdict',
                label: 'Verdict',
                value: detail.indicator.verdict ? (
                  <StatusChip
                    label={detail.indicator.verdict}
                    tone={detail.indicator.verdict === 'malicious' ? 'blocked' : 'neutral'}
                  />
                ) : (
                  <StatusChip label="Not enriched" tone="unknown" />
                ),
              },
              { key: 'enrichment', label: 'Enrichment state', value: detail.enrichment_state },
              { key: 'confidence', label: 'Confidence', value: unknown(detail.indicator.confidence) },
              { key: 'first', label: 'First seen', value: unknown(detail.indicator.first_seen) },
              { key: 'last', label: 'Last seen', value: unknown(detail.indicator.last_seen) },
              { key: 'source', label: 'Source', value: unknown(detail.indicator.source) },
            ]}
          />

          <h2>Sightings in this tenant</h2>
          <p className="muted">{detail.sighting_match_basis}</p>
          {detail.sightings.length > 0 ? (
            <DataTable
              columns={sightingColumns}
              rows={detail.sightings}
              rowKey={(row) => row.id}
              caption="Sightings are reported observations, not confirmations of compromise."
            />
          ) : (
            <p className="muted">No sighting has been reported for this value.</p>
          )}
        </>
      ) : null}
    </DetailShell>
  );
}
