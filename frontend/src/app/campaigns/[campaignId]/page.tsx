import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type CampaignDetail = {
  id?: string;
  name?: string | null;
  description?: string | null;
  status?: string | null;
  confidence?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
  actor_names?: string[];
  targeted_sectors?: string[];
  targeted_countries?: string[];
  attack_techniques?: string[];
  sources?: string[];
};

export function generateMetadata({ params }: { params: { campaignId: string } }): Metadata {
  return { title: `Campaign ${params.campaignId}` };
}

function list(values: string[] | undefined, fallback: string): string {
  return values?.length ? values.join(', ') : fallback;
}

export default async function CampaignDetailPage({ params }: { params: { campaignId: string } }) {
  const outcome = await fetchJson<CampaignDetail>(`/campaigns/${encodeURIComponent(params.campaignId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;

  const fields: Field[] = record
    ? [
        { key: 'description', label: 'Description', value: record.description ?? 'No description recorded.' },
        { key: 'status', label: 'Status', value: unknown(record.status) },
        { key: 'confidence', label: 'Confidence', value: record.confidence ?? 'Not stated by the source' },
        { key: 'actors', label: 'Attributed actors', value: list(record.actor_names, 'No attribution recorded') },
        { key: 'sectors', label: 'Targeted sectors', value: list(record.targeted_sectors, 'Unknown') },
        { key: 'countries', label: 'Targeted countries', value: list(record.targeted_countries, 'Unknown') },
        { key: 'techniques', label: 'ATT&CK techniques', value: list(record.attack_techniques, 'None mapped') },
        { key: 'first', label: 'First seen', value: unknown(record.first_seen) },
        { key: 'last', label: 'Last seen', value: unknown(record.last_seen) },
        { key: 'sources', label: 'Sources', value: list(record.sources, 'No source recorded') },
      ]
    : [];

  return (
    <DetailShell
      backHref="/campaigns"
      backLabel="All campaigns"
      title={record?.name ?? `Campaign ${params.campaignId}`}
      intro="Attribution and confidence are reproduced from the recording source. The console does not raise confidence on its own, and an unmapped technique is not counted as coverage."
      outcome={outcome}
    >
      <FieldTable fields={fields} />
    </DetailShell>
  );
}
