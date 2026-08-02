import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
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

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'targeting', label: 'Attribution and targeting' },
  { key: 'sources', label: 'Sources and evidence' },
];

export function generateMetadata({ params }: { params: { campaignId: string } }): Metadata {
  return { title: `Campaign ${params.campaignId}` };
}

function list(values: string[] | undefined, fallback: string): string {
  return values?.length ? values.join(', ') : fallback;
}

export default async function CampaignDetailPage({
  params,
  searchParams,
}: {
  params: { campaignId: string };
  searchParams?: SearchParams;
}) {
  const active = resolveTab(TABS, searchParams?.tab);
  const basePath = `/campaigns/${encodeURIComponent(params.campaignId)}`;
  const outcome = await fetchJson<CampaignDetail>(basePath);
  const record = outcome.status === 'ok' ? outcome.data : null;

  const overviewFields: Field[] = record
    ? [
        { key: 'description', label: 'Description', value: record.description ?? 'No description recorded.' },
        { key: 'status', label: 'Status', value: unknown(record.status) },
        {
          key: 'confidence',
          label: 'Confidence',
          value: record.confidence ?? 'Not stated by the source',
        },
        { key: 'first', label: 'First seen', value: unknown(record.first_seen) },
        { key: 'last', label: 'Last seen', value: unknown(record.last_seen) },
      ]
    : [];

  const targetingFields: Field[] = record
    ? [
        { key: 'actors', label: 'Attributed actors', value: list(record.actor_names, 'No attribution recorded') },
        { key: 'sectors', label: 'Targeted sectors', value: list(record.targeted_sectors, 'Unknown') },
        { key: 'countries', label: 'Targeted countries', value: list(record.targeted_countries, 'Unknown') },
        { key: 'techniques', label: 'ATT&CK techniques', value: list(record.attack_techniques, 'None mapped') },
      ]
    : [];

  const sources = record?.sources ?? [];

  return (
    <DetailShell
      backHref="/campaigns"
      backLabel="All campaigns"
      title={record?.name ?? `Campaign ${params.campaignId}`}
      intro="Attribution and confidence are reproduced from the recording source. The console does not raise confidence on its own, and an unmapped technique is not counted as coverage."
      outcome={outcome}
    >
      <TabNav basePath={basePath} tabs={TABS} active={active} />

      {active === 'overview' ? (
        <FieldTable fields={overviewFields} caption="Values are reproduced as recorded; blanks mean the source said nothing." />
      ) : null}

      {active === 'targeting' ? (
        <>
          <FieldTable fields={targetingFields} caption="Targeting is claimed by the reporting source, not observed by this platform." />
          <p className="muted">
            An actor named here is repeated from the source that made the claim. This platform does not establish
            attribution, and two sources naming different actors are both kept rather than reconciled into a single
            answer.
          </p>
        </>
      ) : null}

      {active === 'sources' ? (
        <>
          {sources.length ? (
            <ul>
              {sources.map((source) => (
                <li key={source}>{source}</li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              No source is recorded against this campaign. That is a gap in the record, not evidence that the campaign
              is unsourced in the wider world.
            </p>
          )}
        </>
      ) : null}

      <p className="muted">
        Relationship, graph, timeline, and history sections are not shown. The campaign endpoint returns flat name
        references with no typed edges and keeps no revision log, so those sections could only ever render empty.
      </p>
    </DetailShell>
  );
}
