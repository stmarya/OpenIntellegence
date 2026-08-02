import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { pageMetaOf, withPageQuery } from '@/lib/pagination';
import { fetchList, rowsOf, type FetchOutcome } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'ATT&CK coverage' };

const AGGREGATE_LIMIT = 200;

type TechniqueBearer = { id: string; name?: string | null; attack_techniques?: string[] };

type CoverageRow = {
  technique: string;
  campaignCount: number;
  malwareCount: number;
  examples: string[];
};

const columns: Column<CoverageRow>[] = [
  { key: 'technique', header: 'Technique', render: (row) => <strong>{row.technique}</strong> },
  { key: 'campaigns', header: 'Campaigns', render: (row) => <>{row.campaignCount}</> },
  { key: 'malware', header: 'Malware families', render: (row) => <>{row.malwareCount}</> },
  {
    key: 'examples',
    header: 'Referenced by',
    render: (row) => <small>{row.examples.length > 0 ? row.examples.join(', ') : 'Unnamed records'}</small>,
  },
];

function buildCoverage(campaigns: TechniqueBearer[], malware: TechniqueBearer[]): CoverageRow[] {
  const index = new Map<string, CoverageRow>();
  const add = (records: TechniqueBearer[], field: 'campaignCount' | 'malwareCount') => {
    for (const record of records) {
      for (const technique of record.attack_techniques ?? []) {
        const row = index.get(technique) ?? { technique, campaignCount: 0, malwareCount: 0, examples: [] };
        row[field] += 1;
        if (record.name && row.examples.length < 4 && !row.examples.includes(record.name)) {
          row.examples.push(record.name);
        }
        index.set(technique, row);
      }
    }
  };
  add(campaigns, 'campaignCount');
  add(malware, 'malwareCount');
  return [...index.values()].sort(
    (a, b) => b.campaignCount + b.malwareCount - (a.campaignCount + a.malwareCount)
  );
}

/**
 * Describe the population the aggregate was actually computed over.
 *
 * An aggregate is only as honest as its denominator. If either source list
 * was truncated, the counts below understate reality and the page has to say
 * so rather than presenting a partial tally as coverage.
 */
function describeBasis(label: string, total: number | null, fetched: number): string | null {
  if (total === null) {
    return `The ${label} endpoint reported no total, so it is unknown whether all ${label} were counted.`;
  }
  if (total > fetched) {
    return `Only ${fetched} of ${total} ${label} were read, so these counts are a lower bound.`;
  }
  return null;
}

export default async function AttackCoveragePage() {
  const state = { limit: AGGREGATE_LIMIT, offset: 0 };
  const [campaigns, malware] = await Promise.all([
    fetchList<TechniqueBearer>(withPageQuery('/campaigns', state)),
    fetchList<TechniqueBearer>(withPageQuery('/malware', state)),
  ]);
  const campaignRows = rowsOf(campaigns);
  const malwareRows = rowsOf(malware);

  const outcome: FetchOutcome<CoverageRow[]> =
    campaignRows.status === 'unavailable'
      ? campaignRows
      : malwareRows.status === 'unavailable'
        ? malwareRows
        : { status: 'ok', data: buildCoverage(campaignRows.data, malwareRows.data) };

  const caveats = [
    describeBasis('campaigns', pageMetaOf(campaigns)?.total ?? null, campaignRows.status === 'ok' ? campaignRows.data.length : 0),
    describeBasis('malware families', pageMetaOf(malware)?.total ?? null, malwareRows.status === 'ok' ? malwareRows.data.length : 0),
  ].filter((value): value is string => value !== null);

  return (
    <section className="content">
      <h1>ATT&amp;CK coverage</h1>
      <p className="muted">
        Coverage is counted from techniques that ingested campaigns and malware families actually reference. It is
        intelligence coverage, not detection coverage, and no percentage is claimed for techniques nobody has mapped.
      </p>
      <ResourceTable
        outcome={outcome}
        columns={columns}
        rowKey={(row) => row.technique}
        emptyTitle="No technique mappings"
        emptyDetail="Both endpoints responded successfully and no ingested record references an ATT&CK technique yet."
        caption="A technique absent from this table is unmapped, which is not the same as uncovered."
      />
      {caveats.length > 0 ? (
        <p className="muted">
          {caveats.join(' ')} A matrix view is not drawn from a partial tally, because a grid of mostly empty cells reads
          as measured absence rather than missing input.
        </p>
      ) : (
        <p className="muted">
          Every ingested campaign and malware family was included in this aggregate. Techniques nobody mapped are absent
          rather than shown as zero.
        </p>
      )}
    </section>
  );
}
