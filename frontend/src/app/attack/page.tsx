import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { fetchList, rowsOf, type FetchOutcome } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'ATT&CK coverage' };

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

export default async function AttackCoveragePage() {
  const [campaigns, malware] = await Promise.all([
    fetchList<TechniqueBearer>('/campaigns'),
    fetchList<TechniqueBearer>('/malware'),
  ]);
  const campaignRows = rowsOf(campaigns);
  const malwareRows = rowsOf(malware);

  const outcome: FetchOutcome<CoverageRow[]> =
    campaignRows.status === 'unavailable'
      ? campaignRows
      : malwareRows.status === 'unavailable'
        ? malwareRows
        : { status: 'ok', data: buildCoverage(campaignRows.data, malwareRows.data) };

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
    </section>
  );
}
