import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { DemoDataBanner, EmptyState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { intelligenceRepository } from '@/data/repositories/intelligence-repository';
import { withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Intelligence explorer' };

const SEARCH_LIMIT = 200;

type Hit = {
  id: string;
  entity: string;
  label: string;
  detail: string;
  href: string | null;
};

type VulnerabilityRow = { id?: string | null; cve_id?: string | null; title?: string | null; description?: string | null };
type IndicatorRow = { id: string; value?: string | null; indicator_type?: string | null; verdict?: string | null };
type ActorRow = { id: string; name?: string | null; description?: string | null };
type CampaignRow = { id: string; name?: string | null; description?: string | null };
type MalwareRow = { id: string; name?: string | null; description?: string | null };

const columns: Column<Hit>[] = [
  { key: 'entity', header: 'Type', render: (row) => <StatusChip label={row.entity} tone="neutral" /> },
  {
    key: 'label',
    header: 'Match',
    render: (row) => (row.href ? <Link href={row.href}>{row.label}</Link> : <strong>{row.label}</strong>),
  },
  { key: 'detail', header: 'Context', render: (row) => <small>{row.detail}</small> },
];

function matches(query: string, ...values: Array<string | null | undefined>): boolean {
  const needle = query.toLowerCase();
  return values.some((value) => (value ?? '').toLowerCase().includes(needle));
}

/**
 * Intelligence explorer.
 *
 * This is a cross-entity lookup over the records the API returns, not a
 * server-side index. The distinction is stated on the page because a search
 * box that quietly searches only part of the corpus will be trusted as though
 * it searched all of it.
 */
export default async function ResearchPage({ searchParams }: { searchParams?: SearchParams }) {
  const rawQuery = Array.isArray(searchParams?.q) ? searchParams?.q[0] : searchParams?.q;
  const query = (rawQuery ?? '').trim();
  const references = intelligenceRepository.listResearchReferences();

  if (query.length === 0) {
    return (
      <section className="content">
        <h1>Intelligence explorer</h1>
        <p className="muted">
          Search vulnerabilities, indicators, threat actors, campaigns, and malware families in one place. Add a{' '}
          <code>?q=</code> term to the address to run a lookup, for example{' '}
          <Link href="/research?q=ransom">/research?q=ransom</Link>.
        </p>
        <p className="muted">
          No search runs until a term is supplied. An empty result set for an empty query would be indistinguishable
          from a corpus with nothing in it.
        </p>

        <h2>Pinned research corpus</h2>
        <DemoDataBanner label="Pinned public research corpus. Not tenant data." />
        {references.length === 0 ? (
          <EmptyState
            title="No research references available"
            detail="The bundled corpus returned no research references for this view."
          />
        ) : (
          references.map((record) => (
            <article className="reference" key={record.id}>
              <strong>{record.repository}</strong>
              <StatusChip label="Unverified" tone="unknown" />
              <p>{record.description}</p>
              <small>
                Source: {record.provenance.sourceFile} · {record.updatedAt}
              </small>
            </article>
          ))
        )}
      </section>
    );
  }

  const page = { limit: SEARCH_LIMIT, offset: 0 };
  const [vulnerabilities, indicators, actors, campaigns, malware] = await Promise.all([
    fetchList<VulnerabilityRow>(withPageQuery('/vulnerabilities', page)),
    fetchList<IndicatorRow>(withPageQuery('/iocs', page)),
    fetchList<ActorRow>(withPageQuery('/actors', page)),
    fetchList<CampaignRow>(withPageQuery('/campaigns', page)),
    fetchList<MalwareRow>(withPageQuery('/malware', page)),
  ]);

  const hits: Hit[] = [];
  const unreadable: string[] = [];

  const vulnerabilityRows = rowsOf(vulnerabilities);
  if (vulnerabilityRows.status === 'ok') {
    for (const row of vulnerabilityRows.data) {
      const cve = row.cve_id ?? row.id;
      if (matches(query, cve, row.title, row.description)) {
        hits.push({
          id: `vulnerability:${cve}`,
          entity: 'Vulnerability',
          label: unknown(cve),
          detail: row.title ?? 'No title supplied by the source.',
          href: cve ? `/vulnerabilities/${encodeURIComponent(cve)}` : null,
        });
      }
    }
  } else {
    unreadable.push(`vulnerabilities (${vulnerabilityRows.reason})`);
  }

  const indicatorRows = rowsOf(indicators);
  if (indicatorRows.status === 'ok') {
    for (const row of indicatorRows.data) {
      if (matches(query, row.value, row.indicator_type)) {
        hits.push({
          id: `indicator:${row.id}`,
          entity: 'Indicator',
          label: unknown(row.value),
          detail: `${unknown(row.indicator_type)} \u00b7 ${row.verdict ?? 'not enriched'}`,
          href: `/indicators/${encodeURIComponent(row.id)}`,
        });
      }
    }
  } else {
    unreadable.push(`indicators (${indicatorRows.reason})`);
  }

  const actorRows = rowsOf(actors);
  if (actorRows.status === 'ok') {
    for (const row of actorRows.data) {
      if (matches(query, row.name, row.description)) {
        hits.push({
          id: `actor:${row.id}`,
          entity: 'Threat actor',
          label: unknown(row.name),
          detail: row.description ?? 'No description supplied by the source.',
          href: `/threat-actors/${encodeURIComponent(row.id)}`,
        });
      }
    }
  } else {
    unreadable.push(`threat actors (${actorRows.reason})`);
  }

  const campaignRows = rowsOf(campaigns);
  if (campaignRows.status === 'ok') {
    for (const row of campaignRows.data) {
      if (matches(query, row.name, row.description)) {
        hits.push({
          id: `campaign:${row.id}`,
          entity: 'Campaign',
          label: unknown(row.name),
          detail: row.description ?? 'No description supplied by the source.',
          href: `/campaigns/${encodeURIComponent(row.id)}`,
        });
      }
    }
  } else {
    unreadable.push(`campaigns (${campaignRows.reason})`);
  }

  const malwareRows = rowsOf(malware);
  if (malwareRows.status === 'ok') {
    for (const row of malwareRows.data) {
      if (matches(query, row.name, row.description)) {
        hits.push({
          id: `malware:${row.id}`,
          entity: 'Malware',
          label: unknown(row.name),
          detail: row.description ?? 'No description supplied by the source.',
          href: `/malware/${encodeURIComponent(row.id)}`,
        });
      }
    }
  } else {
    unreadable.push(`malware (${malwareRows.reason})`);
  }

  return (
    <section className="content">
      <h1>Intelligence explorer</h1>
      <p className="muted">
        Results for <strong>{query}</strong>. Matching is a substring comparison performed over the first {SEARCH_LIMIT}{' '}
        records read from each entity type. It is not a ranked index, and a term absent here may still exist further
        down a collection.
      </p>

      {unreadable.length > 0 ? (
        <p className="muted">
          These sources could not be searched, so this result set is incomplete: {unreadable.join('; ')}.
        </p>
      ) : null}

      {hits.length > 0 ? (
        <DataTable
          columns={columns}
          rows={hits}
          rowKey={(row) => row.id}
          caption="Matches are grouped by entity type in the order the sources were read."
        />
      ) : (
        <EmptyState
          title="No match in the records read"
          detail="Every searched source answered, and none of the records read contain this term. Records beyond the search window were not examined."
        />
      )}
    </section>
  );
}
