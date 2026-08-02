import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, noteOf, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Vulnerabilities' };

type VulnerabilityRow = {
  id?: string | null;
  cve_id?: string | null;
  title?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  is_kev?: boolean | null;
  known_exploited?: boolean | null;
  published_at?: string | null;
  last_modified_at?: string | null;
};

function exploited(row: VulnerabilityRow): boolean {
  return row.is_kev === true || row.known_exploited === true;
}

const columns: Column<VulnerabilityRow>[] = [
  {
    key: 'cve',
    header: 'CVE',
    render: (row) => {
      const cve = row.cve_id ?? row.id;
      return (
        <>
          {cve ? (
            <Link href={`/vulnerabilities/${encodeURIComponent(cve)}`}>
              <strong>{cve}</strong>
            </Link>
          ) : (
            <strong>Unknown identifier</strong>
          )}
          <br />
          <small>{row.title ?? 'No title supplied by the source.'}</small>
        </>
      );
    },
  },
  {
    key: 'risk',
    header: 'Risk',
    render: (row) => <RiskBadge score={row.cvss_score ?? null} knownExploited={exploited(row)} />,
  },
  {
    key: 'kev',
    header: 'Exploitation',
    render: (row) =>
      exploited(row) ? (
        <StatusChip label="Known exploited" tone="blocked" />
      ) : (
        <StatusChip label="Not present in KEV" tone="unknown" />
      ),
  },
  { key: 'cvss', header: 'CVSS', render: (row) => <>{row.cvss_score ?? 'Unknown'}</> },
  { key: 'severity', header: 'Severity', render: (row) => <>{unknown(row.severity)}</> },
  {
    key: 'dates',
    header: 'Published / modified',
    render: (row) => (
      <small>
        {unknown(row.published_at)}
        <br />
        {row.last_modified_at ?? 'Not modified since publication'}
      </small>
    ),
  },
];

/**
 * Vulnerability list.
 *
 * Reads the same endpoint as the CVE detail view. Previously this page served
 * the bundled snapshot while the detail page served the API, which let the
 * same CVE carry two different scores depending on how you arrived at it.
 */
export default async function VulnerabilitiesPage({ searchParams }: { searchParams?: SearchParams }) {
  const state = readPageState(searchParams);
  const envelope = await fetchList<VulnerabilityRow>(withPageQuery('/vulnerabilities', state));
  return (
    <section className="content">
      <h1>Vulnerabilities and exposures</h1>
      <p className="muted">
        A missing CVSS score is shown as unknown and never as zero, and absence from the KEV catalogue is reported as
        unproven exploitation rather than as safety.
      </p>
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => String(row.cve_id ?? row.id)}
        page={pageMetaOf(envelope)}
        basePath="/vulnerabilities"
        note={noteOf(envelope)}
        emptyTitle="No vulnerabilities recorded"
        emptyDetail="The API responded successfully and no vulnerability record exists for this tenant."
        caption="Provenance for each record is shown on its detail view."
      />
      <p className="muted">
        This list is not filtered against your estate. A CVE appearing here means it was ingested, not that anything you
        run is affected by it.
      </p>
    </section>
  );
}
