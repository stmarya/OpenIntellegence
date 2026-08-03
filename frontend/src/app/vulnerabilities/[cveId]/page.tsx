import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

/** Mirrors ExploitOut in app/api/schemas.py. */
type Exploit = {
  source?: string | null;
  external_id?: string | null;
  title?: string | null;
  url?: string | null;
  author?: string | null;
  stars?: number | null;
  confidence?: number | null;
  published_at?: string | null;
};

/** Mirrors VulnerabilityDetail in app/api/schemas.py. */
type VulnerabilityDetail = {
  cve_id?: string | null;
  title?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  severity?: string | null;
  epss_score?: number | null;
  is_kev?: boolean | null;
  kev_added_at?: string | null;
  kev_due_at?: string | null;
  vendor?: string | null;
  product?: string | null;
  exploit_maturity?: string | null;
  published_at?: string | null;
  last_modified_at?: string | null;
  sources?: string[];
  affected_asset_count?: number | null;
  cpe_uris?: string[];
  exploits?: Exploit[];
};

const TABS: TabDefinition[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'products', label: 'Affected products' },
  { key: 'exploitation', label: 'Exploitation' },
  { key: 'sources', label: 'Sources and evidence' },
];

export function generateMetadata({ params }: { params: { cveId: string } }): Metadata {
  return { title: params.cveId };
}

export default async function VulnerabilityDetailPage({
  params,
  searchParams,
}: {
  params: { cveId: string };
  searchParams?: SearchParams;
}) {
  const outcome = await fetchJson<VulnerabilityDetail>(`/vulnerabilities/${encodeURIComponent(params.cveId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;
  const tab = resolveTab(TABS, searchParams?.tab);
  const basePath = `/vulnerabilities/${encodeURIComponent(params.cveId)}`;
  const exploits = record?.exploits ?? [];
  const cpeUris = record?.cpe_uris ?? [];

  const overviewFields: Field[] = record
    ? [
        { key: 'title', label: 'Title', value: unknown(record.title) },
        {
          key: 'description',
          label: 'Description',
          value: record.description ?? 'No description supplied by the source.',
        },
        {
          key: 'risk',
          label: 'Risk tier',
          value: <RiskBadge score={record.cvss_score ?? null} knownExploited={Boolean(record.is_kev)} />,
        },
        { key: 'cvss', label: 'CVSS score', value: record.cvss_score ?? 'Unknown, not zero' },
        { key: 'vector', label: 'CVSS vector', value: unknown(record.cvss_vector) },
        { key: 'severity', label: 'Severity', value: unknown(record.severity) },
        {
          key: 'epss',
          label: 'EPSS probability',
          value:
            record.epss_score == null
              ? 'Not scored. EPSS estimates the chance of exploitation activity; no score means unscored, not low risk.'
              : record.epss_score,
        },
        {
          key: 'assets',
          label: 'Affected assets in this tenant',
          value:
            record.affected_asset_count == null
              ? 'Unknown'
              : `${record.affected_asset_count} (counted from unresolved exposure rows)`,
        },
        { key: 'published', label: 'Published', value: unknown(record.published_at) },
        { key: 'modified', label: 'Last modified', value: unknown(record.last_modified_at) },
      ]
    : [];

  const exploitationFields: Field[] = record
    ? [
        {
          key: 'kev',
          label: 'Known exploitation',
          value: record.is_kev ? (
            <StatusChip label={`In KEV since ${unknown(record.kev_added_at)}`} tone="blocked" />
          ) : (
            <StatusChip label="Not present in the KEV catalogue" tone="unknown" />
          ),
        },
        {
          key: 'kev_due',
          label: 'KEV remediation due',
          value: record.kev_due_at ?? 'No KEV due date recorded.',
        },
        { key: 'maturity', label: 'Exploit maturity', value: unknown(record.exploit_maturity) },
        {
          key: 'poc_count',
          label: 'Public proof-of-concept repositories',
          value: exploits.length,
        },
      ]
    : [];

  return (
    <DetailShell
      backHref="/vulnerabilities"
      backLabel="All vulnerabilities"
      title={params.cveId}
      intro="Absence from the KEV catalogue means exploitation is unknown for this CVE. It never means the CVE is safe, and a missing CVSS score is shown as unknown rather than as zero."
      outcome={outcome}
    >
      <TabNav basePath={basePath} tabs={TABS} active={tab} />

      {tab === 'overview' ? (
        <FieldTable fields={overviewFields} caption="Every field is reproduced as the source recorded it." />
      ) : null}

      {tab === 'products' ? (
        <>
          <FieldTable
            fields={[
              { key: 'vendor', label: 'Vendor', value: unknown(record?.vendor) },
              { key: 'product', label: 'Product', value: unknown(record?.product) },
            ]}
            caption="Vendor and product as recorded by the advisory, not normalised."
          />
          {cpeUris.length ? (
            <>
              <p className="muted">
                {cpeUris.length} CPE identifier{cpeUris.length === 1 ? '' : 's'} are recorded for this CVE. Asset
                matching runs against these strings, so a product that is affected in reality but absent from this list
                will not be counted as exposed.
              </p>
              <ul>
                {cpeUris.map((cpe) => (
                  <li key={cpe}>
                    <code>{cpe}</code>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">
              No CPE identifier was recorded for this CVE. Without one, this vulnerability cannot be matched to installed
              software automatically, so an exposure count of zero here reflects missing identifiers rather than a
              confirmed absence of affected hosts.
            </p>
          )}
        </>
      ) : null}

      {tab === 'exploitation' ? (
        <>
          <FieldTable fields={exploitationFields} caption="Exploitation state is reported, never inferred." />
          {exploits.length ? (
            <>
              <h2>Public proof-of-concept code</h2>
              <ul>
                {exploits.map((exploit) => (
                  <li key={`${exploit.source ?? 'source'}:${exploit.external_id ?? exploit.url ?? ''}`}>
                    {exploit.url ? (
                      <a href={exploit.url} rel="noreferrer noopener" target="_blank">
                        {exploit.title ?? exploit.external_id ?? exploit.url}
                      </a>
                    ) : (
                      <strong>{exploit.title ?? exploit.external_id ?? 'Untitled'}</strong>
                    )}
                    <br />
                    <small>
                      {unknown(exploit.source)}
                      {exploit.author ? ` · ${exploit.author}` : ''}
                      {exploit.stars == null ? '' : ` · ${exploit.stars} stars`}
                      {exploit.published_at ? ` · published ${exploit.published_at}` : ''}
                    </small>
                  </li>
                ))}
              </ul>
              <p className="muted">
                A published repository is evidence that exploit code circulates, not that it works or that it has been
                used against this estate. Star counts measure attention, not reliability.
              </p>
            </>
          ) : (
            <p className="muted">
              No public proof-of-concept repository was ingested for this CVE. Coverage comes from the pinned GitHub
              corpus, so this means none was found in that window rather than that none exists.
            </p>
          )}
          <p className="muted">
            In-the-wild exploitation telemetry is not shown, because no endpoint reports it for a single CVE.
          </p>
        </>
      ) : null}

      {tab === 'sources' ? (
        record?.sources?.length ? (
          <>
            <p className="muted">This record was assembled from the following feeds.</p>
            <ul>
              {record.sources.map((source) => (
                <li key={source}>{source}</li>
              ))}
            </ul>
            <p className="muted">
              Where the feeds disagreed, the stored value is whichever feed wrote last. This page does not show the
              superseded values, because no revision history is kept per field.
            </p>
          </>
        ) : (
          <p className="muted">No contributing source was recorded for this CVE.</p>
        )
      ) : null}

      <p className="muted">
        Detection content, related campaigns, and analyst notes are absent because no endpoint links them to a CVE.
        Empty tabs are not shown for them, since an empty tab reads as an answered question.
      </p>
    </DetailShell>
  );
}
