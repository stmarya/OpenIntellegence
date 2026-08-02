import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { TabNav, resolveTab, type TabDefinition } from '@/components/TabNav';
import type { SearchParams } from '@/lib/pagination';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type VulnerabilityDetail = {
  cve_id?: string | null;
  title?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  severity?: string | null;
  is_kev?: boolean | null;
  kev_date_added?: string | null;
  published_at?: string | null;
  last_modified_at?: string | null;
  affected_products?: string[];
  references?: string[];
  exploit_maturity?: string | null;
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
            <StatusChip label={`In KEV since ${unknown(record.kev_date_added)}`} tone="blocked" />
          ) : (
            <StatusChip label="Not present in the KEV catalogue" tone="unknown" />
          ),
        },
        { key: 'maturity', label: 'Exploit maturity', value: unknown(record.exploit_maturity) },
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
        record?.affected_products?.length ? (
          <ul>
            {record.affected_products.map((product) => (
              <li key={product}>{product}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">
            No affected product was recorded by the source. This is missing source data, not confirmation that nothing is
            affected.
          </p>
        )
      ) : null}

      {tab === 'exploitation' ? (
        <>
          <FieldTable fields={exploitationFields} caption="Exploitation state is reported, never inferred." />
          <p className="muted">
            Public proof-of-concept tracking and in-the-wild telemetry are not shown, because no endpoint reports either
            for a single CVE.
          </p>
        </>
      ) : null}

      {tab === 'sources' ? (
        record?.references?.length ? (
          <ul>
            {record.references.map((reference) => (
              <li key={reference}>
                <a href={reference} rel="noreferrer noopener" target="_blank">
                  {reference}
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No reference was recorded for this CVE.</p>
        )
      ) : null}

      <p className="muted">
        Affected assets, detection content, related campaigns, and analyst notes are absent because no endpoint links
        them to a CVE. Empty tabs are not shown for them, since an empty tab reads as an answered question.
      </p>
    </DetailShell>
  );
}
