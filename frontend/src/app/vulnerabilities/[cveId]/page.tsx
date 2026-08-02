import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
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

export function generateMetadata({ params }: { params: { cveId: string } }): Metadata {
  return { title: params.cveId };
}

export default async function VulnerabilityDetailPage({ params }: { params: { cveId: string } }) {
  const outcome = await fetchJson<VulnerabilityDetail>(`/vulnerabilities/${encodeURIComponent(params.cveId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;

  const fields: Field[] = record
    ? [
        { key: 'title', label: 'Title', value: unknown(record.title) },
        { key: 'description', label: 'Description', value: record.description ?? 'No description supplied by the source.' },
        {
          key: 'risk',
          label: 'Risk tier',
          value: <RiskBadge score={record.cvss_score ?? null} knownExploited={Boolean(record.is_kev)} />,
        },
        { key: 'cvss', label: 'CVSS score', value: record.cvss_score ?? 'Unknown, not zero' },
        { key: 'vector', label: 'CVSS vector', value: unknown(record.cvss_vector) },
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
        { key: 'published', label: 'Published', value: unknown(record.published_at) },
        { key: 'modified', label: 'Last modified', value: unknown(record.last_modified_at) },
        {
          key: 'products',
          label: 'Affected products',
          value: record.affected_products?.length ? record.affected_products.join(', ') : 'None recorded',
        },
        {
          key: 'references',
          label: 'References',
          value: record.references?.length ? record.references.join(' · ') : 'None recorded',
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
      <FieldTable fields={fields} caption="Every field is reproduced as the source recorded it." />
    </DetailShell>
  );
}
