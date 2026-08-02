import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type ExposureRow = {
  cve_id?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  is_kev?: boolean | null;
  matched_via?: string | null;
  detected_at?: string | null;
  sla_breached?: boolean | null;
};

export function generateMetadata({ params }: { params: { assetId: string } }): Metadata {
  return { title: `Asset ${params.assetId}` };
}

const columns: Column<ExposureRow>[] = [
  {
    key: 'cve',
    header: 'CVE',
    render: (row) => (
      <>
        <strong>{unknown(row.cve_id)}</strong>
        <br />
        <small>{row.cvss_score ?? 'CVSS unknown'}</small>
      </>
    ),
  },
  {
    key: 'kev',
    header: 'Exploitation',
    render: (row) =>
      row.is_kev ? (
        <StatusChip label="Known exploited" tone="blocked" />
      ) : (
        <StatusChip label="Not in KEV" tone="unknown" />
      ),
  },
  {
    key: 'match',
    header: 'Matched via',
    render: (row) => <small>{row.matched_via ?? 'Match basis not recorded'}</small>,
  },
  {
    key: 'sla',
    header: 'Remediation SLA',
    render: (row) =>
      row.sla_breached === null || row.sla_breached === undefined ? (
        <StatusChip label="Unknown" tone="unknown" />
      ) : row.sla_breached ? (
        <StatusChip label="Breached" tone="blocked" />
      ) : (
        <StatusChip label="Within SLA" tone="approved" />
      ),
  },
  { key: 'detected', header: 'Detected', render: (row) => <small>{unknown(row.detected_at)}</small> },
];

export default async function AssetDetailPage({ params }: { params: { assetId: string } }) {
  const envelope = await fetchList<ExposureRow>(`/assets/${encodeURIComponent(params.assetId)}/exposure`);
  return (
    <DetailShell
      backHref="/assets"
      backLabel="All assets"
      title={`Asset ${params.assetId}`}
      intro="Exposure is only as complete as this asset's software inventory. Every row states how the match was made, so a CPE match is never confused with a vendor-name guess."
      outcome={envelope}
    >
      <ResourceTable
        outcome={rowsOf(envelope)}
        columns={columns}
        rowKey={(row) => String(row.cve_id)}
        emptyTitle="No exposure recorded"
        emptyDetail="The API responded successfully and no CVE has been matched to this asset. If the asset has never reported an inventory, that means unmatched rather than clean."
        caption="Packages with no CPE cannot be matched and are reported as unmatched by the API."
      />
    </DetailShell>
  );
}
