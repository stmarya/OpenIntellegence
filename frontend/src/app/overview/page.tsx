import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { MetricCards, type Metric } from '@/components/MetricCards';
import { ResourceTable } from '@/components/ResourceTable';
import { RiskBadge } from '@/components/RiskBadge';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';
import { totalOf } from '@/lib/totals';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Command center' };

type VulnerabilityRow = {
  cve_id?: string | null;
  id?: string | null;
  title?: string | null;
  cvss_score?: number | null;
  known_exploited?: boolean | null;
  published_at?: string | null;
};

type AlertRow = { id: string };
type AssetRow = { id: string };
type CaseRow = { id: string };

const columns: Column<VulnerabilityRow>[] = [
  {
    key: 'record',
    header: 'Record',
    render: (row) => {
      const cve = row.cve_id ?? row.id;
      return (
        <>
          <strong>{cve ? <Link href={`/vulnerabilities/${cve}`}>{cve}</Link> : 'Unknown'}</strong>
          <br />
          <small>{row.title ?? 'No title supplied by the source.'}</small>
        </>
      );
    },
  },
  {
    key: 'risk',
    header: 'Risk',
    render: (row) => <RiskBadge score={row.cvss_score ?? null} knownExploited={row.known_exploited === true} />,
  },
  { key: 'cvss', header: 'CVSS', render: (row) => <>{row.cvss_score ?? 'Unknown'}</> },
  { key: 'published', header: 'Published', render: (row) => <small>{unknown(row.published_at)}</small> },
];

export default async function OverviewPage() {
  const [vulnerabilities, alerts, assets, cases] = await Promise.all([
    fetchList<VulnerabilityRow>('/vulnerabilities?limit=25'),
    fetchList<AlertRow>('/alerts?limit=1'),
    fetchList<AssetRow>('/assets?limit=1'),
    fetchList<CaseRow>('/cases?limit=1'),
  ]);

  const metrics: Metric[] = [
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities tracked',
      value: totalOf(vulnerabilities),
      basis: 'Reported total from the vulnerabilities endpoint.',
    },
    {
      id: 'alerts',
      label: 'Alerts raised',
      value: totalOf(alerts),
      basis: 'Reported total from the alerts endpoint.',
    },
    {
      id: 'assets',
      label: 'Assets in inventory',
      value: totalOf(assets),
      basis: 'Reported total from the asset inventory.',
    },
    {
      id: 'cases',
      label: 'Cases on record',
      value: totalOf(cases),
      basis: 'Reported total from the case management endpoint.',
    },
  ];

  return (
    <section className="content">
      <h1>Command center</h1>
      <p className="muted">
        Each counter is the total the API itself reports. A counter that could not be read says Unavailable, because an
        unobserved environment is not a quiet one.
      </p>
      <MetricCards metrics={metrics} />

      <h2>Vulnerability triage</h2>
      <ResourceTable
        outcome={rowsOf(vulnerabilities)}
        columns={columns}
        rowKey={(row) => String(row.cve_id ?? row.id)}
        emptyTitle="No vulnerabilities recorded"
        emptyDetail="The API responded successfully and no vulnerability record exists for this tenant."
        caption="Unknown CVSS stays Unknown and is never treated as low risk. Absence from KEV means unproven exploitation, not safety."
      />
    </section>
  );
}
