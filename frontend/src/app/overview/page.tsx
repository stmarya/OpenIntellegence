import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { MetricCards, type Metric } from '@/components/MetricCards';
import { ResourceTable } from '@/components/ResourceTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { withPageQuery } from '@/lib/pagination';
import { fetchJson, fetchList, rowsOf, unknown } from '@/lib/server-fetch';
import { totalOf } from '@/lib/totals';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Command center' };

const PREVIEW = { limit: 5, offset: 0 };
const TRIAGE = { limit: 25, offset: 0 };
const COUNT_ONLY = { limit: 1, offset: 0 };

type VulnerabilityRow = {
  cve_id?: string | null;
  id?: string | null;
  title?: string | null;
  cvss_score?: number | null;
  known_exploited?: boolean | null;
  published_at?: string | null;
};
type AlertRow = {
  id: string;
  title?: string | null;
  severity?: string | null;
  status?: string | null;
  risk_score?: number | null;
  last_triggered_at?: string | null;
};
type CorrelationRow = { id: string; title?: string | null; risk_score?: number | null; created_at?: string | null };
type CaseRow = { id: string; title?: string | null; status?: string | null; severity?: string | null };
type VictimRow = { id: string; victim_name?: string | null; group_name?: string | null; discovered_at?: string | null };
type FeedRow = { source?: string | null; status?: string | null };
type Row = { id: string };

const vulnerabilityColumns: Column<VulnerabilityRow>[] = [
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

const alertColumns: Column<AlertRow>[] = [
  {
    key: 'alert',
    header: 'Alert',
    render: (row) => <Link href={`/alerts/${encodeURIComponent(row.id)}`}>{unknown(row.title)}</Link>,
  },
  { key: 'severity', header: 'Severity', render: (row) => <>{unknown(row.severity)}</> },
  {
    key: 'status',
    header: 'Triage',
    render: (row) =>
      row.status === 'acknowledged' ? (
        <StatusChip label="Acknowledged" tone="approved" />
      ) : (
        <StatusChip label={row.status ?? 'open'} tone="pending" />
      ),
  },
  { key: 'seen', header: 'Last triggered', render: (row) => <small>{unknown(row.last_triggered_at)}</small> },
];

const correlationColumns: Column<CorrelationRow>[] = [
  {
    key: 'correlation',
    header: 'Correlation',
    render: (row) => <Link href={`/correlations/${encodeURIComponent(row.id)}`}>{unknown(row.title)}</Link>,
  },
  { key: 'risk', header: 'Risk score', render: (row) => <>{row.risk_score ?? 'Unknown'}</> },
  { key: 'created', header: 'Produced', render: (row) => <small>{unknown(row.created_at)}</small> },
];

const caseColumns: Column<CaseRow>[] = [
  {
    key: 'case',
    header: 'Case',
    render: (row) => <Link href={`/cases/${encodeURIComponent(row.id)}`}>{unknown(row.title)}</Link>,
  },
  { key: 'status', header: 'Status', render: (row) => <>{unknown(row.status)}</> },
  { key: 'severity', header: 'Severity', render: (row) => <>{unknown(row.severity)}</> },
];

const victimColumns: Column<VictimRow>[] = [
  { key: 'victim', header: 'Claimed victim', render: (row) => <strong>{unknown(row.victim_name)}</strong> },
  { key: 'group', header: 'Group', render: (row) => <>{unknown(row.group_name)}</> },
  { key: 'discovered', header: 'Discovered', render: (row) => <small>{unknown(row.discovered_at)}</small> },
];

/**
 * Command center.
 *
 * Every block reads a live endpoint and reports its own basis. Blocks the
 * platform cannot substantiate are named in prose rather than rendered as
 * empty panels, because an empty panel on a dashboard reads as "nothing to
 * worry about".
 */
export default async function OverviewPage() {
  const [vulnerabilities, alerts, assets, cases, correlations, victims, agents, feeds] = await Promise.all([
    fetchList<VulnerabilityRow>(withPageQuery('/vulnerabilities', TRIAGE)),
    fetchList<AlertRow>(withPageQuery('/alerts', PREVIEW)),
    fetchList<Row>(withPageQuery('/assets', COUNT_ONLY)),
    fetchList<CaseRow>(withPageQuery('/cases', PREVIEW)),
    fetchList<CorrelationRow>(withPageQuery('/correlations', PREVIEW)),
    fetchList<VictimRow>(withPageQuery('/ransomware/victims', PREVIEW)),
    fetchList<Row>(withPageQuery('/agents', COUNT_ONLY)),
    fetchJson<FeedRow[]>('/feeds'),
  ]);

  const metrics: Metric[] = [
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities tracked',
      value: totalOf(vulnerabilities),
      basis: 'Reported total from the vulnerabilities endpoint.',
    },
    { id: 'alerts', label: 'Alerts raised', value: totalOf(alerts), basis: 'Reported total from the alerts endpoint.' },
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
    {
      id: 'correlations',
      label: 'Correlations produced',
      value: totalOf(correlations),
      basis: 'Reported total from the correlation engine.',
    },
    {
      id: 'agents',
      label: 'Agents enrolled',
      value: totalOf(agents),
      basis: 'Enrollment count only. It does not mean the agents are currently reporting.',
    },
  ];

  const feedRows = feeds.status === 'ok' ? feeds.data : [];
  const degraded = feedRows.filter((row) => row.status === 'failed' || row.status === 'never_run');

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
        columns={vulnerabilityColumns}
        rowKey={(row) => String(row.cve_id ?? row.id)}
        emptyTitle="No vulnerabilities recorded"
        emptyDetail="The API responded successfully and no vulnerability record exists for this tenant."
        caption="Unknown CVSS stays Unknown and is never treated as low risk. Absence from KEV means unproven exploitation, not safety."
      />

      <h2>Alerts awaiting triage</h2>
      <ResourceTable
        outcome={rowsOf(alerts)}
        columns={alertColumns}
        rowKey={(row) => row.id}
        emptyTitle="No alerts raised"
        emptyDetail="The API responded successfully and no alert has fired for this tenant."
        caption="Highest risk first. See the alert queue for the full list."
      />

      <h2>Recent correlations</h2>
      <ResourceTable
        outcome={rowsOf(correlations)}
        columns={correlationColumns}
        rowKey={(row) => row.id}
        emptyTitle="No correlations produced"
        emptyDetail="The correlation engine responded successfully and has produced no correlation for this tenant."
        caption="A correlation is a hypothesis linking records, not a confirmed incident."
      />

      <h2>Active cases</h2>
      <ResourceTable
        outcome={rowsOf(cases)}
        columns={caseColumns}
        rowKey={(row) => row.id}
        emptyTitle="No cases on record"
        emptyDetail="The API responded successfully and no case has been opened."
        caption="Five most recent cases. Case workflow state is owned by the case surface."
      />

      <h2>Latest ransomware claims</h2>
      <ResourceTable
        outcome={rowsOf(victims)}
        columns={victimColumns}
        rowKey={(row) => row.id}
        emptyTitle="No victim records"
        emptyDetail="The API responded successfully and no leak-site victim has been ingested."
        caption="Leak-site posts are attacker claims about other organisations, not findings about your estate."
      />

      <h2>Collection health</h2>
      {feeds.status === 'unavailable' ? (
        <p className="muted">Connector state could not be read: {feeds.reason}</p>
      ) : degraded.length > 0 ? (
        <p className="muted">
          {degraded.length} of {feedRows.length} connectors have failed or never run:{' '}
          {degraded.map((row) => unknown(row.source)).join(', ')}. Intelligence from those sources is missing rather than
          absent. See <Link href="/connectors">connectors</Link>.
        </p>
      ) : (
        <p className="muted">
          All {feedRows.length} registered connectors report a completed run. A completed run means records were
          accepted, not that the upstream source was complete.
        </p>
      )}

      <h2>What this dashboard does not show</h2>
      <p className="muted">
        There is no trend line, no posture score, and no time-series comparison. The platform does not retain the
        historical series those would require, and a shape drawn from a single snapshot invents a direction the data
        cannot support.
      </p>
    </section>
  );
}
