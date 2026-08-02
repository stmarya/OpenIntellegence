import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { FeatureGate } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'System health' };

type Component = {
  component: string;
  state?: string | null;
  observation?: string | null;
  detail?: string | null;
};

type HealthPayload = {
  components?: Component[];
  note?: string | null;
  generated_at?: string | null;
};

const columns: Column<Component>[] = [
  { key: 'component', header: 'Component', render: (row) => <strong>{unknown(row.component)}</strong> },
  {
    key: 'state',
    header: 'State',
    render: (row) =>
      row.state === 'reachable' ? (
        <StatusChip label="Reachable" tone="approved" />
      ) : row.state === 'unreachable' ? (
        <StatusChip label="Unreachable" tone="blocked" />
      ) : row.state === 'configured' ? (
        <StatusChip label="Configured, not probed" tone="unknown" />
      ) : (
        <StatusChip label={row.state ?? 'Unknown'} tone="unknown" />
      ),
  },
  {
    key: 'observation',
    header: 'Basis',
    render: (row) =>
      row.observation === 'probed' ? (
        <StatusChip label="Probed this request" tone="neutral" />
      ) : (
        <StatusChip label="Read from configuration" tone="unknown" />
      ),
  },
  { key: 'detail', header: 'Detail', render: (row) => <small>{row.detail ?? 'No detail recorded.'}</small> },
];

/**
 * Platform component state.
 *
 * This page previously rendered the ingestion feed table, which describes
 * connector runs rather than platform components. Connector state now lives
 * solely on the connector surface, and this page reports what was actually
 * probed.
 */
export default async function SystemHealthPage() {
  const outcome = await fetchJson<HealthPayload>('/system-health');

  if (outcome.status === 'unavailable') {
    return (
      <section className="content">
        <h1>System health</h1>
        <FeatureGate title="Health could not be established" detail={outcome.reason}>
          <small>
            An unanswered health check is reported as unknown. It is never rendered as a healthy system, because that is
            precisely the failure mode this page exists to catch.
          </small>
        </FeatureGate>
      </section>
    );
  }

  const components = outcome.data.components ?? [];

  return (
    <section className="content">
      <h1>System health</h1>
      <p className="muted">
        A component is only called reachable when this request contacted it. Components read from configuration are
        marked as such, because being configured says nothing about being available.
      </p>
      {components.length > 0 ? (
        <DataTable
          columns={columns}
          rows={components}
          rowKey={(row) => row.component}
          caption="Probed and declared states are deliberately distinguished."
        />
      ) : (
        <p className="muted">The health endpoint reported no component, which is itself a gap in instrumentation.</p>
      )}
      <p className="muted">{outcome.data.note}</p>
      <p className="muted">
        Ingestion connector runs are reported on the <Link href="/connectors">connector surface</Link> and are not
        repeated here. Checked at {unknown(outcome.data.generated_at)}.
      </p>
    </section>
  );
}
