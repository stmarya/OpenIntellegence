import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Alert' };

type Alert = {
  id: string;
  title?: string | null;
  summary?: string | null;
  severity?: string | null;
  status?: string | null;
  entity_type?: string | null;
  entity_id?: string | null;
  risk_score?: number | null;
  occurrences?: number | null;
  first_triggered_at?: string | null;
  last_triggered_at?: string | null;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
};

type Rule = {
  id: string;
  name?: string | null;
  trigger_type?: string | null;
  severity?: string | null;
  cooldown_minutes?: number | null;
  enabled?: boolean | null;
};

type Sighting = {
  id: string;
  source: string;
  observed_at: string;
  asset_id?: string | null;
  confidence?: number | null;
};

type AlertDetail = {
  alert: Alert;
  rule?: Rule | null;
  sightings: Sighting[];
  rule_basis: string;
  sighting_match_basis: string;
};

const sightingColumns: Column<Sighting>[] = [
  { key: 'observed', header: 'Observed at', render: (row) => <>{unknown(row.observed_at)}</> },
  { key: 'source', header: 'Reported by', render: (row) => <>{unknown(row.source)}</> },
  { key: 'asset', header: 'Asset', render: (row) => <small>{row.asset_id ?? 'No asset attributed'}</small> },
  { key: 'confidence', header: 'Confidence', render: (row) => <>{row.confidence ?? 'Unknown'}</> },
];

export default async function AlertDetailPage({ params }: { params: { alertId: string } }) {
  const outcome = await fetchJson<AlertDetail>(`/alerts/${encodeURIComponent(params.alertId)}`);
  const detail = outcome.status === 'ok' ? outcome.data : null;

  return (
    <DetailShell
      backHref="/alerts"
      backLabel="Back to alerts"
      title={detail ? unknown(detail.alert.title) : 'Alert'}
      intro="One alert, the rule that raised it, and the sightings that share its entity reference."
      outcome={outcome}
    >
      {detail ? (
        <>
          <FieldTable
            caption="Occurrence count reflects repeat triggers folded into this alert rather than duplicate rows."
            fields={[
              { key: 'summary', label: 'Summary', value: detail.alert.summary ?? 'No summary recorded.' },
              {
                key: 'severity',
                label: 'Severity',
                value: detail.alert.severity ? (
                  <StatusChip
                    label={detail.alert.severity}
                    tone={
                      detail.alert.severity === 'critical' || detail.alert.severity === 'high'
                        ? 'blocked'
                        : 'neutral'
                    }
                  />
                ) : (
                  <StatusChip label="Unknown" tone="unknown" />
                ),
              },
              {
                key: 'status',
                label: 'Triage state',
                value:
                  detail.alert.status === 'acknowledged' ? (
                    <StatusChip label="Acknowledged" tone="approved" />
                  ) : (
                    <StatusChip label={detail.alert.status ?? 'open'} tone="pending" />
                  ),
              },
              { key: 'risk', label: 'Risk score', value: detail.alert.risk_score ?? 'Unknown' },
              {
                key: 'entity',
                label: 'Entity',
                value: detail.alert.entity_id
                  ? `${unknown(detail.alert.entity_type)} \u00b7 ${detail.alert.entity_id}`
                  : 'No entity reference recorded',
              },
              { key: 'occurrences', label: 'Occurrences', value: detail.alert.occurrences ?? 'Unknown' },
              { key: 'first', label: 'First triggered', value: unknown(detail.alert.first_triggered_at) },
              { key: 'last', label: 'Last triggered', value: unknown(detail.alert.last_triggered_at) },
              {
                key: 'acknowledged',
                label: 'Acknowledged',
                value: detail.alert.acknowledged_at
                  ? `${detail.alert.acknowledged_at} by ${unknown(detail.alert.acknowledged_by)}`
                  : 'Not acknowledged',
              },
            ]}
          />

          <h2>Triggering rule</h2>
          <p className="muted">{detail.rule_basis}</p>
          {detail.rule ? (
            <FieldTable
              fields={[
                { key: 'name', label: 'Rule', value: unknown(detail.rule.name) },
                { key: 'trigger', label: 'Trigger type', value: unknown(detail.rule.trigger_type) },
                { key: 'severity', label: 'Rule severity', value: unknown(detail.rule.severity) },
                {
                  key: 'cooldown',
                  label: 'Cooldown',
                  value: detail.rule.cooldown_minutes ? `${detail.rule.cooldown_minutes} minutes` : 'Unknown',
                },
                {
                  key: 'enabled',
                  label: 'Enabled',
                  value: detail.rule.enabled ? 'Yes' : 'No',
                },
              ]}
            />
          ) : null}

          <h2>Related sightings</h2>
          <p className="muted">{detail.sighting_match_basis}</p>
          {detail.sightings.length > 0 ? (
            <DataTable
              columns={sightingColumns}
              rows={detail.sightings}
              rowKey={(row) => row.id}
              caption="Sightings are reported observations tied to this alert's entity reference."
            />
          ) : (
            <p className="muted">No sighting shares this alert&apos;s entity reference.</p>
          )}

          <p className="muted">
            Acknowledgement is a write action and is not offered here. The console is read-only until write surfaces
            land, and an inert button would imply an authority this session does not have.
          </p>
        </>
      ) : null}
    </DetailShell>
  );
}
