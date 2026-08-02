import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type AuditEntry = { id: string; actor?: string | null; event_type?: string | null; detail?: Record<string, unknown> | null; event_at?: string | null };
type IntentDetail = {
  id?: string;
  agent_id?: string | null;
  intent_type?: string | null;
  state?: string | null;
  effective_state?: string | null;
  requested_by?: string | null;
  expires_at?: string | null;
  delivery_state?: string | null;
  audit_trail?: AuditEntry[];
};

export function generateMetadata({ params }: { params: { intentId: string } }): Metadata {
  return { title: `Intent ${params.intentId}` };
}

export default async function EndpointIntentDetailPage({ params }: { params: { intentId: string } }) {
  const outcome = await fetchJson<IntentDetail>(`/endpoint-intents/${encodeURIComponent(params.intentId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;
  const trail = record?.audit_trail ?? [];
  const state = record?.effective_state ?? record?.state;

  const fields: Field[] = record
    ? [
        { key: 'type', label: 'Intent type', value: unknown(record.intent_type) },
        { key: 'agent', label: 'Target agent', value: unknown(record.agent_id) },
        {
          key: 'state',
          label: 'Approval state',
          value:
            state === 'approved' ? (
              <StatusChip label="Approved" tone="approved" />
            ) : state === 'pending' ? (
              <StatusChip label="Awaiting second approver" tone="pending" />
            ) : (
              <StatusChip label={state ?? 'Unknown'} tone={state ? 'blocked' : 'unknown'} />
            ),
        },
        {
          key: 'delivery',
          label: 'Delivery state',
          value: <StatusChip label="Not dispatched" tone="blocked" />,
        },
        { key: 'requester', label: 'Requested by', value: unknown(record.requested_by) },
        { key: 'expires', label: 'Expires', value: unknown(record.expires_at) },
      ]
    : [];

  return (
    <DetailShell
      backHref="/endpoint-intents"
      backLabel="All endpoint intents"
      title={`${record?.intent_type ?? 'Endpoint intent'}`}
      intro="The audit trail below is append-only. Approvals are recorded per actor, an approver can never be the requester, and no route exists that would deliver this intent to the endpoint."
      outcome={outcome}
    >
      <FieldTable fields={fields} />
      <h2>Audit trail</h2>
      {trail.length === 0 ? (
        <p className="muted">No audit event has been recorded for this intent.</p>
      ) : (
        <ul className="timeline">
          {trail.map((entry) => (
            <li key={entry.id}>
              <strong>
                {unknown(entry.event_type)} · {unknown(entry.event_at)}
              </strong>
              <span>{unknown(entry.actor)}</span>
              {entry.detail && Object.keys(entry.detail).length > 0 ? (
                <span>
                  <small>{JSON.stringify(entry.detail)}</small>
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </DetailShell>
  );
}
