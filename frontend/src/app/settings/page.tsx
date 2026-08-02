import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { FieldTable, type Field } from '@/components/FieldTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { FeatureGate } from '@/components/States';
import { fetchJson, mapOutcome, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Settings' };

type Capability = { action: string; available?: boolean | null; delivery_mode?: string | null; reason?: string | null };
type PolicySettings = {
  tenant_id?: string | null;
  policy?: {
    grantable_api_key_scopes?: string[];
    allowed_endpoint_intents?: string[];
    endpoint_command_delivery?: string;
    required_intent_approvers?: number;
    requester_may_approve?: boolean;
    non_replayable_actions?: string[];
  };
  automation_capabilities?: Capability[];
  generated_at?: string | null;
};

const capabilityColumns: Column<Capability>[] = [
  { key: 'action', header: 'Action', render: (row) => <strong>{row.action}</strong> },
  {
    key: 'available',
    header: 'Configured',
    render: (row) =>
      row.available ? (
        <StatusChip label="Configured" tone="approved" />
      ) : (
        <StatusChip label="Not configured" tone="unknown" />
      ),
  },
  { key: 'delivery', header: 'Delivery mode', render: (row) => <>{unknown(row.delivery_mode)}</> },
];

export default async function SettingsPage() {
  const outcome = await fetchJson<PolicySettings>('/settings');

  if (outcome.status === 'unavailable') {
    return (
      <section className="content">
        <h1>Settings</h1>
        <FeatureGate title="Policy settings unavailable" detail={outcome.reason}>
          <small>No assumed defaults are displayed, because a wrong policy value is worse than no policy value.</small>
        </FeatureGate>
      </section>
    );
  }

  const policy = outcome.data.policy ?? {};
  const fields: Field[] = [
    { key: 'tenant', label: 'Tenant', value: unknown(outcome.data.tenant_id) },
    {
      key: 'scopes',
      label: 'Grantable API key scopes',
      value: policy.grantable_api_key_scopes?.join(', ') ?? 'Unknown',
    },
    {
      key: 'intents',
      label: 'Allowed endpoint intents',
      value: policy.allowed_endpoint_intents?.join(', ') ?? 'Unknown',
    },
    {
      key: 'approvers',
      label: 'Approvers required per intent',
      value: policy.required_intent_approvers ?? 'Unknown',
    },
    {
      key: 'self-approve',
      label: 'Requester may approve own intent',
      value: policy.requester_may_approve ? 'Yes' : 'No',
    },
    {
      key: 'delivery',
      label: 'Endpoint command delivery',
      value: <StatusChip label={unknown(policy.endpoint_command_delivery)} tone="blocked" />,
    },
    {
      key: 'non-replayable',
      label: 'Actions that can never be replayed',
      value: policy.non_replayable_actions?.join(', ') ?? 'Unknown',
    },
  ];

  return (
    <section className="content">
      <h1>Settings</h1>
      <p className="muted">
        These are the decisions the platform enforces, read from the running configuration. No credential or connection
        string is exposed here, and capability state is derived from configuration without probing any external system.
      </p>
      <FieldTable fields={fields} caption="Policy values are read from the API, never assumed by the console." />
      <h2>Automation capabilities</h2>
      <ResourceTable
        outcome={mapOutcome(outcome, (payload) => payload.automation_capabilities ?? [])}
        columns={capabilityColumns}
        rowKey={(row) => row.action}
        emptyTitle="No automation action registered"
        emptyDetail="The API responded successfully and no automation action is registered."
      />
    </section>
  );
}
