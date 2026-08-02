import { ApprovalTimeline } from '@/components/ApprovalTimeline';
import { StatusChip } from '@/components/StatusChip';
import { DemoDataBanner, EmptyState, FeatureGate } from '@/components/States';

const SUPPORTED_INTENTS = ['isolate_network', 'collect_inventory', 'rotate_agent_certificate'] as const;

/**
 * Control-plane request review only. This route intentionally exposes no shell
 * command input, no dispatch action, and no completion or delivery state.
 */
export default function EndpointIntentsPage() {
  return (
    <section className="content">
      <DemoDataBanner label="Endpoint intents are approval-only control-plane requests." />
      <h1>Endpoint intents</h1>
      <p className="muted">
        Delivery remains null until an approved backend capability exists. Requests stay{' '}
        <StatusChip label="Pending / not dispatched" tone="pending" /> regardless of approval outcome.
      </p>

      <FeatureGate
        title="Supported intent types"
        detail="Only allowlisted intents can be requested. Free-form commands are not representable in this UI."
      >
        <ul>
          {SUPPORTED_INTENTS.map((intent) => (
            <li key={intent}>
              <code>{intent}</code>
            </li>
          ))}
        </ul>
      </FeatureGate>

      <FeatureGate
        title="Approval policy"
        detail="Requester exclusion, two distinct approvers, expiry, and cancellation are enforced by the control plane."
      >
        <ApprovalTimeline events={[]} />
      </FeatureGate>

      <EmptyState
        title="No tenant intents available"
        detail="No tenant-scoped intent requests are available from the current API session."
      />
    </section>
  );
}
