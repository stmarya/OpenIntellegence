import type { Metadata } from 'next';
import { FeatureGate } from '@/components/States';

export const metadata: Metadata = { title: 'Endpoint intents' };

const LIFECYCLE = [
  ['Requested', 'An analyst records an intent against one enrolled agent, with an explicit expiry.'],
  ['Approved', 'Two distinct approvers are required, and the requester cannot be one of them.'],
  ['Expired or cancelled', 'An intent past its expiry, or cancelled before approval, can never become approved.'],
  ['Not dispatched', 'Delivery state is fixed at not dispatched. No route exists that sends the intent to an endpoint.'],
] as const;

export default function EndpointIntentsPage() {
  return (
    <section className="content">
      <h1>Endpoint intents</h1>
      <p className="muted">
        This is an approval ledger, not a command channel. The platform records what someone wanted to do to an
        endpoint and who agreed to it, and stops there.
      </p>
      <ul className="timeline">
        {LIFECYCLE.map(([state, detail]) => (
          <li key={state}>
            <strong>{state}</strong>
            <span>{detail}</span>
          </li>
        ))}
      </ul>
      <FeatureGate
        title="No list endpoint exists yet"
        detail="Intent creation, approval, and cancellation exist in API v1, but there is no read route to list intents for a tenant. Rather than invent a queue, this surface stays empty until that endpoint ships."
      >
        <small>Allowed intents are network isolation, inventory collection, and agent certificate rotation.</small>
      </FeatureGate>
    </section>
  );
}
