import { UnavailableState } from '@/components/UnavailableState';

export default function EndpointAgentsPage() {
  return (
    <UnavailableState
      title="Endpoint agents"
      detail="Fleet health, heartbeat age, and certificate status require the agent gateway. A stale agent is reported as stale, never as healthy, so nothing is shown until the gateway responds."
    />
  );
}
