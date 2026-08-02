import { UnavailableState } from '@/components/UnavailableState';

export default function SystemHealthPage() {
  return (
    <UnavailableState
      title="System health"
      detail="Component readiness comes from the health and readiness endpoints. An unreachable component is reported as unknown, never as healthy."
    />
  );
}
