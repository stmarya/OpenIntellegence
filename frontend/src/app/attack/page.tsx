import { UnavailableState } from '@/components/UnavailableState';

export default function AttackCoveragePage() {
  return (
    <UnavailableState
      title="ATT&CK coverage"
      detail="Technique coverage is computed from observed detections and mapped intelligence. Neither source is connected, so no coverage percentage is displayed."
    />
  );
}
