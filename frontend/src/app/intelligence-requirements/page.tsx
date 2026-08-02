import { UnavailableState } from '@/components/UnavailableState';

export default function IntelligenceRequirementsPage() {
  return (
    <UnavailableState
      title="Intelligence requirements"
      detail="Requirements and their coverage gaps are defined per tenant. Without that data the console does not guess which questions the team cares about."
    />
  );
}
