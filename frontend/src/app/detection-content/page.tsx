import { UnavailableState } from '@/components/UnavailableState';

export default function DetectionContentPage() {
  return (
    <UnavailableState
      title="Detection content"
      detail="Detection rules and their deployment status require the detection service. This surface never deploys or executes a rule on an endpoint."
    />
  );
}
