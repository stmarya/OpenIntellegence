import { UnavailableState } from '@/components/UnavailableState';

export default function ThreatActorsPage() {
  return (
    <UnavailableState
      title="Threat actors"
      detail="Actor profiles, attribution confidence, and technique coverage require the tenant-scoped intelligence API. Attribution is never inferred by the console itself."
    />
  );
}
