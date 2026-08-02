import { UnavailableState } from '@/components/UnavailableState';

export default function CampaignsPage() {
  return (
    <UnavailableState
      title="Campaigns"
      detail="Campaign records depend on the relationship graph between actors, malware, and victims, which is not populated in this build."
    />
  );
}
