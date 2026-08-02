import { UnavailableState } from '@/components/UnavailableState';

export default function SoftwareInventoryPage() {
  return (
    <UnavailableState
      title="Software inventory"
      detail="Installed-software records come from enrolled endpoint agents. No agent is enrolled in this build, and vendor names from the public vulnerability snapshot are not treated as installed software."
    />
  );
}
