import { UnavailableState } from '@/components/UnavailableState';

export default function SettingsPage() {
  return (
    <UnavailableState
      title="Settings"
      detail="Tenant configuration, roles, and retention policy require an authenticated administrative session that this build does not establish."
    />
  );
}
