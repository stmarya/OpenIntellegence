import { UnavailableState } from '@/components/UnavailableState';

export default function DeveloperPortalPage() {
  return (
    <UnavailableState
      title="Developer portal and API keys"
      detail="Key issuance, scopes, rotation, and rate-limit usage require an authenticated session. Key material is shown once at creation by the API and is never rendered from local state."
    />
  );
}
