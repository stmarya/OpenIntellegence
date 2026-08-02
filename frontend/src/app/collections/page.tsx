import { UnavailableState } from '@/components/UnavailableState';

export default function CollectionsPage() {
  return (
    <UnavailableState
      title="Collections"
      detail="Collections and sharing groups carry distribution policy, so they are only rendered from tenant-scoped data with an explicit sharing level."
    />
  );
}
