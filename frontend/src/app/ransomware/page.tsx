import { UnavailableState } from '@/components/UnavailableState';

export default function RansomwarePage() {
  return (
    <UnavailableState
      title="Ransomware intelligence"
      detail="Victim, group, and leak-site records require the ransomware collection API. The bundled snapshot contains vulnerability and research-reference data only, so no victim counts are shown."
    />
  );
}
