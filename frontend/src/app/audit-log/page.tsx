import { UnavailableState } from '@/components/UnavailableState';

export default function AuditLogPage() {
  return (
    <UnavailableState
      title="Audit log"
      detail="Audit entries are immutable tenant records. Showing sample entries here would undermine the exact guarantee the log exists to provide, so the surface stays empty until the API is connected."
    />
  );
}
