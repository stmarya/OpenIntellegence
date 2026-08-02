import Link from 'next/link';
import { EmptyState } from '@/components/States';

export default function NotFound() {
  return (
    <section className="content">
      <h1>Surface not found</h1>
      <EmptyState
        title="No console surface matches this address"
        detail="This is a routing result, not a statement about your data. Nothing was queried, so nothing here implies the record is absent."
      />
      <p className="muted">
        <Link href="/overview">Return to the command center</Link>
      </p>
    </section>
  );
}
