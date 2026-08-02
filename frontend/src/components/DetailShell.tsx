import type { ReactNode } from 'react';
import Link from 'next/link';
import { FeatureGate } from '@/components/States';
import type { FetchOutcome } from '@/lib/server-fetch';

/**
 * Shared frame for entity detail routes. Keeps the back link, heading, and
 * failure explanation identical across entity types.
 */
export function DetailShell({
  backHref,
  backLabel,
  title,
  intro,
  outcome,
  children,
}: {
  backHref: string;
  backLabel: string;
  title: string;
  intro: string;
  outcome: FetchOutcome<unknown>;
  children: ReactNode;
}) {
  return (
    <section className="content">
      <p className="muted">
        <Link href={backHref}>← {backLabel}</Link>
      </p>
      <h1>{title}</h1>
      <p className="muted">{intro}</p>
      {outcome.status === 'unavailable' ? (
        <FeatureGate title="This record could not be loaded" detail={outcome.reason}>
          <small>Nothing is reconstructed from cache or sample data in place of the real record.</small>
        </FeatureGate>
      ) : (
        children
      )}
    </section>
  );
}
