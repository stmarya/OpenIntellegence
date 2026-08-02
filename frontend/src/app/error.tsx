'use client';

import { useEffect } from 'react';
import { ErrorState } from '@/components/States';

/**
 * Route-level failure boundary.
 *
 * The surface is emptied rather than partially rendered, because a half-drawn
 * security view invites the reader to draw a conclusion from data that was
 * never fully loaded.
 */
export default function RouteError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error('Console route failed to render', error);
  }, [error]);

  return (
    <section className="content">
      <ErrorState
        title="This surface failed to render"
        detail="No partial or cached view is shown in its place. Treat this area as unobserved rather than clear, and retry once the underlying service responds."
      />
      <p className="muted">
        <button type="button" onClick={reset}>
          Retry this surface
        </button>
      </p>
      {error.digest ? (
        <p className="muted">
          <small>Error digest: {error.digest}</small>
        </p>
      ) : null}
    </section>
  );
}
