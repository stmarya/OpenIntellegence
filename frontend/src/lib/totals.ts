import type { FetchOutcome, ListEnvelope } from '@/lib/server-fetch';

/**
 * Reads the authoritative record count from a list envelope.
 *
 * Returns null when the API could not be reached or did not report a total.
 * Null is not zero: a headline figure that silently degrades to 0 during an
 * outage would tell an executive the environment is quiet when it is actually
 * unobserved.
 */
export function totalOf<T>(outcome: FetchOutcome<ListEnvelope<T>>): number | null {
  if (outcome.status !== 'ok') return null;
  const total = outcome.data.page?.total;
  return typeof total === 'number' ? total : null;
}

export function reasonOf(outcome: FetchOutcome<unknown>): string | null {
  return outcome.status === 'unavailable' ? outcome.reason : null;
}
