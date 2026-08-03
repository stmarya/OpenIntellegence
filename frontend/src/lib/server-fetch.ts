import 'server-only';

export type FetchOutcome<T> = { status: 'ok'; data: T } | { status: 'unavailable'; reason: string };
export interface ListEnvelope<T> {
  data?: T[];
  page?: { limit: number; offset: number; total: number; has_more: boolean };
  provenance?: { note?: string | null } | null;
}

const BASE_URL = process.env.API_BASE_URL ?? process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api/v1';
const SERVICE_KEY = process.env.API_SERVICE_KEY;

export async function fetchJson<T>(path: string): Promise<FetchOutcome<T>> {
  if (!/^https?:\/\//.test(BASE_URL)) return { status: 'unavailable', reason: `No absolute API origin is configured, so ${path} was never requested.` };
  if (!SERVICE_KEY) return { status: 'unavailable', reason: `No server-only API_SERVICE_KEY is configured, so ${path} was never requested.` };
  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, { headers: { Accept: 'application/json', 'X-API-Key': SERVICE_KEY }, cache: 'no-store' });
  } catch {
    return { status: 'unavailable', reason: `The intelligence API at ${BASE_URL} could not be reached for ${path}.` };
  }
  if (response.status === 401 || response.status === 403) return { status: 'unavailable', reason: `The intelligence API refused ${path} with HTTP ${response.status}; no data is rendered.` };
  if (!response.ok) return { status: 'unavailable', reason: `The intelligence API answered HTTP ${response.status} for ${path}.` };
  try { return { status: 'ok', data: (await response.json()) as T }; }
  catch { return { status: 'unavailable', reason: `The response for ${path} was not valid JSON.` }; }
}
export function fetchList<T>(path: string): Promise<FetchOutcome<ListEnvelope<T>>> { return fetchJson<ListEnvelope<T>>(path); }
export function mapOutcome<A, B>(outcome: FetchOutcome<A>, transform: (value: A) => B): FetchOutcome<B> { return outcome.status === 'ok' ? { status: 'ok', data: transform(outcome.data) } : outcome; }
export function rowsOf<T>(outcome: FetchOutcome<ListEnvelope<T>>): FetchOutcome<T[]> { return mapOutcome(outcome, (envelope) => envelope.data ?? []); }
export function noteOf<T>(outcome: FetchOutcome<ListEnvelope<T>>): string | null { return outcome.status === 'ok' ? outcome.data.provenance?.note ?? null : null; }
export function unknown(value: string | number | null | undefined): string { return value === null || value === undefined || value === '' ? 'Unknown' : String(value); }
