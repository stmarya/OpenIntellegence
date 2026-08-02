/**
 * Page-state helpers for list surfaces.
 *
 * The point of this module is not navigation convenience. It is that a
 * truncated list must announce its own truncation. A console that shows the
 * first fifty rows of three hundred, with no total and no control, invites
 * the reader to treat a page as the whole population.
 */

import type { FetchOutcome, ListEnvelope } from '@/lib/server-fetch';

export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 200;

export type SearchParams = Record<string, string | string[] | undefined>;

export interface PageState {
  limit: number;
  offset: number;
}

export interface PageMeta {
  limit: number;
  offset: number;
  total: number;
  has_more: boolean;
}

function readInt(value: string | string[] | undefined): number | null {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined || raw === '') return null;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Resolve the requested page from the URL, clamping hostile or malformed
 * input rather than passing it through to the API.
 */
export function readPageState(
  searchParams?: SearchParams,
  defaultLimit: number = DEFAULT_LIMIT
): PageState {
  const limit = readInt(searchParams?.limit);
  const offset = readInt(searchParams?.offset);
  return {
    limit: limit === null ? defaultLimit : Math.min(Math.max(limit, 1), MAX_LIMIT),
    offset: offset === null || offset < 0 ? 0 : offset,
  };
}

/** Append page parameters to an API path, preserving any existing query. */
export function withPageQuery(path: string, state: PageState): string {
  const separator = path.includes('?') ? '&' : '?';
  return `${path}${separator}limit=${state.limit}&offset=${state.offset}`;
}

/** Build a console href for a given page of the same surface. */
export function pageHref(basePath: string, limit: number, offset: number): string {
  const separator = basePath.includes('?') ? '&' : '?';
  return `${basePath}${separator}limit=${limit}&offset=${Math.max(offset, 0)}`;
}

/** Read page metadata from a list envelope, or null when the API omitted it. */
export function pageMetaOf<T>(outcome: FetchOutcome<ListEnvelope<T>>): PageMeta | null {
  if (outcome.status !== 'ok') return null;
  const page = outcome.data.page;
  if (!page) return null;
  const { limit, offset, total, has_more } = page;
  if (typeof limit !== 'number' || typeof offset !== 'number' || typeof total !== 'number') {
    return null;
  }
  return { limit, offset, total, has_more: Boolean(has_more) };
}

/**
 * Describe the visible slice in plain language.
 *
 * The wording avoids implying that the visible rows are the whole set unless
 * the numbers actually say so.
 */
export function describeRange(meta: PageMeta, rowCount: number): string {
  if (meta.total === 0) return 'No records in this collection.';
  const first = meta.offset + 1;
  const last = meta.offset + rowCount;
  if (meta.total <= rowCount && meta.offset === 0) {
    return `Showing all ${meta.total} records.`;
  }
  return `Showing ${first}\u2013${last} of ${meta.total} records.`;
}
