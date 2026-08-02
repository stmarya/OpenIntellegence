/**
 * Minimal same-origin JSON client for client components.
 *
 * There is deliberately no fallback or substitute-data path. An earlier version
 * of ApiResult advertised a 'fallback' source that nothing ever produced; a
 * result type that names a degraded-data path invites later code to quietly
 * serve stand-in records under it. A failed request throws, and the caller is
 * responsible for saying that the data is unavailable rather than rendering an
 * empty or invented state.
 *
 * Server components should use lib/server-fetch instead, which distinguishes an
 * outage from a genuinely empty result.
 */
export type ApiResult<T> = { data: T; source: 'api' };

export class ApiClient {
  constructor(private readonly baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api/v1') {}

  async get<T>(path: string): Promise<ApiResult<T>> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`api_request_failed:${response.status}`);
    return { data: (await response.json()) as T, source: 'api' };
  }
}

// Authentication is intentionally delegated to same-origin session handling.
// Browser code must never receive, store, or construct platform API keys.
export const apiClient = new ApiClient();
