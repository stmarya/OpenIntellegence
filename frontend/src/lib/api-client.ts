export type ApiResult<T> = { data: T; source: 'api' } | { data: T; source: 'fallback' };

export class ApiClient {
  constructor(private readonly baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api/v1') {}

  async get<T>(path: string): Promise<ApiResult<T>> {
    const response = await fetch(`${this.baseUrl}${path}`, { credentials: 'include', headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`api_request_failed:${response.status}`);
    return { data: await response.json() as T, source: 'api' };
  }
}

// Authentication is intentionally delegated to same-origin session handling.
// Browser code must never receive, store, or construct platform API keys.
export const apiClient = new ApiClient();
