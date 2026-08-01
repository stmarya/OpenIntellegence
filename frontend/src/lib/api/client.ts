/**
 * HTTP API client for the OpenIntelligence backend.
 *
 * When NEXT_PUBLIC_API_BASE is not set, or when an endpoint is not yet live,
 * the mock adapter is used automatically so the frontend can be developed
 * and demoed without a running backend.
 *
 * Security contract:
 *   - Never fabricate security data.
 *   - Never mark unknown values as safe.
 *   - Empty or partial responses are reported as-is, not filled with defaults.
 */

import type {
  AiChatResponse,
  Alert,
  Asset,
  Correlation,
  Investigation,
  ListResponse,
  Playbook,
  Report,
  ThreatActor,
  Vulnerability,
} from "./types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

// ---------------------------------------------------------------------------
// Low-level fetch wrapper
// ---------------------------------------------------------------------------

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiFetch<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}/api/v1${path}`;
  const key = typeof window !== "undefined"
    ? (sessionStorage.getItem("oi_api_key") ?? "")
    : "";

  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {}),
      ...(init.headers ?? {}),
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Resource-specific clients
// ---------------------------------------------------------------------------

export const vulnerabilitiesApi = {
  list(params?: {
    limit?: number;
    offset?: number;
    kev_only?: boolean;
    min_cvss?: number;
  }): Promise<ListResponse<Vulnerability>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.kev_only) q.set("kev_only", "true");
    if (params?.min_cvss != null) q.set("min_cvss", String(params.min_cvss));
    return apiFetch(`/vulnerabilities?${q}`);
  },
};

export const assetsApi = {
  list(params?: { limit?: number; offset?: number }): Promise<ListResponse<Asset>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return apiFetch(`/assets?${q}`);
  },
};

export const alertsApi = {
  list(params?: {
    limit?: number;
    offset?: number;
    status?: string;
    severity?: string;
  }): Promise<ListResponse<Alert>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.status) q.set("status", params.status);
    if (params?.severity) q.set("severity", params.severity);
    return apiFetch(`/alerts?${q}`);
  },
};

export const correlationsApi = {
  list(params?: { limit?: number; offset?: number; risk_tier?: string }): Promise<ListResponse<Correlation>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.risk_tier) q.set("risk_tier", params.risk_tier);
    return apiFetch(`/correlations?${q}`);
  },
};

export const investigationsApi = {
  list(params?: { limit?: number; offset?: number }): Promise<ListResponse<Investigation>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return apiFetch(`/investigations?${q}`);
  },
};

export const playbooksApi = {
  list(params?: { limit?: number; offset?: number }): Promise<ListResponse<Playbook>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return apiFetch(`/playbooks?${q}`);
  },
};

export const reportsApi = {
  list(params?: { limit?: number; offset?: number }): Promise<ListResponse<Report>> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    return apiFetch(`/reports?${q}`);
  },
};

export const threatActorsApi = {
  get(canonicalName: string): Promise<ThreatActor> {
    return apiFetch(`/actors/${encodeURIComponent(canonicalName)}`);
  },
};

export const aiApi = {
  query(question: string, topK = 12): Promise<AiChatResponse> {
    return apiFetch("/chat/query", {
      method: "POST",
      body: JSON.stringify({ question, top_k: topK }),
    });
  },
};

export { ApiError };
