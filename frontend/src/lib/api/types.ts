/**
 * Shared API types mirroring the backend OpenAPI schema.
 *
 * All types are derived from the backend contract; never fabricate security
 * data or mark unknown values safe.
 */

// ---------------------------------------------------------------------------
// Common shapes
// ---------------------------------------------------------------------------

export interface Provenance {
  generated_at: string;
  sources_included: string[];
  sources_degraded: string[];
  is_partial: boolean;
  note: string | null;
}

export interface Page {
  limit: number;
  offset: number;
  total: number;
  has_more: boolean;
}

export interface ListResponse<T> {
  data: T[];
  page: Page;
  provenance: Provenance;
}

export interface Citation {
  entity_type: string;
  entity_id: string;
  title: string;
  source: string | null;
  url: string | null;
}

// ---------------------------------------------------------------------------
// Typed UI states
// ---------------------------------------------------------------------------

export type RemoteState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "empty"; provenance?: Provenance }
  | { status: "partial"; data: T; provenance: Provenance; note: string }
  | { status: "ok"; data: T; provenance?: Provenance };

export function idle(): RemoteState<never> {
  return { status: "idle" };
}

export function loading(): RemoteState<never> {
  return { status: "loading" };
}

export function fromListResponse<T>(resp: ListResponse<T>): RemoteState<T[]> {
  if (resp.data.length === 0) {
    return { status: "empty", provenance: resp.provenance };
  }
  if (resp.provenance.is_partial) {
    return {
      status: "partial",
      data: resp.data,
      provenance: resp.provenance,
      note: resp.provenance.note ?? "Some feeds are degraded; data may be incomplete.",
    };
  }
  return { status: "ok", data: resp.data, provenance: resp.provenance };
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export interface Vulnerability {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: "low" | "medium" | "high" | "critical" | null;
  is_kev: boolean;
  kev_due_date: string | null;
  exploit_maturity: string | null;
  summary: string | null;
  affected_product_count: number;
  published_at: string | null;
  updated_at: string | null;
  affected_asset_count?: number;
}

export interface Asset {
  id: string;
  tenant_id: string;
  hostname: string | null;
  ip_address: string | null;
  os: string | null;
  os_version: string | null;
  criticality: "low" | "medium" | "high" | "critical";
  internet_exposed: boolean;
  exposed_cve_count: number;
  last_seen_at: string | null;
  agent_id: string | null;
  meta: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  rule_id: string | null;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "resolved" | "suppressed";
  fingerprint: string;
  entity_type: string | null;
  entity_id: string | null;
  triggered_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface Correlation {
  id: string;
  tenant_id: string;
  title: string;
  primary_entity_type: string;
  primary_entity_id: string;
  risk_score: number;
  risk_tier: "critical" | "high" | "medium" | "low";
  factors: Array<{
    key: string;
    label: string;
    points: number;
    state: "present" | "unknown";
  }>;
  automation_candidates: Array<{ action: string; label: string }>;
  evaluated_at: string;
  ai_brief_id: string | null;
}

export interface Investigation {
  id: string;
  tenant_id: string;
  title: string;
  status: "open" | "in_progress" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  summary: string | null;
  created_at: string;
  updated_at: string;
}

export interface Playbook {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  trigger_type: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: string;
  tenant_id: string;
  title: string;
  report_type: string;
  status: "pending" | "generating" | "ready" | "failed";
  requested_by: string;
  created_at: string;
  completed_at: string | null;
  content_url: string | null;
}

export interface ThreatActor {
  canonical_name: string;
  aliases: string[];
  motivation: string | null;
  sophistication: string | null;
  description: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface AiChatResponse {
  answer: string;
  citations: Citation[];
  model_used: string | null;
  is_partial: boolean;
}
