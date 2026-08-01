/**
 * Mock / dev API adapter.
 *
 * Returns deterministic fixture data so every page can be developed and
 * reviewed without a running backend. Switch to the real client by
 * setting NEXT_PUBLIC_USE_MOCK=false (or simply unset).
 *
 * Security rule: fixtures never mark unknowns as safe.  CVSS scores that
 * are unknown stay null; severity that is unknown is omitted.
 */

import type {
  AiChatResponse,
  Alert,
  Asset,
  Correlation,
  Investigation,
  ListResponse,
  Playbook,
  Provenance,
  Report,
  Vulnerability,
} from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockProvenance(partial = false): Provenance {
  return {
    generated_at: new Date().toISOString(),
    sources_included: partial
      ? ["nvd", "ransomware_live"]
      : ["nvd", "ransomware_live", "otx", "ransomlook"],
    sources_degraded: partial ? ["otx", "ransomlook"] : [],
    is_partial: partial,
    note: partial
      ? "Partial data. These feeds did not contribute to this response: otx, ransomlook."
      : null,
  };
}

function mockList<T>(data: T[], partial = false): ListResponse<T> {
  return {
    data,
    page: { limit: 50, offset: 0, total: data.length, has_more: false },
    provenance: mockProvenance(partial),
  };
}

// ---------------------------------------------------------------------------
// Vulnerability fixtures
// ---------------------------------------------------------------------------

const MOCK_VULNERABILITIES: Vulnerability[] = [
  {
    id: "vuln-001",
    cve_id: "CVE-2024-3094",
    cvss_score: 10.0,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    severity: "critical",
    is_kev: true,
    kev_due_date: "2024-04-12",
    exploit_maturity: "active",
    summary: "XZ Utils supply-chain backdoor allowing remote code execution.",
    affected_product_count: 12,
    published_at: "2024-03-29T00:00:00Z",
    updated_at: "2024-04-01T00:00:00Z",
    affected_asset_count: 3,
  },
  {
    id: "vuln-002",
    cve_id: "CVE-2024-21762",
    cvss_score: 9.8,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    severity: "critical",
    is_kev: true,
    kev_due_date: "2024-03-05",
    exploit_maturity: "weaponized",
    summary: "Fortinet FortiOS out-of-bounds write in SSL VPN.",
    affected_product_count: 4,
    published_at: "2024-02-09T00:00:00Z",
    updated_at: "2024-02-20T00:00:00Z",
    affected_asset_count: 1,
  },
  {
    id: "vuln-003",
    cve_id: "CVE-2024-27198",
    cvss_score: 9.8,
    cvss_vector: null,
    severity: "critical",
    is_kev: false,
    kev_due_date: null,
    exploit_maturity: "poc",
    summary: "TeamCity authentication bypass allowing unauthorised access.",
    affected_product_count: 2,
    published_at: "2024-03-04T00:00:00Z",
    updated_at: null,
    affected_asset_count: 0,
  },
];

// ---------------------------------------------------------------------------
// Asset fixtures
// ---------------------------------------------------------------------------

const MOCK_ASSETS: Asset[] = [
  {
    id: "asset-001",
    tenant_id: "tenant-dev",
    hostname: "web-prod-01.internal",
    ip_address: "10.0.1.50",
    os: "Ubuntu",
    os_version: "22.04.3 LTS",
    criticality: "critical",
    internet_exposed: true,
    exposed_cve_count: 2,
    last_seen_at: new Date(Date.now() - 60_000).toISOString(),
    agent_id: "agent-abc",
    meta: {},
    created_at: "2024-01-01T00:00:00Z",
    updated_at: new Date().toISOString(),
  },
  {
    id: "asset-002",
    tenant_id: "tenant-dev",
    hostname: "db-primary.internal",
    ip_address: "10.0.2.10",
    os: "RHEL",
    os_version: "9.3",
    criticality: "high",
    internet_exposed: false,
    exposed_cve_count: 1,
    last_seen_at: new Date(Date.now() - 300_000).toISOString(),
    agent_id: "agent-def",
    meta: { department: "Platform" },
    created_at: "2024-01-15T00:00:00Z",
    updated_at: new Date().toISOString(),
  },
];

// ---------------------------------------------------------------------------
// Alert fixtures
// ---------------------------------------------------------------------------

const MOCK_ALERTS: Alert[] = [
  {
    id: "alert-001",
    tenant_id: "tenant-dev",
    rule_id: "rule-001",
    title: "KEV exposure on internet-facing host",
    severity: "critical",
    status: "open",
    fingerprint: "fp-001",
    entity_type: "asset",
    entity_id: "asset-001",
    triggered_at: new Date(Date.now() - 3_600_000).toISOString(),
    acknowledged_at: null,
    resolved_at: null,
  },
  {
    id: "alert-002",
    tenant_id: "tenant-dev",
    rule_id: "rule-002",
    title: "Feed degraded: otx unavailable",
    severity: "medium",
    status: "acknowledged",
    fingerprint: "fp-002",
    entity_type: null,
    entity_id: null,
    triggered_at: new Date(Date.now() - 7_200_000).toISOString(),
    acknowledged_at: new Date(Date.now() - 3_600_000).toISOString(),
    resolved_at: null,
  },
];

// ---------------------------------------------------------------------------
// Correlation fixtures
// ---------------------------------------------------------------------------

const MOCK_CORRELATIONS: Correlation[] = [
  {
    id: "corr-001",
    tenant_id: "tenant-dev",
    title: "CVE-2024-3094 on internet-exposed critical asset",
    primary_entity_type: "vulnerability",
    primary_entity_id: "vuln-001",
    risk_score: 85,
    risk_tier: "critical",
    factors: [
      { key: "cvss", label: "CVSS 10.0", points: 20, state: "present" },
      { key: "kev", label: "Known Exploited Vulnerability", points: 25, state: "present" },
      { key: "internet_exposure", label: "Internet-exposed asset", points: 15, state: "present" },
    ],
    automation_candidates: [
      { action: "slack.notify", label: "Notify Slack" },
      { action: "jira.issue.create", label: "Create Jira ticket" },
    ],
    evaluated_at: new Date().toISOString(),
    ai_brief_id: null,
  },
];

// ---------------------------------------------------------------------------
// Investigation (case) fixtures
// ---------------------------------------------------------------------------

const MOCK_INVESTIGATIONS: Investigation[] = [
  {
    id: "inv-001",
    tenant_id: "tenant-dev",
    title: "XZ supply chain — scope assessment",
    status: "in_progress",
    severity: "critical",
    summary: "Determining blast radius of XZ backdoor across infra.",
    created_at: "2024-03-30T08:00:00Z",
    updated_at: new Date().toISOString(),
  },
];

// ---------------------------------------------------------------------------
// Playbook fixtures
// ---------------------------------------------------------------------------

const MOCK_PLAYBOOKS: Playbook[] = [
  {
    id: "pb-001",
    tenant_id: "tenant-dev",
    name: "KEV Triage",
    description: "Notify on-call, create Jira ticket, and suppress duplicate alerts.",
    trigger_type: "kev_exposure",
    enabled: true,
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-03-01T00:00:00Z",
  },
];

// ---------------------------------------------------------------------------
// Report fixtures
// ---------------------------------------------------------------------------

const MOCK_REPORTS: Report[] = [
  {
    id: "rep-001",
    tenant_id: "tenant-dev",
    title: "Weekly Threat Summary — W13 2024",
    report_type: "weekly_threat_summary",
    status: "ready",
    requested_by: "analyst@example.internal",
    created_at: "2024-04-01T06:00:00Z",
    completed_at: "2024-04-01T06:12:00Z",
    content_url: null,
  },
];

// ---------------------------------------------------------------------------
// Public mock API
// ---------------------------------------------------------------------------

// Simulated network latency (ms) — keeps UX behaviour close to production.
const LATENCY = 200;

const delay = () => new Promise((r) => setTimeout(r, LATENCY));

export const mockApi = {
  async vulnerabilities(): Promise<ListResponse<Vulnerability>> {
    await delay();
    return mockList(MOCK_VULNERABILITIES);
  },

  async assets(): Promise<ListResponse<Asset>> {
    await delay();
    return mockList(MOCK_ASSETS);
  },

  async alerts(): Promise<ListResponse<Alert>> {
    await delay();
    return mockList(MOCK_ALERTS, true); // partial: show provenance banner
  },

  async correlations(): Promise<ListResponse<Correlation>> {
    await delay();
    return mockList(MOCK_CORRELATIONS);
  },

  async investigations(): Promise<ListResponse<Investigation>> {
    await delay();
    return mockList(MOCK_INVESTIGATIONS);
  },

  async playbooks(): Promise<ListResponse<Playbook>> {
    await delay();
    return mockList(MOCK_PLAYBOOKS);
  },

  async reports(): Promise<ListResponse<Report>> {
    await delay();
    return mockList(MOCK_REPORTS);
  },

  async aiQuery(question: string): Promise<AiChatResponse> {
    await delay();
    // Mock: always return a refusal to avoid fabricating security answers.
    return {
      answer:
        "[Mock] The language model is not connected in this dev environment. " +
        "The question asked was: " + question.slice(0, 200),
      citations: [],
      model_used: null,
      is_partial: true,
    };
  },
};

// Decide at module evaluation time to avoid per-call overhead.
export const USE_MOCK =
  process.env.NEXT_PUBLIC_USE_MOCK !== "false" &&
  process.env.NODE_ENV !== "production";
