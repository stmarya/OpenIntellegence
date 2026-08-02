// Shared view model types for OpenIntellegence frontend

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export type StatusType =
  | 'active'
  | 'resolved'
  | 'pending'
  | 'stale'
  | 'open'
  | 'closed'
  | 'in_progress'
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'draft'
  | 'published'
  | 'healthy'
  | 'degraded'
  | 'offline'
  | 'unknown';

export interface Timestamp {
  iso: string;
  display: string;
}

export interface Provenance {
  source: string;
  confidence: number; // 0–100
  last_seen: string;
  tenant_boundary?: string;
  feed?: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  nation_state?: string;
  motivation: string;
  ttps: string[];
}

export interface Indicator {
  id: string;
  type: 'ip' | 'domain' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'url' | 'email' | 'cve';
  value: string;
  risk: RiskLevel;
  status: StatusType;
  tags: string[];
  provenance: Provenance;
  first_seen: string;
  last_seen: string;
  threat_actor?: string;
  campaigns?: string[];
  ttps?: string[];
  description?: string;
}

export interface Asset {
  id: string;
  name: string;
  type: 'workstation' | 'server' | 'network_device' | 'cloud_resource' | 'mobile' | 'iot' | 'unknown';
  os?: string;
  ip?: string;
  owner?: string;
  criticality: RiskLevel;
  status: StatusType;
  last_seen: string;
  vulnerabilities_count: number;
  open_alerts: number;
  tags: string[];
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  severity: RiskLevel;
  cvss_score: number;
  cvss_vector?: string;
  affected_assets: number;
  status: 'open' | 'patched' | 'accepted' | 'in_remediation';
  published: string;
  exploit_available: boolean;
  exploit_in_wild: boolean;
  description: string;
  references: string[];
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: RiskLevel;
  status: StatusType;
  source: string;
  rule_id?: string;
  asset?: string;
  indicator?: string;
  created_at: string;
  updated_at: string;
  assignee?: string;
  tags: string[];
  tactic?: string;
  technique?: string;
}

export interface Correlation {
  id: string;
  name: string;
  description: string;
  alert_count: number;
  severity: RiskLevel;
  status: StatusType;
  first_seen: string;
  last_seen: string;
  threat_actor?: string;
  tactics: string[];
  assets_involved: number;
  confidence: number;
}

export interface Investigation {
  id: string;
  title: string;
  description: string;
  status: 'open' | 'in_progress' | 'resolved' | 'closed';
  priority: RiskLevel;
  assignee?: string;
  created_at: string;
  updated_at: string;
  alert_count: number;
  asset_count: number;
  tags: string[];
}

export type ApprovalState = 'pending' | 'approved' | 'rejected' | 'expired';

export interface ApprovalStep {
  role: string;
  actor?: string;
  state: ApprovalState;
  timestamp?: string;
  comment?: string;
}

export interface Command {
  id: string;
  title: string;
  description: string;
  command: string;
  target_asset: string;
  requester: string;
  requested_at: string;
  status: 'pending_approval' | 'approved' | 'executing' | 'completed' | 'rejected' | 'expired';
  approval_steps: ApprovalStep[];
  executed_at?: string;
  result?: string;
  risk_level: RiskLevel;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: string;
  status: 'active' | 'inactive' | 'draft';
  last_run?: string;
  run_count: number;
  steps: number;
  requires_approval: boolean;
  tags: string[];
}

export interface Report {
  id: string;
  title: string;
  description: string;
  type: 'executive' | 'technical' | 'threat' | 'vulnerability' | 'incident';
  status: 'draft' | 'published' | 'archived';
  created_at: string;
  author: string;
  tags: string[];
  file_size?: string;
}

export interface Connector {
  id: string;
  name: string;
  type: string;
  status: 'healthy' | 'degraded' | 'offline' | 'unknown';
  last_sync?: string;
  events_today?: number;
  error_rate?: number;
  version?: string;
  description: string;
}

export interface AIAnalystMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  grounded: boolean;
  citations?: Citation[];
  confidence?: number;
}

export interface Citation {
  id: string;
  source: string;
  excerpt: string;
  url?: string;
  timestamp?: string;
}

export interface MetricCard {
  label: string;
  value: string | number;
  change?: number;
  trend?: 'up' | 'down' | 'flat';
  description?: string;
  risk?: RiskLevel;
}

export interface TableColumn<T> {
  key: keyof T | string;
  label: string;
  sortable?: boolean;
  width?: string;
  render?: (value: unknown, row: T) => React.ReactNode;
}

export interface PaginationState {
  page: number;
  pageSize: number;
  total: number;
}

export interface SortState {
  key: string;
  direction: 'asc' | 'desc';
}
