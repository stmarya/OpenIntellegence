// API type definitions for OpenIntellegence frontend

import type {
  Indicator,
  Asset,
  Vulnerability,
  Alert,
  Correlation,
  Investigation,
  Command,
  Playbook,
  Report,
  Connector,
  MetricCard,
} from '@/types';

export interface ApiResponse<T> {
  data: T;
  meta?: {
    total: number;
    page: number;
    page_size: number;
  };
  error?: string;
}

export interface ListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
  search?: string;
  filters?: Record<string, string | string[]>;
}

export interface OverviewMetrics {
  cards: MetricCard[];
  active_alerts: number;
  open_investigations: number;
  critical_vulnerabilities: number;
  indicators_today: number;
  connectors_healthy: number;
  connectors_total: number;
}

export type { Indicator, Asset, Vulnerability, Alert, Correlation, Investigation, Command, Playbook, Report, Connector };
