/**
 * Unified API facade.
 *
 * Exports a single `api` object. In development (or when NEXT_PUBLIC_USE_MOCK
 * is not explicitly "false") the mock adapter is used.  In production the
 * real HTTP client is used.
 *
 * Page components import from here, never directly from client.ts or mock.ts.
 */

import * as realClient from "./client";
import { mockApi, USE_MOCK } from "./mock";

export const api = USE_MOCK
  ? {
      vulnerabilities: () => mockApi.vulnerabilities(),
      assets: () => mockApi.assets(),
      alerts: () => mockApi.alerts(),
      correlations: () => mockApi.correlations(),
      investigations: () => mockApi.investigations(),
      playbooks: () => mockApi.playbooks(),
      reports: () => mockApi.reports(),
      aiQuery: (question: string) => mockApi.aiQuery(question),
    }
  : {
      vulnerabilities: realClient.vulnerabilitiesApi.list,
      assets: realClient.assetsApi.list,
      alerts: realClient.alertsApi.list,
      correlations: realClient.correlationsApi.list,
      investigations: realClient.investigationsApi.list,
      playbooks: realClient.playbooksApi.list,
      reports: realClient.reportsApi.list,
      aiQuery: (question: string) => realClient.aiApi.query(question),
    };

export type { RemoteState } from "./types";
export { fromListResponse, idle, loading } from "./types";
export { USE_MOCK };
