import { DATASETS } from '@/data/catalog';

export const cisaKevSnapshot = [
  {
    cve_id: 'CVE-2025-34291', vendor: 'Langflow', product: 'Langflow',
    vulnerability_name: 'Langflow Origin Validation Error Vulnerability', date_added: '2026-05-21',
    description: 'Langflow contains an origin validation error vulnerability involving an overly permissive CORS configuration and refresh-token handling.',
  },
  {
    cve_id: 'CVE-2026-34926', vendor: 'Trend Micro', product: 'Apex One',
    vulnerability_name: 'Trend Micro Apex One (On-Premise) Directory Traversal Vulnerability', date_added: '2026-05-21',
    description: 'Trend Micro Apex One (on-premise) contains a directory traversal vulnerability that could allow modification of a key table on the server.',
  },
  {
    cve_id: 'CVE-2026-31431', vendor: 'Linux', product: 'Kernel',
    vulnerability_name: 'Linux Kernel Incorrect Resource Transfer Between Spheres Vulnerability', date_added: '2026-05-01',
    description: 'Linux Kernel contains an incorrect resource transfer between spheres vulnerability that could allow privilege escalation.',
  },
] as const;

export const nvdSnapshot = [
  {
    cve_id: 'CVE-2026-2896', published: '2026-02-22T00:15:59.450', last_modified: '2026-04-29T01:00:01.613',
    description: 'A weakness has been identified in funadmin up to 7.1.0-rc4 affecting the Configuration Handler.', cvss_score: 7.3, cvss_severity: 'HIGH',
  },
  {
    cve_id: 'CVE-2026-2904', published: '2026-02-22T01:16:00.797', last_modified: '2026-02-24T17:49:09.663',
    description: 'A vulnerability was determined in UTT HiPER 810G 1.7.7-171114 affecting a configuration handler.', cvss_score: 8.8, cvss_severity: 'HIGH',
  },
  {
    cve_id: 'CVE-2026-1369', published: '2026-02-22T06:16:02.537', last_modified: '2026-04-15T00:35:42.020',
    description: 'The Conditional CAPTCHA WordPress plugin through 4.0.0 has an open redirect issue.', cvss_score: 4.3, cvss_severity: 'MEDIUM',
  },
] as const;

export const githubResearchSnapshot = [
  {
    repo_name: 'cve-intelligence-automation', full_name: 'kasireddy-sec/cve-intelligence-automation',
    description: 'Automated CVE intelligence aggregation pipeline using security advisories, RSS feeds, and vulnerability research sources.',
    created_at: '2026-05-21T09:16:28Z', updated_at: '2026-05-22T12:09:06Z', stars: 0,
  },
  {
    repo_name: 'gcve-enriched-dumps', full_name: 'gcve-eu/gcve-enriched-dumps',
    description: 'Vulnerability advisories automatically enriched with AI-assisted and metadata fields.',
    created_at: '2026-05-19T06:35:48Z', updated_at: '2026-05-22T12:05:45Z', stars: 2,
  },
  {
    repo_name: 'cve-lite-cli', full_name: 'OWASP/cve-lite-cli',
    description: 'Developer-focused dependency vulnerability scanner with local lockfile scanning and OSV matching.',
    created_at: '2026-03-27T21:27:59Z', updated_at: '2026-05-22T11:56:35Z', stars: 232,
  },
] as const;

export const sourceSnapshotProvenance = {
  cisaKev: DATASETS.cisaKev,
  nvd: DATASETS.nvd,
  githubResearch: DATASETS.githubResearch,
} as const;
