import { DATASETS } from '@/data/catalog';

// Curated records retain source values verbatim. Selection and excluded fields are
// documented in SOURCE_MANIFEST.json; no source value is rewritten here.
export const cisaKevSnapshot = [
  {
    cve_id: 'CVE-2025-34291', vendor: 'Langflow', product: 'Langflow',
    vulnerability_name: 'Langflow Origin Validation Error Vulnerability', date_added: '2026-05-21',
    description: 'Langflow contains an origin validation error vulnerability in which an overly permissive CORS configuration combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. This could allow the attacker to execute arbitrary code and achieve full system compromise via obtained tokens that permit access to authenticated endpoints.',
  },
  {
    cve_id: 'CVE-2026-34926', vendor: 'Trend Micro', product: 'Apex One',
    vulnerability_name: 'Trend Micro Apex One (On-Premise) Directory Traversal Vulnerability', date_added: '2026-05-21',
    description: 'Trend Micro Apex One (on-premise) contains a directory traversal vulnerability that could allow a pre-authenticated local attacker to modify a key table on the server to inject malicious code to deploy to agents on affected installations.',
  },
  {
    cve_id: 'CVE-2026-31431', vendor: 'Linux', product: 'Kernel',
    vulnerability_name: 'Linux Kernel Incorrect Resource Transfer Between Spheres Vulnerability', date_added: '2026-05-01',
    description: 'Linux Kernel contains an incorrect resource transfer between spheres vulnerability that could allow for privilege escalation.',
  },
] as const;

export const nvdSnapshot = [
  {
    cve_id: 'CVE-2026-2896', published: '2026-02-22T00:15:59.450', last_modified: '2026-04-29T01:00:01.613',
    description: 'A weakness has been identified in funadmin up to 7.1.0-rc4. This affects the function setConfig of the file app/backend/controller/Ajax.php of the component Configuration Handler. Executing a manipulation can lead to improper authorization. The attack can be executed remotely. The exploit has been m', cvss_score: 7.3, cvss_severity: 'HIGH',
  },
  {
    cve_id: 'CVE-2026-2904', published: '2026-02-22T01:16:00.797', last_modified: '2026-02-24T17:49:09.663',
    description: 'A vulnerability was determined in UTT HiPER 810G 1.7.7-171114. This affects the function strcpy of the file /goform/ConfigExceptAli. Executing a manipulation can lead to buffer overflow. The attack can be launched remotely. The exploit has been publicly disclosed and may be utilized.', cvss_score: 8.8, cvss_severity: 'HIGH',
  },
  {
    cve_id: 'CVE-2026-1369', published: '2026-02-22T06:16:02.537', last_modified: '2026-04-15T00:35:42.020',
    description: 'The Conditional CAPTCHA WordPress plugin through 4.0.0 does not validate a parameter before redirecting the user to its value, leading to an Open Redirect issue', cvss_score: 4.3, cvss_severity: 'MEDIUM',
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
    description: 'Vulnerability advisories automatically enriched (AI-Assisted and VL metadata)',
    created_at: '2026-05-19T06:35:48Z', updated_at: '2026-05-22T12:05:45Z', stars: 2,
  },
  {
    repo_name: 'cve-lite-cli', full_name: 'OWASP/cve-lite-cli',
    description: 'Fast, developer-friendly JS/TS dependency vulnerability scanner with local lockfile scanning, OSV matching, direct vs transitive visibility, --fix, JSON output, and practical remediation guidance.',
    created_at: '2026-03-27T21:27:59Z', updated_at: '2026-05-22T11:56:35Z', stars: 232,
  },
] as const;

export const sourceSnapshotProvenance = {
  cisaKev: DATASETS.cisaKev,
  nvd: DATASETS.nvd,
  githubResearch: DATASETS.githubResearch,
} as const;
