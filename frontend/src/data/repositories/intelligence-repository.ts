import { DATASETS, PINNED_COLLECTION, type DatasetProvenance } from '@/data/catalog';
import {
  fromKev,
  fromNvd,
  fromResearch,
  type ResearchReferenceViewModel,
  type VulnerabilityViewModel,
} from '@/data/adapters/intelligence';
import { cisaKevSnapshot, githubResearchSnapshot, nvdSnapshot } from '@/data/raw/source-snapshot';

export interface DatasetSummary {
  key: string;
  label: string;
  provenance: DatasetProvenance;
  recordCount: number;
}

export interface DataQualityMetric {
  id: string;
  metric: string;
  value: number;
  basis: string;
}

export interface PostureMetric {
  id: string;
  label: string;
  value: string;
  basis: string;
}

function listVulnerabilities(): VulnerabilityViewModel[] {
  return [
    ...cisaKevSnapshot.map((record) => fromKev(record, DATASETS.cisaKev)),
    ...nvdSnapshot.map((record) => fromNvd(record, DATASETS.nvd)),
  ];
}

function listResearchReferences(): ResearchReferenceViewModel[] {
  return githubResearchSnapshot.map((record) => fromResearch(record, DATASETS.githubResearch));
}

function listDatasets(): DatasetSummary[] {
  return [
    { key: 'cisaKev', label: 'CISA Known Exploited Vulnerabilities', provenance: DATASETS.cisaKev, recordCount: cisaKevSnapshot.length },
    { key: 'nvd', label: 'NVD vulnerability records', provenance: DATASETS.nvd, recordCount: nvdSnapshot.length },
    { key: 'githubResearch', label: 'GitHub research references', provenance: DATASETS.githubResearch, recordCount: githubResearchSnapshot.length },
  ];
}

/**
 * Quality counters are derived from the bundled snapshot only. Unknown values are
 * counted as unknown and are never coerced into zero, false, or clean.
 */
function dataQualityMetrics(): DataQualityMetric[] {
  const vulnerabilities = listVulnerabilities();
  const references = listResearchReferences();
  return [
    {
      id: 'records',
      metric: 'Vulnerability records in snapshot',
      value: vulnerabilities.length,
      basis: 'CISA KEV and NVD snapshot files combined.',
    },
    {
      id: 'missing-cvss',
      metric: 'Records with unknown CVSS',
      value: vulnerabilities.filter((record) => record.cvssScore === null).length,
      basis: 'A missing score stays null and is rendered as Unknown, never as 0.0.',
    },
    {
      id: 'missing-severity',
      metric: 'Records with unknown severity label',
      value: vulnerabilities.filter((record) => record.severity === null).length,
      basis: 'Severity is only shown when the source supplied it.',
    },
    {
      id: 'kev-listed',
      metric: 'Records confirmed in the KEV snapshot',
      value: vulnerabilities.filter((record) => record.knownExploited).length,
      basis: 'Confirmed exploitation comes from the KEV file only.',
    },
    {
      id: 'exploitation-unknown',
      metric: 'Records with unknown exploitation status',
      value: vulnerabilities.filter((record) => !record.knownExploited).length,
      basis: 'Absence from KEV means unknown exploitation, not absence of exploitation.',
    },
    {
      id: 'unverified-research',
      metric: 'Unverified research references',
      value: references.length,
      basis: 'Repository references are never treated as confirmed exploit intelligence.',
    },
  ];
}

function postureMetrics(): PostureMetric[] {
  const vulnerabilities = listVulnerabilities();
  const scored = vulnerabilities
    .map((record) => record.cvssScore)
    .filter((score): score is number => score !== null);
  const highestScore = scored.length > 0 ? Math.max(...scored).toFixed(1) : 'Unknown';
  const kevCount = vulnerabilities.filter((record) => record.knownExploited).length;
  return [
    {
      id: 'exploited',
      label: 'Vulnerabilities with confirmed exploitation',
      value: String(kevCount),
      basis: `${DATASETS.cisaKev.sourceFile} at commit ${PINNED_COLLECTION.commit.slice(0, 7)}.`,
    },
    {
      id: 'highest-severity',
      label: 'Highest scored vulnerability in snapshot',
      value: highestScore,
      basis: scored.length > 0 ? `${DATASETS.nvd.sourceFile}, ${scored.length} scored records.` : 'No scored record present in the snapshot.',
    },
    {
      id: 'unscored',
      label: 'Records awaiting enrichment',
      value: String(vulnerabilities.length - scored.length),
      basis: 'Counted as unknown; these are not reported as low risk.',
    },
    {
      id: 'tenant-exposure',
      label: 'Assets affected in this tenant',
      value: 'Unavailable',
      basis: 'Asset correlation requires the tenant-scoped exposure API, which is not connected.',
    },
    {
      id: 'open-cases',
      label: 'Open investigations and cases',
      value: 'Unavailable',
      basis: 'Case state requires the tenant-scoped workflow API, which is not connected.',
    },
  ];
}

/**
 * Temporary local repository. Replace this implementation with the typed API
 * client once the backend intelligence endpoints are available.
 */
export const intelligenceRepository = {
  listVulnerabilities,
  listResearchReferences,
  listDatasets,
  dataQualityMetrics,
  postureMetrics,
};
