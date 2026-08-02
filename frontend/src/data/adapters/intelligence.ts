import type { DatasetProvenance } from '@/data/catalog';

export interface ProvenancedRecord {
  provenance: DatasetProvenance;
}

export interface VulnerabilityViewModel extends ProvenancedRecord {
  id: string;
  vendor: string | null;
  product: string | null;
  title: string;
  description: string;
  knownExploited: boolean;
  dateAdded: string | null;
  published: string | null;
  lastModified: string | null;
  cvssScore: number | null;
  severity: string | null;
}

export interface ResearchReferenceViewModel extends ProvenancedRecord {
  id: string;
  repository: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
  stars: number;
  classification: 'unverified-research-reference';
}

type KevRecord = { cve_id: string; vendor: string; product: string; vulnerability_name: string; date_added: string; description: string };
type NvdRecord = { cve_id: string; published: string; last_modified: string; description: string; cvss_score: number | null; cvss_severity: string | null };
type ResearchRecord = { repo_name: string; full_name: string; description: string | null; created_at: string; updated_at: string; stars: number };

export function fromKev(record: KevRecord, provenance: DatasetProvenance): VulnerabilityViewModel {
  return { id: record.cve_id, vendor: record.vendor, product: record.product, title: record.vulnerability_name, description: record.description, knownExploited: true, dateAdded: record.date_added, published: null, lastModified: null, cvssScore: null, severity: null, provenance };
}

export function fromNvd(record: NvdRecord, provenance: DatasetProvenance): VulnerabilityViewModel {
  return { id: record.cve_id, vendor: null, product: null, title: record.cve_id, description: record.description, knownExploited: false, dateAdded: null, published: record.published, lastModified: record.last_modified, cvssScore: record.cvss_score, severity: record.cvss_severity, provenance };
}

export function fromResearch(record: ResearchRecord, provenance: DatasetProvenance): ResearchReferenceViewModel {
  return { id: record.full_name, repository: record.full_name, description: record.description, createdAt: record.created_at, updatedAt: record.updated_at, stars: record.stars, classification: 'unverified-research-reference', provenance };
}
