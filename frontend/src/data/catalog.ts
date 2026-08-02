export type DatasetKind = 'source_snapshot' | 'synthetic_fixture';

export interface DatasetProvenance {
  kind: DatasetKind;
  repository: string;
  commit: string;
  directory: string;
  sourceFile: string;
  sourceSha: string;
  snapshotLabel: string;
}

export const PINNED_COLLECTION = {
  repository: 'stmarya/NogoSecV3.1.1',
  commit: 'c058fa31db917305a42e2205b80d3c21ff4970ed',
  directory: 'API_Testing/OTX/collected_data',
  label: 'Bundled sample-data snapshot',
} as const;

export const DATASETS = {
  cisaKev: {
    ...PINNED_COLLECTION,
    kind: 'source_snapshot',
    sourceFile: 'cisa_kev_3months.json',
    sourceSha: 'a74ca7a4371e570d2799bf6cccfa400cffd812cb',
    snapshotLabel: 'Bundled sample-data snapshot — CISA KEV',
  },
  nvd: {
    ...PINNED_COLLECTION,
    kind: 'source_snapshot',
    sourceFile: 'nvd_api_3months.json',
    sourceSha: '2e48e487f8a29fb94d322671f7e29e105df471af',
    snapshotLabel: 'Bundled sample-data snapshot — NVD',
  },
  githubResearch: {
    ...PINNED_COLLECTION,
    kind: 'source_snapshot',
    sourceFile: 'github_poc_3months.json',
    sourceSha: '11ab03493b87ad1d70bff553239ce7d0bbd53336',
    snapshotLabel: 'Bundled sample-data snapshot — GitHub research references',
  },
} as const satisfies Record<string, DatasetProvenance>;
