import { DATASETS } from '@/data/catalog';
import { fromKev, fromNvd, fromResearch, type ResearchReferenceViewModel, type VulnerabilityViewModel } from '@/data/adapters/intelligence';
import { cisaKevSnapshot, githubResearchSnapshot, nvdSnapshot } from '@/data/raw/source-snapshot';

/**
 * Temporary local repository. Replace this implementation with the typed API
 * client once the backend intelligence endpoints are available.
 */
export const intelligenceRepository = {
  listVulnerabilities(): VulnerabilityViewModel[] {
    return [
      ...cisaKevSnapshot.map((record) => fromKev(record, DATASETS.cisaKev)),
      ...nvdSnapshot.map((record) => fromNvd(record, DATASETS.nvd)),
    ];
  },
  listResearchReferences(): ResearchReferenceViewModel[] {
    return githubResearchSnapshot.map((record) => fromResearch(record, DATASETS.githubResearch));
  },
};
