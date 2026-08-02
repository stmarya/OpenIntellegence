import type { DatasetProvenance } from '@/data/catalog';

export function ProvenancePanel({ provenance }: { provenance: DatasetProvenance }) {
  return <aside className="reference"><strong>Provenance</strong><p>{provenance.snapshotLabel}</p><small>{provenance.repository}@{provenance.commit.slice(0, 12)} · {provenance.directory}/{provenance.sourceFile}</small></aside>;
}
