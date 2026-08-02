import { DemoDataBanner, EmptyState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

export default function ResearchPage() {
  const references = intelligenceRepository.listResearchReferences();
  return (
    <section className="content">
      <DemoDataBanner label="Bundled historical research references." />
      <h1>Intelligence explorer</h1>
      <p className="muted">
        These records are unverified research references, not confirmed exploit intelligence, and expose no payload or
        execution control.
      </p>
      {references.length === 0 ? (
        <EmptyState
          title="No research references available"
          detail="The bundled snapshot returned no research references for this view."
        />
      ) : (
        references.map((record) => (
          <article className="reference" key={record.id}>
            <strong>{record.repository}</strong>
            <StatusChip label="Unverified" tone="unknown" />
            <p>{record.description}</p>
            <small>
              Source: {record.provenance.sourceFile} · {record.updatedAt}
            </small>
          </article>
        ))
      )}
    </section>
  );
}
