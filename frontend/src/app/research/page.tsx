import type { Metadata } from 'next';
import { DemoDataBanner, EmptyState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

export const metadata: Metadata = { title: 'Intelligence explorer' };

export default function ResearchPage() {
  const references = intelligenceRepository.listResearchReferences();
  return (
    <section className="content">
      <DemoDataBanner label="Pinned public research corpus. Not tenant data." />
      <h1>Intelligence explorer</h1>
      <p className="muted">
        These records come from the pinned public research corpus this build was developed against, not from your
        environment. They are unverified research references rather than confirmed exploit intelligence, and they expose
        no payload, delivery, or execution control.
      </p>
      {references.length === 0 ? (
        <EmptyState
          title="No research references available"
          detail="The bundled corpus returned no research references for this view."
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
