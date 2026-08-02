import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

export default function ResearchPage() {
  return <main className="content"><p className="banner">Bundled historical research references. They are not verified exploit intelligence.</p><h1>Intelligence explorer</h1>{intelligenceRepository.listResearchReferences().map(record => <section className="reference" key={record.id}><strong>{record.repository}</strong><span>Unverified research reference</span><p>{record.description}</p><small>Source: {record.provenance.sourceFile} · {record.updatedAt}</small></section>)}</main>;
}
