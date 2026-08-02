import { DemoDataBanner, FeatureGate } from '@/components/States';

/**
 * The AI analyst surface is read-only. It can never expose an action trigger,
 * and it must present analysis as unverified when no cited evidence exists.
 */
export default function AiAnalystPage() {
  return (
    <section className="content">
      <DemoDataBanner label="AI analysis requires retrieved, cited platform evidence." />
      <h1>AI analyst</h1>
      <FeatureGate
        title="Grounded analysis unavailable"
        detail="No tenant-scoped evidence package is currently available to cite, so no analysis is generated."
      >
        <small>
          Responses must preserve citations, provenance, confidence, and an unverified state when evidence is missing.
          The analyst cannot autonomously execute or dispatch any action.
        </small>
      </FeatureGate>
    </section>
  );
}
