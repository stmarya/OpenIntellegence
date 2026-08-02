import { DemoDataBanner, FeatureGate } from '@/components/States';

/**
 * Route-level placeholder for capabilities that have no tenant-scoped data yet.
 * It never renders synthetic telemetry, completion results, or delivery state.
 */
export function UnavailableState({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="content">
      <DemoDataBanner label="Tenant-scoped live data is unavailable." />
      <h1>{title}</h1>
      <FeatureGate title="Awaiting API integration" detail={detail}>
        <small>No synthetic tenant telemetry, completion result, or delivery state is shown.</small>
      </FeatureGate>
    </section>
  );
}
