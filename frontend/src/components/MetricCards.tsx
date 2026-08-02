export type Metric = {
  id: string;
  label: string;
  value: number | string | null;
  basis: string;
};

/**
 * Headline counters. A metric with a null value renders as Unavailable and
 * keeps its explanation, so a missing measurement never reads as a measured
 * zero.
 */
export function MetricCards({ metrics }: { metrics: Metric[] }) {
  return (
    <div className="metrics">
      {metrics.map((metric) => (
        <article key={metric.id}>
          <b>{metric.value === null ? 'Unavailable' : metric.value}</b>
          <span>{metric.label}</span>
          <small className="muted">{metric.basis}</small>
        </article>
      ))}
    </div>
  );
}
