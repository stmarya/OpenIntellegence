import type { Metadata } from 'next';
import { MetricCards, type Metric } from '@/components/MetricCards';
import { FeatureGate } from '@/components/States';
import { fetchList } from '@/lib/server-fetch';
import { reasonOf, totalOf } from '@/lib/totals';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Executive intelligence' };

type Row = { id: string };

export default async function ExecutiveIntelligencePage() {
  const [vulnerabilities, alerts, correlations, cases, investigations, assets, agents, reports] = await Promise.all([
    fetchList<Row>('/vulnerabilities?limit=1'),
    fetchList<Row>('/alerts?limit=1'),
    fetchList<Row>('/correlations?limit=1'),
    fetchList<Row>('/cases?limit=1'),
    fetchList<Row>('/investigations?limit=1'),
    fetchList<Row>('/assets?limit=1'),
    fetchList<Row>('/agents?limit=1'),
    fetchList<Row>('/reports?limit=1'),
  ]);

  const metrics: Metric[] = [
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities tracked',
      value: totalOf(vulnerabilities),
      basis: 'Total reported by the vulnerabilities endpoint.',
    },
    { id: 'alerts', label: 'Alerts raised', value: totalOf(alerts), basis: 'Total reported by the alerts endpoint.' },
    {
      id: 'correlations',
      label: 'Correlations produced',
      value: totalOf(correlations),
      basis: 'Total reported by the correlation engine.',
    },
    { id: 'cases', label: 'Cases on record', value: totalOf(cases), basis: 'Total reported by case management.' },
    {
      id: 'investigations',
      label: 'Investigations opened',
      value: totalOf(investigations),
      basis: 'Total reported by the investigations endpoint.',
    },
    { id: 'assets', label: 'Assets in inventory', value: totalOf(assets), basis: 'Total reported by asset inventory.' },
    {
      id: 'agents',
      label: 'Agents enrolled',
      value: totalOf(agents),
      basis: 'Enrollment count only. It does not imply the agents are currently reporting.',
    },
    {
      id: 'reports',
      label: 'Reports produced',
      value: totalOf(reports),
      basis: 'Total reported by the reporting endpoint.',
    },
  ];

  const failures = [vulnerabilities, alerts, correlations, cases, investigations, assets, agents, reports]
    .map(reasonOf)
    .filter((reason): reason is string => reason !== null);
  const uniqueFailures = Array.from(new Set(failures));

  return (
    <section className="content">
      <h1>Executive intelligence</h1>
      <p className="muted">
        Every figure here is a count the platform can actually substantiate. Measures that could not be read are marked
        Unavailable rather than estimated, extrapolated, or defaulted to zero, so this page can be used to make a
        decision without first checking whether it is telling the truth.
      </p>
      <MetricCards metrics={metrics} />

      {uniqueFailures.length > 0 ? (
        <>
          <h2>Why some measures are missing</h2>
          <FeatureGate
            title={`${uniqueFailures.length} measurement source could not be read`}
            detail="The counters above marked Unavailable correspond to these failures. Treat the affected areas as unobserved, not as clear."
          >
            <ul>
              {uniqueFailures.map((reason) => (
                <li key={reason}>
                  <small>{reason}</small>
                </li>
              ))}
            </ul>
          </FeatureGate>
        </>
      ) : null}

      <h2>What this page deliberately does not do</h2>
      <p className="muted">
        No trend line, risk score, or posture grade is shown. The platform does not yet retain the historical series
        those figures would require, and a fabricated trend is more damaging at board level than an absent one.
      </p>
    </section>
  );
}
