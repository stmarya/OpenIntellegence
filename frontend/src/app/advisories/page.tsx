import type { Metadata } from 'next';
import Link from 'next/link';
import { DataTable, type Column } from '@/components/DataTable';
import { FeatureGate } from '@/components/States';
import { fetchJson, mapOutcome, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Advisories' };

type TemplateRow = { key: string; title?: string | null; default_period_days?: number | null };

const columns: Column<TemplateRow>[] = [
  {
    key: 'template',
    header: 'Template',
    render: (row) => (
      <>
        <strong>{unknown(row.title)}</strong>
        <br />
        <small>{row.key}</small>
      </>
    ),
  },
  {
    key: 'period',
    header: 'Default period',
    render: (row) => <>{row.default_period_days ? `${row.default_period_days} days` : 'Not defined'}</>,
  },
];

/**
 * Advisories do not exist as records yet.
 *
 * This page previously listed report templates under an advisory heading,
 * which invited readers to believe published advisories existed. The templates
 * are still shown, but as generation inputs, clearly separated from the
 * advisory records that no endpoint yet serves.
 */
export default async function AdvisoriesPage() {
  const outcome = mapOutcome(
    await fetchJson<{ templates?: TemplateRow[] }>('/reports/templates'),
    (payload) => payload.templates ?? []
  );
  const templates = outcome.status === 'ok' ? outcome.data : [];

  return (
    <section className="content">
      <h1>Advisories</h1>
      <FeatureGate
        title="No advisory records are served yet"
        detail="The platform exposes no advisory endpoint. There is no advisory entity, no approval state, and no distribution history to read, so none is displayed."
      >
        <small>
          Nothing on this page is an advisory. Listing report templates as though they were published advisories would
          suggest stakeholders had already been notified about something.
        </small>
      </FeatureGate>

      <h2>Templates an advisory could be generated from</h2>
      <p className="muted">
        These are the generation templates exposed by the reporting service. Generated output is drafted from retrieved
        evidence and stays unpublished until a person approves it. See <Link href="/reports">Reports</Link> for the
        artefacts that have actually been produced.
      </p>
      {templates.length > 0 ? (
        <DataTable
          columns={columns}
          rows={templates}
          rowKey={(row) => row.key}
          caption="Templates describe what could be generated, not what has been issued."
        />
      ) : (
        <p className="muted">No report template is registered, so nothing could be generated even on request.</p>
      )}
    </section>
  );
}
