import type { Metadata } from 'next';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
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

export default async function AdvisoriesPage() {
  const outcome = mapOutcome(
    await fetchJson<{ templates?: TemplateRow[] }>('/reports/templates'),
    (payload) => payload.templates ?? []
  );
  return (
    <section className="content">
      <h1>Advisories</h1>
      <p className="muted">
        Advisories are produced from the same grounded pipeline as reports. Publication is intentionally gated on an
        approval step, so nothing here is distributed to stakeholders straight from a model.
      </p>
      <ResourceTable
        outcome={outcome}
        columns={columns}
        rowKey={(row) => row.key}
        emptyTitle="No advisory templates"
        emptyDetail="The API responded successfully and no report template is registered."
        caption="Approval, versioning, and distribution history land with the publication workflow."
      />
    </section>
  );
}
