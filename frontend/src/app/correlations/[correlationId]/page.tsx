import type { Metadata } from 'next';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable, type Field } from '@/components/FieldTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';

type FactorEntry = { factor?: string | null; contribution?: number | null; basis?: string | null };
type AiBrief = { id: string; status?: string | null; content?: string | null; citations?: unknown[]; generated_at?: string | null };
type CorrelationDetail = {
  id?: string;
  title?: string | null;
  primary_entity_type?: string | null;
  primary_entity_id?: string | null;
  risk_score?: number | null;
  risk_tier?: string | null;
  factor_breakdown?: FactorEntry[];
  automation_candidates?: string[];
  evaluated_at?: string | null;
  evidence?: { resolution_status?: string | null } | null;
  ai_briefs?: AiBrief[];
};

export function generateMetadata({ params }: { params: { correlationId: string } }): Metadata {
  return { title: `Correlation ${params.correlationId}` };
}

export default async function CorrelationDetailPage({ params }: { params: { correlationId: string } }) {
  const outcome = await fetchJson<CorrelationDetail>(`/correlations/${encodeURIComponent(params.correlationId)}`);
  const record = outcome.status === 'ok' ? outcome.data : null;
  const briefs = record?.ai_briefs ?? [];

  const fields: Field[] = record
    ? [
        {
          key: 'entity',
          label: 'Primary entity',
          value: `${unknown(record.primary_entity_type)} · ${unknown(record.primary_entity_id)}`,
        },
        {
          key: 'risk',
          label: 'Risk',
          value: <RiskBadge score={record.risk_score ?? null} knownExploited={record.risk_tier === 'critical'} />,
        },
        { key: 'score', label: 'Deterministic score', value: record.risk_score ?? 'Unknown' },
        {
          key: 'resolution',
          label: 'Evidence resolution',
          value:
            record.evidence?.resolution_status === 'unavailable' ? (
              <StatusChip label="No persisted evidence resolved" tone="unknown" />
            ) : (
              <StatusChip label={unknown(record.evidence?.resolution_status)} tone="neutral" />
            ),
        },
        {
          key: 'automation',
          label: 'Automation candidates',
          value: record.automation_candidates?.length
            ? record.automation_candidates.join(', ')
            : 'None proposed',
        },
        { key: 'evaluated', label: 'Evaluated at', value: unknown(record.evaluated_at) },
      ]
    : [];

  const factors: Field[] = (record?.factor_breakdown ?? []).map((entry, index) => ({
    key: `factor-${index}`,
    label: entry.factor ?? `Factor ${index + 1}`,
    value: `${entry.contribution ?? 'Unknown'} — ${entry.basis ?? 'Basis not recorded'}`,
  }));

  return (
    <DetailShell
      backHref="/correlations"
      backLabel="All correlations"
      title={record?.title ?? `Correlation ${params.correlationId}`}
      intro="The score comes from a deterministic factor breakdown, so an analyst can reproduce it by hand. Automation candidates are proposals awaiting human approval; nothing here dispatches an action."
      outcome={outcome}
    >
      <FieldTable fields={fields} />
      <h2>Factor breakdown</h2>
      {factors.length > 0 ? (
        <FieldTable fields={factors} caption="Each contribution states the evidence it was derived from." />
      ) : (
        <p className="muted">No factor contributed to this score.</p>
      )}
      <h2>AI briefs</h2>
      {briefs.length === 0 ? (
        <p className="muted">No AI brief has been generated for this correlation.</p>
      ) : (
        <ul className="timeline">
          {briefs.map((brief) => (
            <li key={brief.id}>
              <strong>
                {brief.status === 'grounded' ? 'Grounded brief' : 'Withheld brief'} · {unknown(brief.generated_at)}
              </strong>
              <span>{brief.content ?? 'No content recorded.'}</span>
              <span>
                <small>
                  {brief.citations?.length
                    ? `${brief.citations.length} cited record(s)`
                    : 'No citation, so this text is not presented as established fact.'}
                </small>
              </span>
            </li>
          ))}
        </ul>
      )}
    </DetailShell>
  );
}
