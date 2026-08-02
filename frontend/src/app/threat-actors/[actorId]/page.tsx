import type { Metadata } from 'next';
import { DataTable, type Column } from '@/components/DataTable';
import { DetailShell } from '@/components/DetailShell';
import { FieldTable } from '@/components/FieldTable';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Threat actor' };

type Actor = {
  id: string;
  name?: string | null;
  slug?: string | null;
  description?: string | null;
  victim_count?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
};

type Victim = {
  id: string;
  victim_name?: string | null;
  country?: string | null;
  sector?: string | null;
  discovered_at?: string | null;
  needs_review?: boolean | null;
};

type ActorDetail = {
  actor: Actor;
  recent_victims: Victim[];
  victim_match_basis: string;
};

const victimColumns: Column<Victim>[] = [
  {
    key: 'victim',
    header: 'Victim',
    render: (row) => (
      <>
        <strong>{unknown(row.victim_name)}</strong>
        <br />
        <small>
          {unknown(row.country)} \u00b7 {unknown(row.sector)}
        </small>
      </>
    ),
  },
  { key: 'discovered', header: 'Discovered', render: (row) => <>{unknown(row.discovered_at)}</> },
  {
    key: 'review',
    header: 'Normalisation',
    render: (row) =>
      row.needs_review ? (
        <StatusChip label="Name not normalised" tone="pending" />
      ) : (
        <StatusChip label="Reviewed" tone="neutral" />
      ),
  },
];

export default async function ThreatActorDetailPage({ params }: { params: { actorId: string } }) {
  const outcome = await fetchJson<ActorDetail>(`/actors/${encodeURIComponent(params.actorId)}`);
  const detail = outcome.status === 'ok' ? outcome.data : null;

  return (
    <DetailShell
      backHref="/threat-actors"
      backLabel="Back to threat actors"
      title={detail ? unknown(detail.actor.name) : 'Threat actor'}
      intro="An actor record as ingested, with the leak-site victims that carry its group name."
      outcome={outcome}
    >
      {detail ? (
        <>
          <FieldTable
            caption="Counts describe what the sources observed, not the true scale of the actor's activity."
            fields={[
              { key: 'name', label: 'Name', value: unknown(detail.actor.name) },
              { key: 'slug', label: 'Alias key', value: unknown(detail.actor.slug) },
              {
                key: 'description',
                label: 'Description',
                value: detail.actor.description ?? 'No description supplied by the source.',
              },
              { key: 'victims', label: 'Observed victims', value: detail.actor.victim_count ?? 'Unknown' },
              { key: 'first', label: 'First seen', value: unknown(detail.actor.first_seen) },
              { key: 'last', label: 'Last seen', value: unknown(detail.actor.last_seen) },
            ]}
          />

          <h2>Leak-site victims</h2>
          <p className="muted">{detail.victim_match_basis}</p>
          {detail.recent_victims.length > 0 ? (
            <DataTable
              columns={victimColumns}
              rows={detail.recent_victims}
              rowKey={(row) => row.id}
              caption="A leak-site listing is an attacker claim, not a verified breach."
            />
          ) : (
            <p className="muted">No ingested victim carries this actor&apos;s group name.</p>
          )}
        </>
      ) : null}
    </DetailShell>
  );
}
