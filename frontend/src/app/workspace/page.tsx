import type { Metadata } from 'next';
import Link from 'next/link';
import { FieldTable, type Field } from '@/components/FieldTable';
import { ErrorState } from '@/components/States';
import { StatusChip } from '@/components/StatusChip';
import { fetchJson, unknown } from '@/lib/server-fetch';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'My workspace' };

type Session = {
  api_key_id?: string | null;
  key_name?: string | null;
  tenant_id?: string | null;
  tenant_name?: string | null;
  tenant_slug?: string | null;
  scopes?: string[];
  rate_limit_per_hour?: number | null;
  subject_kind?: string | null;
  note?: string | null;
};

export default async function WorkspacePage() {
  const outcome = await fetchJson<Session>('/me');

  if (outcome.status !== 'ok') {
    return (
      <section className="content">
        <h1>My workspace</h1>
        <ErrorState
          title="Session could not be read"
          detail={outcome.reason}
        />
      </section>
    );
  }

  const session = outcome.data;
  const scopes = session.scopes ?? [];

  const fields: Field[] = [
    { key: 'key_name', label: 'Credential label', value: unknown(session.key_name) },
    {
      key: 'subject',
      label: 'Authenticated as',
      value: <StatusChip label={session.subject_kind === 'api_key' ? 'API key' : unknown(session.subject_kind)} tone="neutral" />,
    },
    { key: 'api_key_id', label: 'Key identifier', value: <code>{unknown(session.api_key_id)}</code> },
    {
      key: 'tenant',
      label: 'Tenant',
      value: session.tenant_name ? `${session.tenant_name} (${unknown(session.tenant_slug)})` : unknown(session.tenant_id),
    },
    {
      key: 'rate_limit',
      label: 'Rate limit',
      value:
        typeof session.rate_limit_per_hour === 'number'
          ? `${session.rate_limit_per_hour} requests per hour`
          : <StatusChip label="Not reported" tone="unknown" />,
    },
  ];

  return (
    <section className="content">
      <h1>My workspace</h1>
      <p className="muted">
        This page describes the credential you are currently authenticated with. It is not a personal profile, and
        the distinction is not cosmetic: the platform stores no user accounts, so it cannot tell you who is holding
        this key or attribute any action to a named person.
      </p>

      <h2>Session</h2>
      <FieldTable fields={fields} caption="Attributes of the credential authenticating this request" />

      <h2>Authority held</h2>
      {scopes.length === 0 ? (
        <p className="muted">
          This credential carries no scopes. Every scoped surface in the console will refuse it.
        </p>
      ) : (
        <ul>
          {scopes.map((scope) => (
            <li key={scope}>
              <code>{scope}</code>
            </li>
          ))}
        </ul>
      )}
      <p className="muted">
        Authority is carried on the key itself, not on a role that can be edited later. Changing what this session
        may do means issuing a different key. The full catalogue and what each scope permits is on the{' '}
        <Link href="/access">access surface</Link>.
      </p>

      <h2>What this workspace cannot show you</h2>
      <p className="muted">
        A workspace page normally answers &quot;what is assigned to me&quot;. That question has no answer here. Cases,
        investigations, and reports record a tenant and sometimes a free-text owner string, but nothing links them to
        the credential you are using. Listing recent tenant activity under a heading like &quot;my work&quot; would
        present shared records as personal ones, so this page does not do it. Open{' '}
        <Link href="/cases">cases</Link>, <Link href="/investigations">investigations</Link>, and{' '}
        <Link href="/reports">reports</Link> directly; each is scoped to the tenant, not to you.
      </p>
      {session.note ? <p className="muted">{session.note}</p> : null}
    </section>
  );
}
