import type { Metadata } from 'next';
import Link from 'next/link';
import { GroundedChat } from '@/components/GroundedChat';

export const metadata: Metadata = { title: 'AI analyst' };

/**
 * Grounded analyst surface.
 *
 * The design decision on record is that this belongs in a side panel available
 * from every surface, so a question can be asked without losing the record in
 * front of you. Until that panel exists, this page carries the same behaviour
 * and says so, rather than presenting a full-page chat as the intended shape.
 */
export default function AiAnalystPage() {
  return (
    <section className="content">
      <h1>AI analyst</h1>
      <p className="muted">
        The analyst answers only from records retrieved out of this workspace. When retrieval returns nothing, the
        response is withheld instead of being filled in from the model&apos;s general knowledge, which would produce
        confident claims about data you never ingested.
      </p>
      <p className="muted">
        Answers carry citations to the records they were drawn from. An answer without a citation is not shown, because
        an unsourced claim in an intelligence platform is indistinguishable from an invented one.
      </p>
      <p className="muted">
        The analyst cannot execute anything. It has no path to dispatch a playbook, deliver a connector action, or send
        a command to an endpoint.
      </p>
      <GroundedChat />
      <p className="muted">
        This is an interim full-page surface. The agreed design places the analyst in a panel reachable from any record,
        so evidence stays on screen while a question is asked. Generated written products remain under{' '}
        <Link href="/reports">reports</Link>, where approval is recorded.
      </p>
    </section>
  );
}
