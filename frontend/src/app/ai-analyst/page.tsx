import type { Metadata } from 'next';
import { GroundedChat } from '@/components/GroundedChat';

export const metadata: Metadata = { title: 'AI analyst' };

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
        The analyst cannot execute anything. It has no path to dispatch a playbook, deliver a connector action, or send
        a command to an endpoint.
      </p>
      <GroundedChat />
    </section>
  );
}
