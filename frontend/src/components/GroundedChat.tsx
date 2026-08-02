'use client';

import { useState } from 'react';

type Citation = { title?: string | null; source?: string | null; reference?: string | null; url?: string | null };
type ChatResponse = { answer?: string; citations?: Citation[]; provenance?: { note?: string | null } | null };

type ChatState =
  | { phase: 'idle' }
  | { phase: 'loading' }
  | { phase: 'grounded'; answer: string; citations: Citation[] }
  | { phase: 'withheld'; reason: string }
  | { phase: 'error'; reason: string };

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? '/api/v1';

export function GroundedChat() {
  const [question, setQuestion] = useState('');
  const [state, setState] = useState<ChatState>({ phase: 'idle' });

  async function ask(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (question.trim().length === 0) return;
    setState({ phase: 'loading' });
    try {
      const response = await fetch(`${BASE_URL}/chat/query`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ question, top_k: 8 }),
      });
      if (!response.ok) {
        setState({ phase: 'error', reason: `The AI endpoint answered HTTP ${response.status}.` });
        return;
      }
      const payload = (await response.json()) as ChatResponse;
      const citations = payload.citations ?? [];
      if (citations.length === 0) {
        setState({
          phase: 'withheld',
          reason:
            payload.provenance?.note ??
            'No supporting workspace records were retrieved, so the answer is withheld rather than presented as fact.',
        });
        return;
      }
      setState({ phase: 'grounded', answer: payload.answer ?? '', citations });
    } catch {
      setState({ phase: 'error', reason: 'The AI endpoint could not be reached from this browser session.' });
    }
  }

  return (
    <>
      <form onSubmit={ask}>
        <label htmlFor="analyst-question">Ask about records this workspace has actually ingested</label>
        <br />
        <input
          id="analyst-question"
          name="question"
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Which KEV-listed CVEs affect internet-exposed assets?"
          style={{ width: '70%', padding: '8px', marginTop: '8px' }}
        />{' '}
        <button type="submit" disabled={state.phase === 'loading'}>
          {state.phase === 'loading' ? 'Retrieving' : 'Ask'}
        </button>
      </form>

      {state.phase === 'loading' ? (
        <p className="state state-loading" role="status" aria-live="polite">
          Retrieving supporting records…
        </p>
      ) : null}

      {state.phase === 'withheld' ? (
        <section className="state state-gated">
          <h2>Answer withheld</h2>
          <p className="muted">{state.reason}</p>
        </section>
      ) : null}

      {state.phase === 'error' ? (
        <section className="state state-error" role="alert">
          <h2>Request failed</h2>
          <p className="muted">{state.reason}</p>
        </section>
      ) : null}

      {state.phase === 'grounded' ? (
        <section className="state">
          <h2>Grounded answer</h2>
          <p>{state.answer}</p>
          <ul className="timeline">
            {state.citations.map((citation, index) => (
              <li key={`${citation.reference ?? citation.title ?? 'citation'}-${index}`}>
                <strong>{citation.title ?? citation.reference ?? 'Cited record'}</strong>
                <span>{citation.source ?? 'Source not stated'}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </>
  );
}
