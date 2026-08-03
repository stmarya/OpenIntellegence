'use client';

import { FormEvent, useState } from 'react';

type ActionSpec = { key: string; label: string; target?: string; example: object };
const ACTIONS: ActionSpec[] = [
  { key: 'create_case', label: 'Create case', example: { title: 'Investigate affected endpoint', case_type: 'incident', priority: 'high' } },
  { key: 'create_investigation', label: 'Create investigation', example: { title: 'New intelligence hypothesis', hypothesis: 'Describe the hypothesis', priority: 'medium' } },
  { key: 'create_alert_rule', label: 'Create alert rule', example: { name: 'KEV exposure', trigger_type: 'kev_exposure', condition: {}, severity: 'high', cooldown_minutes: 60 } },
  { key: 'acknowledge_alert', label: 'Acknowledge alert', target: 'Alert ID', example: {} },
  { key: 'trigger_ingest', label: 'Trigger ingestion', target: 'Connector name', example: {} },
  { key: 'generate_report', label: 'Generate report', example: { template: 'executive_brief', title: 'Executive intelligence brief' } },
  { key: 'create_endpoint_intent', label: 'Request endpoint action', example: { agent_id: 'agent-uuid', intent_type: 'collect_inventory', expires_at: '2026-08-03T09:00:00Z' } },
  { key: 'create_api_key', label: 'Create API key', example: { name: 'Automation client', scopes: ['read'], rate_limit_per_hour: 1000 } },
];

export function ActionWorkbench() {
  const [selected, setSelected] = useState(ACTIONS[0]);
  const [target, setTarget] = useState('');
  const [payload, setPayload] = useState(JSON.stringify(ACTIONS[0].example, null, 2));
  const [status, setStatus] = useState('Ready. No request has been sent.');
  const [busy, setBusy] = useState(false);

  function choose(key: string) {
    const next = ACTIONS.find((item) => item.key === key) ?? ACTIONS[0];
    setSelected(next); setTarget(''); setPayload(JSON.stringify(next.example, null, 2)); setStatus('Ready. No request has been sent.');
  }

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setStatus('Submitting…');
    let parsed: unknown;
    try { parsed = JSON.parse(payload); } catch { setStatus('Payload is not valid JSON. Nothing was sent.'); setBusy(false); return; }
    try {
      const response = await fetch('/api/actions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: selected.key, id: target || undefined, payload: parsed }) });
      const body = await response.json();
      setStatus(response.ok ? `Accepted (HTTP ${response.status}).\n${JSON.stringify(body, null, 2)}` : `Rejected (HTTP ${response.status}).\n${JSON.stringify(body, null, 2)}`);
    } catch { setStatus('Write gateway could not be reached. The action outcome is unknown; check the audit log before retrying.'); }
    finally { setBusy(false); }
  }

  return <form className="reference" onSubmit={submit}>
    <label>Action<br /><select value={selected.key} onChange={(e) => choose(e.target.value)}>{ACTIONS.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}</select></label>
    {selected.target ? <label>{selected.target}<br /><input required value={target} onChange={(e) => setTarget(e.target.value)} /></label> : null}
    <label>Request payload<br /><textarea rows={12} value={payload} onChange={(e) => setPayload(e.target.value)} spellCheck={false} /></label>
    <p><button type="submit" disabled={busy}>{busy ? 'Submitting…' : selected.label}</button></p>
    <pre aria-live="polite">{status}</pre>
  </form>;
}
