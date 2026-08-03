import { NextRequest, NextResponse } from 'next/server';

const BASE_URL = process.env.API_BASE_URL;
const SERVICE_KEY = process.env.API_SERVICE_KEY;

const ACTIONS: Record<string, { method: 'POST'; path: (id?: string) => string }> = {
  create_case: { method: 'POST', path: () => '/cases' },
  create_investigation: { method: 'POST', path: () => '/investigations' },
  create_alert_rule: { method: 'POST', path: () => '/alert-rules' },
  acknowledge_alert: { method: 'POST', path: (id) => `/alerts/${encodeURIComponent(id ?? '')}/acknowledge` },
  trigger_ingest: { method: 'POST', path: (id) => `/ingest/${encodeURIComponent(id ?? '')}/run` },
  generate_report: { method: 'POST', path: () => '/reports/generate' },
  create_endpoint_intent: { method: 'POST', path: () => '/endpoint-intents' },
  create_api_key: { method: 'POST', path: () => '/api-keys' },
};

export async function POST(request: NextRequest) {
  if (!BASE_URL || !/^https?:\/\//.test(BASE_URL) || !SERVICE_KEY) {
    return NextResponse.json(
      { error: 'Write gateway is unavailable. Configure absolute API_BASE_URL and server-only API_SERVICE_KEY.' },
      { status: 503 },
    );
  }
  let input: { action?: string; id?: string; payload?: unknown };
  try {
    input = await request.json();
  } catch {
    return NextResponse.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const operation = input.action ? ACTIONS[input.action] : undefined;
  if (!operation) return NextResponse.json({ error: 'Action is not allowlisted.' }, { status: 422 });
  if ((input.action === 'acknowledge_alert' || input.action === 'trigger_ingest') && !input.id) {
    return NextResponse.json({ error: 'This action requires a target id.' }, { status: 422 });
  }
  try {
    const upstream = await fetch(`${BASE_URL}${operation.path(input.id)}`, {
      method: operation.method,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-API-Key': SERVICE_KEY },
      body: JSON.stringify(input.payload ?? {}),
      cache: 'no-store',
    });
    const text = await upstream.text();
    let body: unknown = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = { message: 'Upstream returned non-JSON content.' }; }
    return NextResponse.json(body, { status: upstream.status });
  } catch {
    return NextResponse.json({ error: 'The intelligence API could not be reached.' }, { status: 502 });
  }
}
